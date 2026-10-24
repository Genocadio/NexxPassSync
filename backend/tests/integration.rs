#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use nexxpass_sync_server::{config::Config, http, state::AppState, sync::BatchResponse};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

fn make_signing_key(seed_byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed_byte; 32])
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn sign_request(
    method: &str,
    path: &str,
    body_bytes: &[u8],
    signing_key: &SigningKey,
    account_id: &[u8],
    device_id: Option<Uuid>,
    is_identity: bool,
) -> Request<Body> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce: [u8; 16] = Uuid::new_v4().as_bytes().to_owned();
    let nonce_b64u = URL_SAFE_NO_PAD.encode(nonce);

    let mut body_hasher = Sha256::new();
    body_hasher.update(body_bytes);
    let body_digest_hex = hex_lower(&body_hasher.finalize());

    let canonical = format!(
        "NPSSv1\n{}\n{}\n\n{}\n{}\n{}",
        method, path, now, nonce_b64u, body_digest_hex
    );

    let signature = signing_key.sign(canonical.as_bytes());
    let sig_b64u = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("x-nexxpass-protocol", "1")
        .header("x-nexxpass-timestamp", now.to_string())
        .header("x-nexxpass-nonce", nonce_b64u)
        .header("x-nexxpass-signature", sig_b64u);

    if is_identity {
        // Registration endpoint has no x-nexxpass-key header.
    } else {
        builder = builder
            .header("x-nexxpass-account", URL_SAFE_NO_PAD.encode(account_id))
            .header("x-nexxpass-key", "device");
        if let Some(dev_id) = device_id {
            builder = builder.header("x-nexxpass-device", dev_id.to_string());
        }
    }

    if !body_bytes.is_empty() {
        builder = builder.header("content-type", "application/json");
    }

    builder.body(Body::from(body_bytes.to_vec())).unwrap()
}

#[tokio::test]
async fn test_full_batch_sync_lifecycle() {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://nexxpass:change-me@localhost:5432/nexxpass_sync".to_string()
    });

    let config = Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        database_url,
        database_max_connections: 5,
    };

    let state = match AppState::connect(&config).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping postgres integration test: {e}");
            return;
        }
    };

    state
        .migrate()
        .await
        .expect("migrations should apply cleanly");

    let router = http::router(state.clone());

    // Generate test keys
    let identity_key = make_signing_key(0x10);
    let device_key = make_signing_key(0x20);

    let account_id: [u8; 32] = Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(Uuid::new_v4().as_bytes())
        .copied()
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let device_id = Uuid::new_v4();

    let recovery_wrap = URL_SAFE_NO_PAD.encode([0x33; 105]);
    let device_wrap = URL_SAFE_NO_PAD.encode([0x44; 105]);

    // Register account
    let reg_body = serde_json::json!({
        "account_id": URL_SAFE_NO_PAD.encode(account_id),
        "identity_ed25519_pub": URL_SAFE_NO_PAD.encode(identity_key.verifying_key().to_bytes()),
        "identity_x25519_pub": URL_SAFE_NO_PAD.encode([0x55; 32]),
        "derivation_version": 1,
        "device": {
            "device_id": device_id.to_string(),
            "device_ed25519_pub": URL_SAFE_NO_PAD.encode(device_key.verifying_key().to_bytes()),
            "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x66; 32]),
            "device_label": "Test Primary Device",
            "wrap": device_wrap,
        },
        "recovery_wrap": recovery_wrap,
    });

    let reg_body_bytes = serde_json::to_vec(&reg_body).unwrap();
    let reg_req = sign_request(
        "POST",
        "/v1/accounts",
        &reg_body_bytes,
        &identity_key,
        &account_id,
        None,
        true,
    );

    let reg_res = router.clone().oneshot(reg_req).await.unwrap();
    assert_eq!(reg_res.status(), StatusCode::CREATED);

    // Verify GET /v1/accounts/me
    let me_req = sign_request(
        "GET",
        "/v1/accounts/me",
        b"",
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let me_res = router.clone().oneshot(me_req).await.unwrap();
    assert_eq!(me_res.status(), StatusCode::OK);

    // Test POST /v1/sync/batch with put operation
    let item_id_1 = Uuid::new_v4();
    let op_id_1 = Uuid::new_v4();
    let dummy_blob = URL_SAFE_NO_PAD.encode(vec![0x77; 600]); // 600 bytes ciphertext

    let batch_req_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": op_id_1.to_string(),
                "item_id": item_id_1.to_string(),
                "base_version": 0,
                "key_version": 1,
                "blob": dummy_blob,
            }
        ]
    });
    let batch_bytes = serde_json::to_vec(&batch_req_body).unwrap();
    let batch_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &batch_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );

    let batch_res = router.clone().oneshot(batch_req).await.unwrap();
    assert_eq!(batch_res.status(), StatusCode::OK);

    let body_bytes = to_bytes(batch_res.into_body(), 1024 * 1024).await.unwrap();
    let batch_response: BatchResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(batch_response.results.len(), 1);
    assert_eq!(batch_response.results[0].status, "applied");
    assert_eq!(batch_response.results[0].version, Some(1));
    assert_eq!(batch_response.results[0].seq, Some(1));

    // Test Idempotency Retry: repeat the exact same operation with fresh signature/nonce
    let retry_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &batch_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let retry_res = router.clone().oneshot(retry_req).await.unwrap();
    assert_eq!(retry_res.status(), StatusCode::OK);
    let retry_body = to_bytes(retry_res.into_body(), 1024 * 1024).await.unwrap();
    let retry_response: BatchResponse = serde_json::from_slice(&retry_body).unwrap();
    assert_eq!(retry_response.results[0].status, "duplicate");
    assert_eq!(retry_response.results[0].version, Some(1));
    assert_eq!(retry_response.results[0].seq, Some(1));

    // Test Operation ID Reuse with different payload -> must fail with 422 operation_id_reused
    let conflicting_req_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": op_id_1.to_string(),
                "item_id": item_id_1.to_string(),
                "base_version": 1, // Changed base_version!
                "key_version": 1,
                "blob": dummy_blob,
            }
        ]
    });
    let conf_bytes = serde_json::to_vec(&conflicting_req_body).unwrap();
    let conf_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &conf_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let conf_res = router.clone().oneshot(conf_req).await.unwrap();
    assert_eq!(conf_res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Test Delete operation on item_1
    let op_id_2 = Uuid::new_v4();
    let delete_req_body = serde_json::json!({
        "operations": [
            {
                "op": "delete",
                "operation_id": op_id_2.to_string(),
                "item_id": item_id_1.to_string(),
                "base_version": 1,
            }
        ]
    });
    let del_bytes = serde_json::to_vec(&delete_req_body).unwrap();
    let del_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &del_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let del_res = router.clone().oneshot(del_req).await.unwrap();
    assert_eq!(del_res.status(), StatusCode::OK);
    let del_body = to_bytes(del_res.into_body(), 1024 * 1024).await.unwrap();
    let del_response: BatchResponse = serde_json::from_slice(&del_body).unwrap();
    assert_eq!(del_response.results[0].status, "applied");
    assert_eq!(del_response.results[0].version, Some(2));
    assert_eq!(del_response.results[0].seq, Some(2));

    // Test permanent ID retirement: attempt to re-create item_id_1 with base_version 0
    let op_id_3 = Uuid::new_v4();
    let revive_req_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": op_id_3.to_string(),
                "item_id": item_id_1.to_string(),
                "base_version": 0,
                "key_version": 1,
                "blob": dummy_blob,
            }
        ]
    });
    let rev_bytes = serde_json::to_vec(&revive_req_body).unwrap();
    let rev_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &rev_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let rev_res = router.clone().oneshot(rev_req).await.unwrap();
    assert_eq!(rev_res.status(), StatusCode::OK);
    let rev_body = to_bytes(rev_res.into_body(), 1024 * 1024).await.unwrap();
    let rev_response: BatchResponse = serde_json::from_slice(&rev_body).unwrap();
    // Re-creating a retired item ID must be rejected as item_deleted!
    assert_eq!(rev_response.results[0].status, "item_deleted");
}
