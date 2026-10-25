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
        token_hmac_key: [0x55; 32],
        deployment_epoch: 1,
        maintenance_interval_seconds: 3600,
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

    // --- MILESTONE 2: SNAPSHOT AND INCREMENTAL PULL WITH ACKS ---

    // 1. Create a second live item so the snapshot has live content
    let item_id_2 = Uuid::new_v4();
    let op_id_4 = Uuid::new_v4();
    let batch_2_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": op_id_4.to_string(),
                "item_id": item_id_2.to_string(),
                "base_version": 0,
                "key_version": 1,
                "blob": dummy_blob,
            }
        ]
    });
    let b2_bytes = serde_json::to_vec(&batch_2_body).unwrap();
    let b2_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &b2_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let b2_res = router.clone().oneshot(b2_req).await.unwrap();
    assert_eq!(b2_res.status(), StatusCode::OK);

    // 2. Register Device 2 via pairing flow
    let device_key_2 = make_signing_key(0x21);
    let device_id_2 = Uuid::new_v4();
    let pairing_req_body = serde_json::json!({
        "target_account_id": URL_SAFE_NO_PAD.encode(account_id),
        "device_id": device_id_2.to_string(),
        "device_ed25519_pub": URL_SAFE_NO_PAD.encode(device_key_2.verifying_key().to_bytes()),
        "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x88; 32]),
        "device_label": "Test Secondary Device",
    });
    let p_bytes = serde_json::to_vec(&pairing_req_body).unwrap();
    let p_req = Request::builder()
        .method("POST")
        .uri("/v1/pairings")
        .header("x-nexxpass-protocol", "1")
        .header("content-type", "application/json")
        .body(Body::from(p_bytes))
        .unwrap();
    let p_res = router.clone().oneshot(p_req).await.unwrap();
    assert_eq!(p_res.status(), StatusCode::ACCEPTED);
    let p_body = to_bytes(p_res.into_body(), 1024 * 1024).await.unwrap();
    let challenge: serde_json::Value = serde_json::from_slice(&p_body).unwrap();
    let pairing_id_str = challenge["pairing_id"].as_str().unwrap();

    // Primary device approves pairing
    let approval_body = serde_json::json!({
        "pairing_id": pairing_id_str,
        "account_id": URL_SAFE_NO_PAD.encode(account_id),
        "device_id": device_id_2.to_string(),
        "device_ed25519_pub": URL_SAFE_NO_PAD.encode(device_key_2.verifying_key().to_bytes()),
        "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x88; 32]),
        "expiry": challenge["expires_at"].as_str().unwrap(),
        "active_key_version": 1,
        "wrap": URL_SAFE_NO_PAD.encode([0x99; 105]),
    });
    let app_bytes = serde_json::to_vec(&approval_body).unwrap();
    let app_req = sign_request(
        "POST",
        &format!("/v1/pairings/{pairing_id_str}/approve"),
        &app_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let app_res = router.clone().oneshot(app_req).await.unwrap();
    assert_eq!(app_res.status(), StatusCode::OK);

    // 3. Device 2 performs Full Snapshot Pull (`checkpoint = 0`)
    let pull_req_body = serde_json::json!({
        "checkpoint": 0,
        "page_size": 50,
    });
    let pull_bytes = serde_json::to_vec(&pull_req_body).unwrap();
    let pull_req = sign_request(
        "POST",
        "/v1/sync/pull",
        &pull_bytes,
        &device_key_2,
        &account_id,
        Some(device_id_2),
        false,
    );
    let pull_res = router.clone().oneshot(pull_req).await.unwrap();
    assert_eq!(pull_res.status(), StatusCode::OK);
    let pull_body = to_bytes(pull_res.into_body(), 1024 * 1024).await.unwrap();
    let page: serde_json::Value = serde_json::from_slice(&pull_body).unwrap();

    assert!(page["done"].as_bool().unwrap());
    let items_array = page["items"].as_array().unwrap();
    // Full snapshot must omit tombstones! So item_id_1 (deleted) must be absent, and item_id_2 present.
    assert_eq!(items_array.len(), 1);
    assert_eq!(
        items_array[0]["item_id"].as_str().unwrap(),
        item_id_2.to_string()
    );
    assert!(!items_array[0]["deleted"].as_bool().unwrap());

    let session_id = page["sync_session_id"].as_str().unwrap();
    let high_watermark = page["high_watermark"].as_u64().unwrap();
    let receipt = page["page_receipt"].as_str().unwrap();

    // 4. Device 2 acknowledges the snapshot page
    let ack_req_body = serde_json::json!({
        "sync_session_id": session_id,
        "terminal_seq": high_watermark,
        "page_receipt": receipt,
    });
    let ack_bytes = serde_json::to_vec(&ack_req_body).unwrap();
    let ack_req = sign_request(
        "POST",
        "/v1/sync/ack",
        &ack_bytes,
        &device_key_2,
        &account_id,
        Some(device_id_2),
        false,
    );
    let ack_res = router.clone().oneshot(ack_req).await.unwrap();
    assert_eq!(ack_res.status(), StatusCode::OK);
    let ack_body = to_bytes(ack_res.into_body(), 1024 * 1024).await.unwrap();
    let ack_resp: serde_json::Value = serde_json::from_slice(&ack_body).unwrap();
    assert_eq!(ack_resp["status"].as_str().unwrap(), "accepted");
    assert_eq!(ack_resp["last_seen_seq"].as_u64().unwrap(), high_watermark);

    // 5. Test Ack Idempotent Retry
    let ack_retry_req = sign_request(
        "POST",
        "/v1/sync/ack",
        &ack_bytes,
        &device_key_2,
        &account_id,
        Some(device_id_2),
        false,
    );
    let ack_retry_res = router.clone().oneshot(ack_retry_req).await.unwrap();
    assert_eq!(ack_retry_res.status(), StatusCode::OK);
    let ack_retry_body = to_bytes(ack_retry_res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let ack_retry_resp: serde_json::Value = serde_json::from_slice(&ack_retry_body).unwrap();
    assert_eq!(ack_retry_resp["status"].as_str().unwrap(), "duplicate");
    assert_eq!(
        ack_retry_resp["last_seen_seq"].as_u64().unwrap(),
        high_watermark
    );

    // Verify GET /v1/accounts/me now reports device 2 with first_sync_at set!
    let me_req_2 = sign_request(
        "GET",
        "/v1/accounts/me",
        b"",
        &device_key_2,
        &account_id,
        Some(device_id_2),
        false,
    );
    let me_res_2 = router.clone().oneshot(me_req_2).await.unwrap();
    assert_eq!(me_res_2.status(), StatusCode::OK);
    let me_body_2 = to_bytes(me_res_2.into_body(), 1024 * 1024).await.unwrap();
    let me_json_2: serde_json::Value = serde_json::from_slice(&me_body_2).unwrap();
    assert!(me_json_2["device"]["first_sync_at"].is_string());
    assert_eq!(
        me_json_2["checkpoint"]["last_seen_seq"].as_u64().unwrap(),
        high_watermark
    );

    // 6. Test Incremental Pull on Device 2
    // Primary device writes a new item (item_id_3)
    let item_id_3 = Uuid::new_v4();
    let op_id_5 = Uuid::new_v4();
    let batch_3_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": op_id_5.to_string(),
                "item_id": item_id_3.to_string(),
                "base_version": 0,
                "key_version": 1,
                "blob": dummy_blob,
            }
        ]
    });
    let b3_bytes = serde_json::to_vec(&batch_3_body).unwrap();
    let b3_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &b3_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let b3_res = router.clone().oneshot(b3_req).await.unwrap();
    assert_eq!(b3_res.status(), StatusCode::OK);

    // Device 2 pulls incrementally starting from its acknowledged checkpoint (high_watermark)
    let inc_pull_body = serde_json::json!({
        "checkpoint": high_watermark,
        "page_size": 50,
    });
    let inc_bytes = serde_json::to_vec(&inc_pull_body).unwrap();
    let inc_req = sign_request(
        "POST",
        "/v1/sync/pull",
        &inc_bytes,
        &device_key_2,
        &account_id,
        Some(device_id_2),
        false,
    );
    let inc_res = router.clone().oneshot(inc_req).await.unwrap();
    assert_eq!(inc_res.status(), StatusCode::OK);
    let inc_page_body = to_bytes(inc_res.into_body(), 1024 * 1024).await.unwrap();
    let inc_page: serde_json::Value = serde_json::from_slice(&inc_page_body).unwrap();
    assert!(inc_page["done"].as_bool().unwrap());
    let inc_items = inc_page["items"].as_array().unwrap();
    assert_eq!(inc_items.len(), 1);
    assert_eq!(
        inc_items[0]["item_id"].as_str().unwrap(),
        item_id_3.to_string()
    );
}

#[tokio::test]
async fn test_multipage_pull_and_continuation_token() {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://nexxpass:change-me@localhost:5432/nexxpass_sync".to_string()
    });

    let config = Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        database_url,
        database_max_connections: 5,
        token_hmac_key: [0x77; 32],
        deployment_epoch: 1,
        maintenance_interval_seconds: 3600,
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

    let identity_key = make_signing_key(0x31);
    let device_key = make_signing_key(0x32);
    let account_id: [u8; 32] = Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(Uuid::new_v4().as_bytes())
        .copied()
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let device_id = Uuid::new_v4();

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
            "device_label": "Test Device MultiPage",
            "wrap": URL_SAFE_NO_PAD.encode([0x44; 105]),
        },
        "recovery_wrap": URL_SAFE_NO_PAD.encode([0x33; 105]),
    });
    let reg_bytes = serde_json::to_vec(&reg_body).unwrap();
    let reg_req = sign_request(
        "POST",
        "/v1/accounts",
        &reg_bytes,
        &identity_key,
        &account_id,
        None,
        true,
    );
    let reg_res = router.clone().oneshot(reg_req).await.unwrap();
    assert_eq!(reg_res.status(), StatusCode::CREATED);

    // Create 5 items in a single batch
    let dummy_blob = URL_SAFE_NO_PAD.encode(vec![0xaa; 600]);
    let mut ops = Vec::new();
    for _ in 0..5 {
        ops.push(serde_json::json!({
            "op": "put",
            "operation_id": Uuid::new_v4().to_string(),
            "item_id": Uuid::new_v4().to_string(),
            "base_version": 0,
            "key_version": 1,
            "blob": dummy_blob,
        }));
    }
    let batch_req_body = serde_json::json!({ "operations": ops });
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

    // Page 1: Request with page_size = 2
    let p1_body = serde_json::json!({ "checkpoint": 0, "page_size": 2 });
    let p1_bytes = serde_json::to_vec(&p1_body).unwrap();
    let p1_req = sign_request(
        "POST",
        "/v1/sync/pull",
        &p1_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let p1_res = router.clone().oneshot(p1_req).await.unwrap();
    assert_eq!(p1_res.status(), StatusCode::OK);
    let p1_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(p1_res.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(p1_json["items"].as_array().unwrap().len(), 2);
    assert!(!p1_json["done"].as_bool().unwrap());
    let token_1 = p1_json["continuation_token"].as_str().unwrap();
    let session_id = p1_json["sync_session_id"].as_str().unwrap();
    let receipt_1 = p1_json["page_receipt"].as_str().unwrap();

    // Acknowledge Page 1
    let ack_1_body = serde_json::json!({
        "sync_session_id": session_id,
        "terminal_seq": p1_json["page_cursor"].as_u64().unwrap(),
        "page_receipt": receipt_1,
    });
    let ack_1_req = sign_request(
        "POST",
        "/v1/sync/ack",
        &serde_json::to_vec(&ack_1_body).unwrap(),
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let ack_1_res = router.clone().oneshot(ack_1_req).await.unwrap();
    assert_eq!(ack_1_res.status(), StatusCode::OK);

    // Page 2: Continue using token_1
    let p2_body = serde_json::json!({ "continuation_token": token_1 });
    let p2_bytes = serde_json::to_vec(&p2_body).unwrap();
    let p2_req = sign_request(
        "POST",
        "/v1/sync/pull",
        &p2_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let p2_res = router.clone().oneshot(p2_req).await.unwrap();
    assert_eq!(p2_res.status(), StatusCode::OK);
    let p2_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(p2_res.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(p2_json["items"].as_array().unwrap().len(), 2);
    assert!(!p2_json["done"].as_bool().unwrap());
    let token_2 = p2_json["continuation_token"].as_str().unwrap();
    let receipt_2 = p2_json["page_receipt"].as_str().unwrap();

    // Acknowledge Page 2
    let ack_2_body = serde_json::json!({
        "sync_session_id": session_id,
        "terminal_seq": p2_json["page_cursor"].as_u64().unwrap(),
        "page_receipt": receipt_2,
    });
    let ack_2_req = sign_request(
        "POST",
        "/v1/sync/ack",
        &serde_json::to_vec(&ack_2_body).unwrap(),
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let ack_2_res = router.clone().oneshot(ack_2_req).await.unwrap();
    assert_eq!(ack_2_res.status(), StatusCode::OK);

    // Page 3: Final page using token_2
    let p3_body = serde_json::json!({ "continuation_token": token_2 });
    let p3_bytes = serde_json::to_vec(&p3_body).unwrap();
    let p3_req = sign_request(
        "POST",
        "/v1/sync/pull",
        &p3_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let p3_res = router.clone().oneshot(p3_req).await.unwrap();
    assert_eq!(p3_res.status(), StatusCode::OK);
    let p3_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(p3_res.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(p3_json["items"].as_array().unwrap().len(), 1);
    assert!(p3_json["done"].as_bool().unwrap());
    assert!(p3_json["continuation_token"].is_null());
    let receipt_3 = p3_json["page_receipt"].as_str().unwrap();

    // Acknowledge Page 3
    let ack_3_body = serde_json::json!({
        "sync_session_id": session_id,
        "terminal_seq": p3_json["page_cursor"].as_u64().unwrap(),
        "page_receipt": receipt_3,
    });
    let ack_3_req = sign_request(
        "POST",
        "/v1/sync/ack",
        &serde_json::to_vec(&ack_3_body).unwrap(),
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let ack_3_res = router.clone().oneshot(ack_3_req).await.unwrap();
    assert_eq!(ack_3_res.status(), StatusCode::OK);
}

fn sign_identity_request(
    method: &str,
    path: &str,
    body_bytes: &[u8],
    signing_key: &SigningKey,
    account_id: &[u8],
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
        .header("x-nexxpass-signature", sig_b64u)
        .header("x-nexxpass-account", URL_SAFE_NO_PAD.encode(account_id))
        .header("x-nexxpass-key", "identity");

    if !body_bytes.is_empty() {
        builder = builder.header("content-type", "application/json");
    }

    builder.body(Body::from(body_bytes.to_vec())).unwrap()
}

async fn setup_test_app() -> (axum::Router, AppState) {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://nexxpass:change-me@localhost:5432/nexxpass_sync".to_string()
    });

    let config = Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        database_url,
        database_max_connections: 5,
        token_hmac_key: [0x55; 32],
        deployment_epoch: 1,
        maintenance_interval_seconds: 3600,
    };

    let state = AppState::connect(&config).await.expect("connect db");
    state.migrate().await.expect("apply migrations");
    let router = http::router(state.clone());
    (router, state)
}

#[tokio::test]
async fn test_device_management_and_recovery_lifecycle() {
    let (router, _state) = setup_test_app().await;

    let identity_key = make_signing_key(0x31);
    let device_key = make_signing_key(0x32);
    let account_id: [u8; 32] = Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(Uuid::new_v4().as_bytes())
        .copied()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let device_id = Uuid::new_v4();

    let wrap_105 = [0x77u8; 105];
    let wrap_b64u = URL_SAFE_NO_PAD.encode(wrap_105);

    // 1. Register account
    let reg_body = serde_json::json!({
        "account_id": URL_SAFE_NO_PAD.encode(account_id),
        "identity_ed25519_pub": URL_SAFE_NO_PAD.encode(identity_key.verifying_key().to_bytes()),
        "identity_x25519_pub": URL_SAFE_NO_PAD.encode([0x33u8; 32]),
        "derivation_version": 1,
        "recovery_wrap": wrap_b64u,
        "device": {
            "device_id": device_id.to_string(),
            "device_ed25519_pub": URL_SAFE_NO_PAD.encode(device_key.verifying_key().to_bytes()),
            "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x44u8; 32]),
            "device_label": "Device 1",
            "wrap": wrap_b64u,
        }
    });

    let reg_req = sign_request(
        "POST",
        "/v1/accounts",
        &serde_json::to_vec(&reg_body).unwrap(),
        &identity_key,
        &account_id,
        None,
        true,
    );
    let reg_res = router.clone().oneshot(reg_req).await.unwrap();
    assert_eq!(reg_res.status(), StatusCode::CREATED);

    // 2. Read recovery wraps via GET /v1/accounts/recovery (identity-signed)
    let rec_req = sign_identity_request(
        "GET",
        "/v1/accounts/recovery",
        &[],
        &identity_key,
        &account_id,
    );
    let rec_res = router.clone().oneshot(rec_req).await.unwrap();
    assert_eq!(rec_res.status(), StatusCode::OK);
    let rec_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(rec_res.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    let wraps = rec_json["wraps"].as_array().unwrap();
    assert_eq!(wraps.len(), 1);
    assert_eq!(wraps[0]["recipient"].as_str().unwrap(), "recovery");
    assert_eq!(wraps[0]["status"].as_str().unwrap(), "active");

    // 3. Register Device 2 via recovery phrase (POST /v1/devices, identity-signed)
    let device_2_key = make_signing_key(0x33);
    let device_2_id = Uuid::new_v4();
    let dev2_body = serde_json::json!({
        "device_id": device_2_id.to_string(),
        "device_ed25519_pub": URL_SAFE_NO_PAD.encode(device_2_key.verifying_key().to_bytes()),
        "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x55u8; 32]),
        "device_label": "Device 2 Recovery",
        "wrap": wrap_b64u,
    });
    let dev2_req = sign_identity_request(
        "POST",
        "/v1/devices",
        &serde_json::to_vec(&dev2_body).unwrap(),
        &identity_key,
        &account_id,
    );
    let dev2_res = router.clone().oneshot(dev2_req).await.unwrap();
    assert_eq!(dev2_res.status(), StatusCode::CREATED);

    // 4. List devices via GET /v1/devices (device-signed by device 1)
    let list_req = sign_request(
        "GET",
        "/v1/devices",
        &[],
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let list_res = router.clone().oneshot(list_req).await.unwrap();
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(list_res.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    let dev_list = list_json["devices"].as_array().unwrap();
    assert_eq!(dev_list.len(), 2);

    // 5. Revoke Device 2 via DELETE /v1/devices/{device_id}
    let revoke_path = format!("/v1/devices/{device_2_id}");
    let revoke_req = sign_request(
        "DELETE",
        &revoke_path,
        &[],
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let revoke_res = router.clone().oneshot(revoke_req).await.unwrap();
    assert_eq!(revoke_res.status(), StatusCode::OK);

    // Device 2 is now rejected
    let d2_req = sign_request(
        "GET",
        "/v1/devices",
        &[],
        &device_2_key,
        &account_id,
        Some(device_2_id),
        false,
    );
    let d2_res = router.clone().oneshot(d2_req).await.unwrap();
    assert_eq!(d2_res.status(), StatusCode::FORBIDDEN);

    // 6. Lock identity via POST /v1/accounts/lock
    let lock_req = sign_request(
        "POST",
        "/v1/accounts/lock",
        &[],
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let lock_res = router.clone().oneshot(lock_req).await.unwrap();
    assert_eq!(lock_res.status(), StatusCode::OK);

    // Identity-signed requests now return identity_locked (403)
    let locked_rec_req = sign_identity_request(
        "GET",
        "/v1/accounts/recovery",
        &[],
        &identity_key,
        &account_id,
    );
    let locked_rec_res = router.clone().oneshot(locked_rec_req).await.unwrap();
    assert_eq!(locked_rec_res.status(), StatusCode::FORBIDDEN);

    // Device 1 continues to work
    let me_req = sign_request(
        "GET",
        "/v1/accounts/me",
        &[],
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let me_res = router.clone().oneshot(me_req).await.unwrap();
    assert_eq!(me_res.status(), StatusCode::OK);
    let me_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(me_res.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(me_json["status"].as_str().unwrap(), "identity_locked");

    // 7. In-place identity migration via POST /v1/accounts/migrate
    let new_identity_key = make_signing_key(0x34);
    let new_recovery_wrap = [0x88u8; 105];
    let new_wrap_b64u = URL_SAFE_NO_PAD.encode(new_recovery_wrap);

    let mig_body = serde_json::json!({
        "identity_ed25519_pub": URL_SAFE_NO_PAD.encode(new_identity_key.verifying_key().to_bytes()),
        "identity_x25519_pub": URL_SAFE_NO_PAD.encode([0x66u8; 32]),
        "derivation_version": 2,
        "recovery_wraps": [
            {
                "key_version": 1,
                "wrap": new_wrap_b64u,
            }
        ]
    });
    let mig_bytes = serde_json::to_vec(&mig_body).unwrap();

    // Compute countersignature by old identity key
    let body_hash_hex = hex_lower(&Sha256::digest(&mig_bytes));
    let mut preimage = Vec::with_capacity(9 + 32 + 64);
    preimage.extend_from_slice(b"NPSIdMig1");
    preimage.extend_from_slice(&account_id);
    preimage.extend_from_slice(body_hash_hex.as_bytes());
    let countersig = identity_key.sign(&preimage);
    let countersig_b64u = URL_SAFE_NO_PAD.encode(countersig.to_bytes());

    let mut mig_req = sign_request(
        "POST",
        "/v1/accounts/migrate",
        &mig_bytes,
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    mig_req
        .headers_mut()
        .insert("x-nexxpass-countersign", countersig_b64u.parse().unwrap());

    let mig_res = router.clone().oneshot(mig_req).await.unwrap();
    assert_eq!(mig_res.status(), StatusCode::OK);

    // Old identity key is rejected
    let old_rec_req = sign_identity_request(
        "GET",
        "/v1/accounts/recovery",
        &[],
        &identity_key,
        &account_id,
    );
    let old_rec_res = router.clone().oneshot(old_rec_req).await.unwrap();
    assert_eq!(old_rec_res.status(), StatusCode::UNAUTHORIZED);

    // New identity key succeeds!
    let new_rec_req = sign_identity_request(
        "GET",
        "/v1/accounts/recovery",
        &[],
        &new_identity_key,
        &account_id,
    );
    let new_rec_res = router.clone().oneshot(new_rec_req).await.unwrap();
    assert_eq!(new_rec_res.status(), StatusCode::OK);
    let new_rec_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(new_rec_res.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let new_wraps = new_rec_json["wraps"].as_array().unwrap();
    assert_eq!(new_wraps.len(), 1);
    assert_eq!(new_wraps[0]["wrap"].as_str().unwrap(), new_wrap_b64u);

    // 8. Request account deletion via DELETE /v1/accounts
    let del_req = sign_identity_request(
        "DELETE",
        "/v1/accounts",
        &[],
        &new_identity_key,
        &account_id,
    );
    let del_res = router.clone().oneshot(del_req).await.unwrap();
    assert_eq!(del_res.status(), StatusCode::OK);
    let del_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(del_res.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(del_json["status"].as_str().unwrap(), "deletion_pending");
    assert!(del_json["deletion_requested_at"].is_string());

    // 9. Cancel account deletion via POST /v1/accounts/deletion/cancel
    let cancel_req = sign_request(
        "POST",
        "/v1/accounts/deletion/cancel",
        &[],
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let cancel_res = router.clone().oneshot(cancel_req).await.unwrap();
    assert_eq!(cancel_res.status(), StatusCode::OK);
    let cancel_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(cancel_res.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(cancel_json["status"].as_str().unwrap(), "active");
}

#[tokio::test]
async fn test_rotation_state_machine_routine_abort_and_mpc_complete() {
    let (router, _state) = setup_test_app().await;

    let identity_key = make_signing_key(0x41);
    let device_1_key = make_signing_key(0x42);
    let device_2_key = make_signing_key(0x43);

    let account_id: [u8; 32] = Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(Uuid::new_v4().as_bytes())
        .copied()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let device_1_id = Uuid::new_v4();
    let device_2_id = Uuid::new_v4();

    let wrap_105 = [0x77u8; 105];
    let wrap_b64u = URL_SAFE_NO_PAD.encode(wrap_105);

    // 1. Register account with device 1
    let reg_body = serde_json::json!({
        "account_id": URL_SAFE_NO_PAD.encode(account_id),
        "identity_ed25519_pub": URL_SAFE_NO_PAD.encode(identity_key.verifying_key().to_bytes()),
        "identity_x25519_pub": URL_SAFE_NO_PAD.encode([0x33u8; 32]),
        "derivation_version": 1,
        "recovery_wrap": wrap_b64u,
        "device": {
            "device_id": device_1_id.to_string(),
            "device_ed25519_pub": URL_SAFE_NO_PAD.encode(device_1_key.verifying_key().to_bytes()),
            "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x44u8; 32]),
            "device_label": "Device 1",
            "wrap": wrap_b64u,
        }
    });

    let reg_req = sign_request(
        "POST",
        "/v1/accounts",
        &serde_json::to_vec(&reg_body).unwrap(),
        &identity_key,
        &account_id,
        None,
        true,
    );
    let reg_res = router.clone().oneshot(reg_req).await.unwrap();
    assert_eq!(reg_res.status(), StatusCode::CREATED);

    // 2. Register Device 2 via recovery
    let dev2_body = serde_json::json!({
        "device_id": device_2_id.to_string(),
        "device_ed25519_pub": URL_SAFE_NO_PAD.encode(device_2_key.verifying_key().to_bytes()),
        "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x55u8; 32]),
        "device_label": "Device 2",
        "wrap": wrap_b64u,
    });
    let dev2_req = sign_identity_request(
        "POST",
        "/v1/devices",
        &serde_json::to_vec(&dev2_body).unwrap(),
        &identity_key,
        &account_id,
    );
    let dev2_res = router.clone().oneshot(dev2_req).await.unwrap();
    assert_eq!(dev2_res.status(), StatusCode::CREATED);

    // 3. Start Routine Rotation (POST /v1/rotation/start)
    let target_wrap = [0x88u8; 105];
    let target_wrap_b64u = URL_SAFE_NO_PAD.encode(target_wrap);

    let start_body = serde_json::json!({
        "mode": "routine",
        "recovery_wrap": target_wrap_b64u,
        "device_wraps": [
            { "device_id": device_1_id.to_string(), "wrap": target_wrap_b64u },
            { "device_id": device_2_id.to_string(), "wrap": target_wrap_b64u },
        ]
    });
    let start_req = sign_request(
        "POST",
        "/v1/rotation/start",
        &serde_json::to_vec(&start_body).unwrap(),
        &device_1_key,
        &account_id,
        Some(device_1_id),
        false,
    );
    let start_res = router.clone().oneshot(start_req).await.unwrap();
    assert_eq!(start_res.status(), StatusCode::OK);
    let start_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(start_res.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(start_json["mode"].as_str().unwrap(), "routine");
    assert_eq!(start_json["target_key_version"].as_i64().unwrap(), 2);

    // 4. Heartbeat lease
    let hb_req = sign_request(
        "POST",
        "/v1/rotation/heartbeat",
        &[],
        &device_1_key,
        &account_id,
        Some(device_1_id),
        false,
    );
    let hb_res = router.clone().oneshot(hb_req).await.unwrap();
    assert_eq!(hb_res.status(), StatusCode::OK);

    // 5. Abort routine rotation
    let abort_req = sign_request(
        "POST",
        "/v1/rotation/abort",
        &[],
        &device_1_key,
        &account_id,
        Some(device_1_id),
        false,
    );
    let abort_res = router.clone().oneshot(abort_req).await.unwrap();
    assert_eq!(abort_res.status(), StatusCode::OK);
    let abort_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(abort_res.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(abort_json["mode"].as_str().unwrap(), "idle");

    // 6. Start Master Password Change rotation
    // Note: target_key_version should now be 3 (since version 2 was retired).
    let mpc_start_body = serde_json::json!({
        "mode": "master_password_change",
        "recovery_wrap": target_wrap_b64u,
        "device_wraps": [
            { "device_id": device_1_id.to_string(), "wrap": target_wrap_b64u },
            { "device_id": device_2_id.to_string(), "wrap": target_wrap_b64u },
        ]
    });
    let mpc_start_req = sign_request(
        "POST",
        "/v1/rotation/start",
        &serde_json::to_vec(&mpc_start_body).unwrap(),
        &device_1_key,
        &account_id,
        Some(device_1_id),
        false,
    );
    let mpc_start_res = router.clone().oneshot(mpc_start_req).await.unwrap();
    assert_eq!(mpc_start_res.status(), StatusCode::OK);
    let mpc_start_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(mpc_start_res.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        mpc_start_json["mode"].as_str().unwrap(),
        "master_password_change"
    );
    assert_eq!(mpc_start_json["target_key_version"].as_i64().unwrap(), 3);
    assert!(mpc_start_json["writes_frozen"].as_bool().unwrap());

    // 7. Normal writes are frozen
    let item_uuid = Uuid::new_v4();
    let blob_bytes = vec![0x99u8; 600];
    let blob_b64u = URL_SAFE_NO_PAD.encode(&blob_bytes);
    let batch_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": item_uuid.to_string(),
                "base_version": 0,
                "key_version": 3,
                "blob": blob_b64u,
            }
        ]
    });
    let frozen_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &serde_json::to_vec(&batch_body).unwrap(),
        &device_1_key,
        &account_id,
        Some(device_1_id),
        false,
    );
    let frozen_res = router.clone().oneshot(frozen_req).await.unwrap();
    assert_eq!(frozen_res.status(), StatusCode::CONFLICT); // rotation_in_progress

    // 8. Lease owner rewrites via POST /v1/rotation/rewrite
    let rewrite_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": item_uuid.to_string(),
                "base_version": 0,
                "key_version": 3,
                "blob": blob_b64u,
            }
        ]
    });
    let rewrite_req = sign_request(
        "POST",
        "/v1/rotation/rewrite",
        &serde_json::to_vec(&rewrite_body).unwrap(),
        &device_1_key,
        &account_id,
        Some(device_1_id),
        false,
    );
    let rewrite_res = router.clone().oneshot(rewrite_req).await.unwrap();
    assert_eq!(rewrite_res.status(), StatusCode::OK);
    let rewrite_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(rewrite_res.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        rewrite_json["results"][0]["status"].as_str().unwrap(),
        "applied"
    );

    // 9. Option A: Complete rotation immediately on Device 1 without waiting for Device 2 ack
    let comp_req = sign_request(
        "POST",
        "/v1/rotation/complete",
        &[],
        &device_1_key,
        &account_id,
        Some(device_1_id),
        false,
    );
    let comp_res = router.clone().oneshot(comp_req).await.unwrap();
    assert_eq!(comp_res.status(), StatusCode::OK);
    let comp_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(comp_res.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(comp_json["mode"].as_str().unwrap(), "idle");
    assert_eq!(comp_json["active_key_version"].as_i64().unwrap(), 3);
    assert!(!comp_json["writes_frozen"].as_bool().unwrap());

    // 10. Device 1 can write immediately under active key version 3
    let unfrozen_item_uuid = Uuid::new_v4();
    let unfrozen_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": unfrozen_item_uuid.to_string(),
                "base_version": 0,
                "key_version": 3,
                "blob": blob_b64u,
            }
        ]
    });
    let unfrozen_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &serde_json::to_vec(&unfrozen_body).unwrap(),
        &device_1_key,
        &account_id,
        Some(device_1_id),
        false,
    );
    let unfrozen_res = router.clone().oneshot(unfrozen_req).await.unwrap();
    assert_eq!(unfrozen_res.status(), StatusCode::OK);
    let unfrozen_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(unfrozen_res.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        unfrozen_json["results"][0]["status"].as_str().unwrap(),
        "applied"
    );

    // 11. Offline Device 2 attempts write with old key_version (1) -> rejected with unsupported_key_version
    let stale_write_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": Uuid::new_v4().to_string(),
                "base_version": 0,
                "key_version": 1,
                "blob": blob_b64u,
            }
        ]
    });
    let stale_write_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &serde_json::to_vec(&stale_write_body).unwrap(),
        &device_2_key,
        &account_id,
        Some(device_2_id),
        false,
    );
    let stale_write_res = router.clone().oneshot(stale_write_req).await.unwrap();
    assert_eq!(stale_write_res.status(), StatusCode::OK);
    let stale_write_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(stale_write_res.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        stale_write_json["results"][0]["status"].as_str().unwrap(),
        "unsupported_key_version"
    );

    // 12. Device 2 wakes up, enters new password, and acknowledges key_version 3 in idle mode
    let ack_2_body = serde_json::json!({
        "key_version": 3,
        "local_master_password_updated": true,
    });
    let ack_2_req = sign_request(
        "POST",
        "/v1/rotation/ack",
        &serde_json::to_vec(&ack_2_body).unwrap(),
        &device_2_key,
        &account_id,
        Some(device_2_id),
        false,
    );
    let ack_2_res = router.clone().oneshot(ack_2_req).await.unwrap();
    assert_eq!(ack_2_res.status(), StatusCode::OK);
    let ack_2_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(ack_2_res.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(ack_2_json["active_key_version"].as_i64().unwrap(), 3);
    assert_eq!(ack_2_json["mode"].as_str().unwrap(), "idle");

    // 13. Device 2 can now write with key_version 3
    let dev2_write_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": Uuid::new_v4().to_string(),
                "base_version": 0,
                "key_version": 3,
                "blob": blob_b64u,
            }
        ]
    });
    let dev2_write_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &serde_json::to_vec(&dev2_write_body).unwrap(),
        &device_2_key,
        &account_id,
        Some(device_2_id),
        false,
    );
    let dev2_write_res = router.clone().oneshot(dev2_write_req).await.unwrap();
    assert_eq!(dev2_write_res.status(), StatusCode::OK);
    let dev2_write_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(dev2_write_res.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        dev2_write_json["results"][0]["status"].as_str().unwrap(),
        "applied"
    );
}

#[tokio::test]
async fn test_background_maintenance_jobs_and_advisory_locking() {
    let (_router, state) = setup_test_app().await;

    let pool = &state.database;

    // 1. Run maintenance normally -> acquires lock, returns Some(stats)
    let stats = nexxpass_sync_server::maintenance::run_maintenance(pool)
        .await
        .expect("maintenance should run cleanly")
        .expect("should acquire advisory lock");
    assert_eq!(stats.expired_cleaned, 0);

    // 2. Simulate another instance holding the advisory lock
    let mut conn = pool.acquire().await.unwrap();
    let lock_acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(nexxpass_sync_server::maintenance::MAINTENANCE_ADVISORY_LOCK_ID)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert!(
        lock_acquired,
        "test connection should acquire advisory lock"
    );

    // 3. Maintenance attempt while lock is held should return Ok(None)
    let skipped = nexxpass_sync_server::maintenance::run_maintenance(pool)
        .await
        .expect("maintenance should run cleanly");
    assert!(skipped.is_none(), "should skip execution when lock is held");

    // 4. Release lock on test connection
    let _: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
        .bind(nexxpass_sync_server::maintenance::MAINTENANCE_ADVISORY_LOCK_ID)
        .fetch_one(&mut *conn)
        .await
        .unwrap();

    // 5. Maintenance can now run again
    let rerun = nexxpass_sync_server::maintenance::run_maintenance(pool)
        .await
        .expect("maintenance should run cleanly");
    assert!(rerun.is_some(), "should run after lock is released");
}

#[tokio::test]
async fn test_deep_healthchecks() {
    let (router, _state) = setup_test_app().await;

    // GET /health/live
    let live_req = Request::builder()
        .method("GET")
        .uri("/health/live")
        .body(Body::empty())
        .unwrap();
    let live_res = router.clone().oneshot(live_req).await.unwrap();
    assert_eq!(live_res.status(), StatusCode::OK);
    let live_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(live_res.into_body(), 1024).await.unwrap()).unwrap();
    assert_eq!(live_json["status"].as_str().unwrap(), "live");

    // GET /health/ready
    let ready_req = Request::builder()
        .method("GET")
        .uri("/health/ready")
        .body(Body::empty())
        .unwrap();
    let ready_res = router.clone().oneshot(ready_req).await.unwrap();
    assert_eq!(ready_res.status(), StatusCode::OK);
    let ready_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(ready_res.into_body(), 1024).await.unwrap()).unwrap();
    assert_eq!(ready_json["status"].as_str().unwrap(), "ready");
    assert_eq!(ready_json["database"].as_str().unwrap(), "connected");
}

#[tokio::test]
async fn test_realtime_sync_events_sse() {
    use http_body_util::BodyExt;

    let (router, _state) = setup_test_app().await;

    let identity_key = make_signing_key(0x71);
    let device_key = make_signing_key(0x72);
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

    let reg_body = serde_json::json!({
        "account_id": URL_SAFE_NO_PAD.encode(account_id),
        "identity_ed25519_pub": URL_SAFE_NO_PAD.encode(identity_key.verifying_key().to_bytes()),
        "identity_x25519_pub": URL_SAFE_NO_PAD.encode([0x55; 32]),
        "derivation_version": 1,
        "device": {
            "device_id": device_id.to_string(),
            "device_ed25519_pub": URL_SAFE_NO_PAD.encode(device_key.verifying_key().to_bytes()),
            "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x66; 32]),
            "device_label": "Test SSE Device",
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

    // 1. Subscribe to SSE events endpoint
    let sse_req = sign_request(
        "GET",
        "/v1/sync/events",
        &[],
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let sse_res = router.clone().oneshot(sse_req).await.unwrap();
    assert_eq!(sse_res.status(), StatusCode::OK);
    assert_eq!(
        sse_res
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/event-stream"
    );

    // 2. Push a sync batch with 1 mutation
    let blob_bytes = vec![0x42u8; 600];
    let blob_b64u = URL_SAFE_NO_PAD.encode(&blob_bytes);
    let batch_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": Uuid::new_v4().to_string(),
                "base_version": 0,
                "key_version": 1,
                "blob": blob_b64u,
            }
        ]
    });
    let batch_req = sign_request(
        "POST",
        "/v1/sync/batch",
        &serde_json::to_vec(&batch_body).unwrap(),
        &device_key,
        &account_id,
        Some(device_id),
        false,
    );
    let batch_res = router.clone().oneshot(batch_req).await.unwrap();
    assert_eq!(batch_res.status(), StatusCode::OK);

    // 3. Read the emitted event from the SSE response stream
    let mut body = sse_res.into_body();
    let frame = body.frame().await.unwrap().unwrap();
    let data_bytes = frame.into_data().unwrap();
    let event_str = String::from_utf8(data_bytes.to_vec()).unwrap();
    assert!(event_str.contains("event: sync"));
    assert!(event_str.contains("\"seq\":1"));
}

#[tokio::test]
async fn test_rate_limiting_pairing() {
    let (router, _state) = setup_test_app().await;

    let target_account_id = [0x55u8; 32];
    let device_key = make_signing_key(0x56);
    let device_pub_b64u = URL_SAFE_NO_PAD.encode(device_key.verifying_key().to_bytes());
    let x25519_b64u = URL_SAFE_NO_PAD.encode([0x57u8; 32]);

    for i in 0..20 {
        let dev_id = Uuid::new_v4();
        let body = serde_json::json!({
            "target_account_id": URL_SAFE_NO_PAD.encode(target_account_id),
            "device_id": dev_id.to_string(),
            "device_ed25519_pub": device_pub_b64u,
            "device_x25519_pub": x25519_b64u,
            "device_label": format!("Device {i}"),
        });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/pairings")
            .header("x-nexxpass-protocol", "1")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
    }

    // 21st request exceeds rate limit (20 req / minute)
    let dev_id = Uuid::new_v4();
    let body = serde_json::json!({
        "target_account_id": URL_SAFE_NO_PAD.encode(target_account_id),
        "device_id": dev_id.to_string(),
        "device_ed25519_pub": device_pub_b64u,
        "device_x25519_pub": x25519_b64u,
        "device_label": "Device 21",
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/pairings")
        .header("x-nexxpass-protocol", "1")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key("retry-after"));
    let err_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(res.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(err_json["error"]["code"].as_str().unwrap(), "rate_limited");
}

#[tokio::test]
async fn test_active_device_quota() {
    let (router, _state) = setup_test_app().await;

    let identity_key = make_signing_key(0x61);
    let device_key = make_signing_key(0x62);
    let account_id: [u8; 32] = Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(Uuid::new_v4().as_bytes())
        .copied()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let device_id = Uuid::new_v4();
    let wrap_b64u = URL_SAFE_NO_PAD.encode([0x77u8; 105]);

    // 1. Register account with first device (count = 1)
    let reg_body = serde_json::json!({
        "account_id": URL_SAFE_NO_PAD.encode(account_id),
        "identity_ed25519_pub": URL_SAFE_NO_PAD.encode(identity_key.verifying_key().to_bytes()),
        "identity_x25519_pub": URL_SAFE_NO_PAD.encode([0x33u8; 32]),
        "derivation_version": 1,
        "recovery_wrap": wrap_b64u,
        "device": {
            "device_id": device_id.to_string(),
            "device_ed25519_pub": URL_SAFE_NO_PAD.encode(device_key.verifying_key().to_bytes()),
            "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x44u8; 32]),
            "device_label": "Device 1",
            "wrap": wrap_b64u,
        }
    });

    let reg_req = sign_request(
        "POST",
        "/v1/accounts",
        &serde_json::to_vec(&reg_body).unwrap(),
        &identity_key,
        &account_id,
        None,
        true,
    );
    let reg_res = router.clone().oneshot(reg_req).await.unwrap();
    assert_eq!(reg_res.status(), StatusCode::CREATED);

    // 2. Register 9 more devices via recovery (total reaches 10)
    for i in 2..=10 {
        let dk = make_signing_key(0x70 + i as u8);
        let did = Uuid::new_v4();
        let dev_body = serde_json::json!({
            "device_id": did.to_string(),
            "device_ed25519_pub": URL_SAFE_NO_PAD.encode(dk.verifying_key().to_bytes()),
            "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x55u8; 32]),
            "device_label": format!("Device {i}"),
            "wrap": wrap_b64u,
        });
        let req = sign_identity_request(
            "POST",
            "/v1/devices",
            &serde_json::to_vec(&dev_body).unwrap(),
            &identity_key,
            &account_id,
        );
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
    }

    // 3. Registering device 11 exceeds the max 10 active devices cap
    let dk11 = make_signing_key(0x99);
    let did11 = Uuid::new_v4();
    let dev11_body = serde_json::json!({
        "device_id": did11.to_string(),
        "device_ed25519_pub": URL_SAFE_NO_PAD.encode(dk11.verifying_key().to_bytes()),
        "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x55u8; 32]),
        "device_label": "Device 11",
        "wrap": wrap_b64u,
    });
    let req11 = sign_identity_request(
        "POST",
        "/v1/devices",
        &serde_json::to_vec(&dev11_body).unwrap(),
        &identity_key,
        &account_id,
    );
    let res11 = router.clone().oneshot(req11).await.unwrap();
    assert_eq!(res11.status(), StatusCode::TOO_MANY_REQUESTS);
    let err_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(res11.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        err_json["error"]["code"].as_str().unwrap(),
        "quota_exceeded"
    );
}
