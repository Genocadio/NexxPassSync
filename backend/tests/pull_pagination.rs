#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Regression tests for `/v1/sync/pull` pagination correctness.
//!
//! Invariants covered here (plan §7):
//! * a session reports `done` only once every change row in `(cursor, H]` has
//!   been consumed — never because the deduplicated item count fell below
//!   `page_size`;
//! * the continuation cursor advances to the raw change-row boundary, never to
//!   an item's latest-at-H sequence, which can jump past other items' rows;
//! * full snapshots may filter tombstones without ending the session early.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use nexxpass_sync_server::{config::Config, http, state::AppState};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

struct TestEnv {
    router: axum::Router,
    device_key: SigningKey,
    account_id: [u8; 32],
    device_id: Uuid,
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
    let body_digest_hex = {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::new();
        for b in body_hasher.finalize() {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    };

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

    if !is_identity {
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

async fn setup() -> Option<TestEnv> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://nexxpass:change-me@localhost:5432/nexxpass_sync".to_string()
    });
    let config = Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        database_url,
        database_max_connections: 5,
        token_hmac_key: [0x99; 32],
        deployment_epoch: 1,
        maintenance_interval_seconds: 3600,
    };
    let state = match AppState::connect(&config).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping postgres integration test: {e}");
            return None;
        }
    };
    state.migrate().await.unwrap();
    let router = http::router(state.clone());

    let identity_key = SigningKey::from_bytes(&[0x71; 32]);
    let device_key = SigningKey::from_bytes(&[0x72; 32]);
    let account_id: [u8; 32] = Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(Uuid::new_v4().as_bytes())
        .copied()
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let device_id = Uuid::new_v4();

    let reg_body = serde_json::json!({
        "account_id": URL_SAFE_NO_PAD.encode(account_id),
        "identity_ed25519_pub": URL_SAFE_NO_PAD.encode(identity_key.verifying_key().to_bytes()),
        "identity_x25519_pub": URL_SAFE_NO_PAD.encode([0x55; 32]),
        "derivation_version": 1,
        "device": {
            "device_id": device_id.to_string(),
            "device_ed25519_pub": URL_SAFE_NO_PAD.encode(device_key.verifying_key().to_bytes()),
            "device_x25519_pub": URL_SAFE_NO_PAD.encode([0x66; 32]),
            "device_label": "Pull Regression Device",
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

    Some(TestEnv {
        router,
        device_key,
        account_id,
        device_id,
    })
}

impl TestEnv {
    async fn post(&self, path: &str, body: serde_json::Value) -> serde_json::Value {
        let bytes = serde_json::to_vec(&body).unwrap();
        let req = sign_request(
            "POST",
            path,
            &bytes,
            &self.device_key,
            &self.account_id,
            Some(self.device_id),
            false,
        );
        let res = self.router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "POST {path} rejected");
        let raw = to_bytes(res.into_body(), 2 * 1024 * 1024).await.unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    async fn put(&self, item_id: Uuid, base_version: u64) {
        self.post(
            "/v1/sync/batch",
            serde_json::json!({
                "operations": [{
                    "op": "put",
                    "operation_id": Uuid::new_v4().to_string(),
                    "item_id": item_id.to_string(),
                    "base_version": base_version,
                    "key_version": 1,
                    "blob": URL_SAFE_NO_PAD.encode(vec![0xaa; 600]),
                }]
            }),
        )
        .await;
    }

    async fn delete(&self, item_id: Uuid, base_version: u64) {
        self.post(
            "/v1/sync/batch",
            serde_json::json!({
                "operations": [{
                    "op": "delete",
                    "operation_id": Uuid::new_v4().to_string(),
                    "item_id": item_id.to_string(),
                    "base_version": base_version,
                }]
            }),
        )
        .await;
    }

    /// Pulls the whole session, acknowledging every page, and returns the item
    /// IDs observed plus the checkpoint the final ack produced.
    async fn drain_pull(&self, first_request: serde_json::Value) -> (Vec<String>, u64) {
        let mut request = first_request;
        let mut received: Vec<String> = Vec::new();
        let mut pages = 0;

        loop {
            let page = self.post("/v1/sync/pull", request).await;
            pages += 1;
            assert!(pages <= 64, "pull session did not terminate");

            for item in page["items"].as_array().unwrap() {
                received.push(item["item_id"].as_str().unwrap().to_string());
            }

            let ack = self
                .post(
                    "/v1/sync/ack",
                    serde_json::json!({
                        "sync_session_id": page["sync_session_id"],
                        "terminal_seq": page["page_cursor"],
                        "page_receipt": page["page_receipt"],
                    }),
                )
                .await;

            if page["done"].as_bool().unwrap() {
                assert!(
                    page["continuation_token"].is_null(),
                    "final page must not carry a continuation token"
                );
                assert_eq!(
                    page["page_cursor"].as_u64().unwrap(),
                    page["high_watermark"].as_u64().unwrap(),
                    "final page_cursor must equal H"
                );
                return (received, ack["last_seen_seq"].as_u64().unwrap());
            }

            assert!(
                page["continuation_token"].is_string(),
                "non-final page must carry a continuation token"
            );
            request = serde_json::json!({ "continuation_token": page["continuation_token"].as_str().unwrap() });
        }
    }
}

fn assert_all_present(received: &[String], expected: &[Uuid], scenario: &str) {
    for id in expected {
        assert!(
            received.contains(&id.to_string()),
            "{scenario}: item {id} was never delivered (received {received:?})"
        );
    }
}

/// An item with several changes inside one page window shrinks the
/// deduplicated result below `page_size`. The session must keep paging instead
/// of reporting `done` and advancing the checkpoint past undelivered items.
#[tokio::test]
async fn pull_session_does_not_end_on_deduplicated_page() {
    let Some(env) = setup().await else {
        return;
    };

    let item_a = Uuid::new_v4();
    let item_b = Uuid::new_v4();

    env.put(item_a, 0).await; // seq 1
    env.put(item_a, 1).await; // seq 2
    env.put(item_a, 2).await; // seq 3
    env.put(item_a, 3).await; // seq 4
    env.put(item_b, 0).await; // seq 5

    let (received, checkpoint) = env
        .drain_pull(serde_json::json!({ "checkpoint": 0, "page_size": 4 }))
        .await;

    assert_all_present(&received, &[item_a, item_b], "dedup page");
    assert_eq!(checkpoint, 5, "checkpoint must reach H after full delivery");
}

/// An item whose latest-at-H sequence sits past the raw page boundary must not
/// advance the cursor over another item's only change row.
#[tokio::test]
async fn pull_cursor_does_not_skip_undelivered_items() {
    let Some(env) = setup().await else {
        return;
    };

    let item_a = Uuid::new_v4();
    let item_b = Uuid::new_v4();
    let item_c = Uuid::new_v4();

    env.put(item_a, 0).await; // seq 1
    env.put(item_b, 0).await; // seq 2
    env.put(item_c, 0).await; // seq 3
    env.put(item_a, 1).await; // seq 4

    let (received, checkpoint) = env
        .drain_pull(serde_json::json!({ "checkpoint": 0, "page_size": 2 }))
        .await;

    assert_all_present(&received, &[item_a, item_b, item_c], "cursor skip");
    assert_eq!(checkpoint, 4, "checkpoint must reach H after full delivery");
}

/// Full snapshots drop tombstones from the response. That filtering must not
/// terminate the session while live items remain below H.
#[tokio::test]
async fn pull_full_snapshot_survives_tombstone_filtered_page() {
    let Some(env) = setup().await else {
        return;
    };

    let item_a = Uuid::new_v4();
    let item_b = Uuid::new_v4();
    let item_c = Uuid::new_v4();
    let item_d = Uuid::new_v4();

    env.put(item_a, 0).await; // seq 1
    env.put(item_b, 0).await; // seq 2
    env.put(item_c, 0).await; // seq 3
    env.put(item_d, 0).await; // seq 4
    env.delete(item_b, 1).await; // seq 5 (tombstone)

    let (received, checkpoint) = env
        .drain_pull(serde_json::json!({ "checkpoint": 0, "page_size": 3 }))
        .await;

    assert_all_present(&received, &[item_a, item_c, item_d], "tombstone page");
    assert!(
        !received.contains(&item_b.to_string()),
        "full snapshot must omit tombstoned items"
    );
    assert_eq!(checkpoint, 5, "checkpoint must reach H after full delivery");
}
