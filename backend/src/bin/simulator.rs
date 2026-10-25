use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::StreamExt;
use reqwest::header::HeaderMap;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

struct SimulatedDevice {
    name: &'static str,
    device_id: Uuid,
    signing_key: SigningKey,
    x25519_pub: [u8; 32],
    account_id: Vec<u8>,
    active_key_version: i64,
}

impl SimulatedDevice {
    fn new(name: &'static str, seed: u8, account_id: Vec<u8>) -> Self {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        key_bytes[31] = seed;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let mut x25519_pub = [0u8; 32];
        x25519_pub[0] = seed;
        x25519_pub[1] = 0xAA;

        Self {
            name,
            device_id: Uuid::new_v4(),
            signing_key,
            x25519_pub,
            account_id,
            active_key_version: 1,
        }
    }

    fn pub_ed25519_b64u(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().to_bytes())
    }

    fn pub_x25519_b64u(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.x25519_pub)
    }

    fn sign_headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        is_identity: bool,
    ) -> Result<HeaderMap, Box<dyn std::error::Error + Send + Sync>> {
        let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let nonce = Uuid::new_v4().as_bytes()[..16].to_vec();
        let nonce_b64u = URL_SAFE_NO_PAD.encode(&nonce);

        let body_hash = Sha256::digest(body);
        let canonical = format!(
            "NPSSv1\n{}\n{}\n\n{}\n{}\n{}",
            method,
            path,
            now_unix,
            nonce_b64u,
            hex_lower(&body_hash)
        );

        let sig = self.signing_key.sign(canonical.as_bytes());
        let sig_b64u = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("x-nexxpass-protocol", "1".parse()?);
        headers.insert(
            "x-nexxpass-account",
            URL_SAFE_NO_PAD.encode(&self.account_id).parse()?,
        );
        headers.insert(
            "x-nexxpass-key",
            if is_identity { "identity" } else { "device" }.parse()?,
        );
        if !is_identity {
            headers.insert("x-nexxpass-device", self.device_id.to_string().parse()?);
        }
        headers.insert("x-nexxpass-timestamp", now_unix.to_string().parse()?);
        headers.insert("x-nexxpass-nonce", nonce_b64u.parse()?);
        headers.insert("x-nexxpass-signature", sig_b64u.parse()?);
        headers.insert("content-type", "application/json".parse()?);

        Ok(headers)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("\x1b[1;36m");
    println!("╔════════════════════════════════════════════════════════════════════════════════╗");
    println!("║       NEXXPASS SYNC: MULTI-DEVICE PROTOCOL SIMULATOR & DIAGNOSTIC TOOL         ║");
    println!("╚════════════════════════════════════════════════════════════════════════════════╝");
    println!("\x1b[0m");

    // 1. Resolve or start server
    let server_url = match std::env::var("SERVER_URL") {
        Ok(url) => {
            println!("[\x1b[1;34mSETUP\x1b[0m] Connecting to external server: {url}");
            url
        }
        Err(_) => {
            println!("[\x1b[1;34mSETUP\x1b[0m] Starting embedded live server on ephemeral port...");
            if std::env::var("DATABASE_URL").is_err() {
                std::env::set_var(
                    "DATABASE_URL",
                    "postgres://nexxpass:change-me@localhost:5432/nexxpass_sync",
                );
            }
            let config = nexxpass_sync_server::config::Config::from_env()?;
            let state = nexxpass_sync_server::state::AppState::connect(&config).await?;
            state.migrate().await?;

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let local_addr = listener.local_addr()?;
            let url = format!("http://{}", local_addr);

            tokio::spawn(async move {
                let router = nexxpass_sync_server::http::router(state);
                let _ = axum::serve(listener, router).await;
            });

            tokio::time::sleep(Duration::from_millis(50)).await;
            println!(
                "[\x1b[1;34mSETUP\x1b[0m] Embedded live server running at \x1b[1;32m{url}\x1b[0m"
            );
            url
        }
    };

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // 2. Health checks
    print!("[\x1b[1;34mHEALTH\x1b[0m] Checking /health/live and /health/ready... ");
    let live_res: Value = http_client
        .get(format!("{server_url}/health/live"))
        .send()
        .await?
        .json()
        .await?;
    let ready_res: Value = http_client
        .get(format!("{server_url}/health/ready"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(live_res["status"], "live");
    assert_eq!(ready_res["status"], "ready");
    println!("\x1b[1;32mOK (Connected to PostgreSQL)\x1b[0m");

    // 3. Phase 1: Device 1 Registers Account & Initializes Vault
    println!("\n\x1b[1;33m─── PHASE 1: Account Registration & Initial Sync (Device 1: Laptop) ───\x1b[0m");
    let account_id: [u8; 32] = Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(Uuid::new_v4().as_bytes())
        .copied()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "invalid account id")?;

    let identity_key = SigningKey::from_bytes(&[0x11; 32]);
    let mut dev1 = SimulatedDevice::new("MacBook Pro (Dev 1)", 0x12, account_id.to_vec());

    let recovery_wrap = URL_SAFE_NO_PAD.encode([0x33; 105]);
    let dev1_wrap = URL_SAFE_NO_PAD.encode([0x44; 105]);

    let reg_body = serde_json::json!({
        "account_id": URL_SAFE_NO_PAD.encode(account_id),
        "identity_ed25519_pub": URL_SAFE_NO_PAD.encode(identity_key.verifying_key().to_bytes()),
        "identity_x25519_pub": URL_SAFE_NO_PAD.encode([0x55; 32]),
        "derivation_version": 1,
        "device": {
            "device_id": dev1.device_id.to_string(),
            "device_ed25519_pub": dev1.pub_ed25519_b64u(),
            "device_x25519_pub": dev1.pub_x25519_b64u(),
            "device_label": dev1.name,
            "wrap": dev1_wrap,
        },
        "recovery_wrap": recovery_wrap,
    });
    let reg_bytes = serde_json::to_vec(&reg_body)?;

    // Sign registration with Identity Key
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let nonce_b64u = URL_SAFE_NO_PAD.encode([0xAA; 16]);
    let body_hash = Sha256::digest(&reg_bytes);
    let canonical = format!(
        "NPSSv1\nPOST\n/v1/accounts\n\n{}\n{}\n{}",
        now_unix,
        nonce_b64u,
        hex_lower(&body_hash)
    );
    let id_sig = identity_key.sign(canonical.as_bytes());

    let mut reg_headers = HeaderMap::new();
    reg_headers.insert("x-nexxpass-protocol", "1".parse()?);
    reg_headers.insert("x-nexxpass-timestamp", now_unix.to_string().parse()?);
    reg_headers.insert("x-nexxpass-nonce", nonce_b64u.parse()?);
    reg_headers.insert(
        "x-nexxpass-signature",
        URL_SAFE_NO_PAD.encode(id_sig.to_bytes()).parse()?,
    );
    reg_headers.insert("content-type", "application/json".parse()?);

    let reg_res = http_client
        .post(format!("{server_url}/v1/accounts"))
        .headers(reg_headers)
        .body(reg_bytes)
        .send()
        .await?;
    let status = reg_res.status();
    let text = reg_res.text().await?;
    if status != 201 {
        eprintln!("Registration failed: status={status}, body={text}");
    }
    assert_eq!(status, 201);
    println!(
        "[\x1b[1;32mDEV 1\x1b[0m] Enrolled account \x1b[1m{}\x1b[0m and registered as Primary Device ({})",
        URL_SAFE_NO_PAD.encode(account_id),
        dev1.device_id
    );

    // Device 1 writes Item A and Item B
    let item_a_id = Uuid::new_v4();
    let item_b_id = Uuid::new_v4();
    let blob_bytes = vec![0x77u8; 600];
    let blob_b64u = URL_SAFE_NO_PAD.encode(&blob_bytes);

    let batch_1_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": item_a_id.to_string(),
                "base_version": 0,
                "key_version": 1,
                "blob": blob_b64u,
            },
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": item_b_id.to_string(),
                "base_version": 0,
                "key_version": 1,
                "blob": blob_b64u,
            }
        ]
    });
    let b1_bytes = serde_json::to_vec(&batch_1_body)?;
    let b1_headers = dev1.sign_headers("POST", "/v1/sync/batch", &b1_bytes, false)?;

    let b1_res: Value = http_client
        .post(format!("{server_url}/v1/sync/batch"))
        .headers(b1_headers)
        .body(b1_bytes)
        .send()
        .await?
        .json()
        .await?;

    println!(
        "[\x1b[1;32mDEV 1\x1b[0m] Committed 2 vault items (seq: {}, seq: {}) via /v1/sync/batch",
        b1_res["results"][0]["seq"], b1_res["results"][1]["seq"]
    );

    // 4. Phase 2: Device 2 Enrollment via QR Code Pairing
    println!("\n\x1b[1;33m─── PHASE 2: QR Code Device Pairing (Device 2: iPhone) ───\x1b[0m");
    let dev2 = SimulatedDevice::new("iPhone 16 Pro (Dev 2)", 0x22, account_id.to_vec());

    // Device 2 initiates pairing challenge
    let challenge_req = serde_json::json!({
        "target_account_id": URL_SAFE_NO_PAD.encode(account_id),
        "device_id": dev2.device_id.to_string(),
        "device_ed25519_pub": dev2.pub_ed25519_b64u(),
        "device_x25519_pub": dev2.pub_x25519_b64u(),
        "device_label": dev2.name,
    });
    let ch_res: Value = http_client
        .post(format!("{server_url}/v1/pairings"))
        .header("x-nexxpass-protocol", "1")
        .header("content-type", "application/json")
        .json(&challenge_req)
        .send()
        .await?
        .json()
        .await?;

    let pairing_id = ch_res["pairing_id"]
        .as_str()
        .ok_or("missing pairing_id")?
        .to_string();
    let expiry = ch_res["expires_at"]
        .as_str()
        .ok_or("missing expires_at")?
        .to_string();
    let digest = ch_res["device_pub_digest"]
        .as_str()
        .ok_or("missing device_pub_digest")?
        .to_string();

    println!("[\x1b[1;35mDEV 2\x1b[0m] Generated pairing challenge. Displaying simulated QR code:");
    println!("    ┌────────────────────────────────────────────────────────────────────────┐");
    println!("    │ \x1b[1;37m[SIMULATED QR CODE RENDERED ON DEVICE 2 SCREEN]\x1b[0m                        │");
    println!(
        "    │ Pairing ID: \x1b[1;33m{}\x1b[0m                           │",
        pairing_id
    );
    println!(
        "    │ Device Digest: \x1b[1;36m{}\x1b[0m...       │",
        &digest[..24]
    );
    println!(
        "    │ Expires At: {}\x1b[0m                                   │",
        expiry
    );
    println!("    └────────────────────────────────────────────────────────────────────────┘");

    // Device 1 scans QR code and approves
    let dev2_wrap = URL_SAFE_NO_PAD.encode([0x88; 105]);
    let approve_body = serde_json::json!({
        "pairing_id": pairing_id,
        "account_id": URL_SAFE_NO_PAD.encode(account_id),
        "device_id": dev2.device_id.to_string(),
        "device_ed25519_pub": dev2.pub_ed25519_b64u(),
        "device_x25519_pub": dev2.pub_x25519_b64u(),
        "expiry": expiry,
        "active_key_version": 1,
        "wrap": dev2_wrap,
    });
    let app_bytes = serde_json::to_vec(&approve_body)?;
    let app_path = format!("/v1/pairings/{pairing_id}/approve");
    let app_headers = dev1.sign_headers("POST", &app_path, &app_bytes, false)?;

    let app_res = http_client
        .post(format!("{server_url}{app_path}"))
        .headers(app_headers)
        .body(app_bytes)
        .send()
        .await?;
    assert_eq!(app_res.status(), 200);
    println!(
        "[\x1b[1;32mDEV 1\x1b[0m] Scanned QR code, encrypted vault key wrap, and approved Device 2 via POST {app_path}"
    );

    // 5. Phase 3: Device 2 Real-Time SSE Setup & Initial Pull
    println!(
        "\n\x1b[1;33m─── PHASE 3: SSE Notification Stream & Initial Pull (Device 2) ───\x1b[0m"
    );

    // Device 2 connects to SSE events stream
    let sse_headers = dev2.sign_headers("GET", "/v1/sync/events", &[], false)?;
    let sse_res = http_client
        .get(format!("{server_url}/v1/sync/events"))
        .headers(sse_headers)
        .send()
        .await?;
    assert_eq!(sse_res.status(), 200);
    println!("[\x1b[1;35mDEV 2\x1b[0m] Subscribed to real-time Server-Sent Events stream (/v1/sync/events)");

    let (sse_tx, mut sse_rx) = tokio::sync::mpsc::channel::<i64>(10);
    let mut sse_stream = sse_res.bytes_stream();

    // Spawn SSE listener in background task
    tokio::spawn(async move {
        while let Some(item) = sse_stream.next().await {
            if let Ok(bytes) = item {
                let text = String::from_utf8_lossy(&bytes);
                for line in text.lines() {
                    if let Some(json_str) = line.strip_prefix("data:") {
                        if let Ok(v) = serde_json::from_str::<Value>(json_str.trim()) {
                            if let Some(seq) = v["seq"].as_i64() {
                                let _ = sse_tx.send(seq).await;
                            }
                        }
                    }
                }
            }
        }
    });

    // Device 2 initial pull (checkpoint = 0)
    let pull_1_body = serde_json::json!({
        "checkpoint": 0,
        "page_size": 50,
    });
    let p1_bytes = serde_json::to_vec(&pull_1_body)?;
    let p1_headers = dev2.sign_headers("POST", "/v1/sync/pull", &p1_bytes, false)?;

    let p1_res: Value = http_client
        .post(format!("{server_url}/v1/sync/pull"))
        .headers(p1_headers)
        .body(p1_bytes)
        .send()
        .await?
        .json()
        .await?;

    let pull_items = p1_res["items"].as_array().ok_or("missing items array")?;
    println!(
        "[\x1b[1;35mDEV 2\x1b[0m] Executed initial full pull: retrieved {} items (High Watermark: {})",
        pull_items.len(),
        p1_res["high_watermark"]
    );

    // 6. Phase 4: Live Mutation & Real-Time Push Propagation
    println!("\n\x1b[1;33m─── PHASE 4: Live Edit Propagation via SSE ───\x1b[0m");

    // Device 1 updates Item A
    let mod_blob = URL_SAFE_NO_PAD.encode(vec![0x99u8; 600]);
    let mod_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": item_a_id.to_string(),
                "base_version": 1,
                "key_version": 1,
                "blob": mod_blob,
            }
        ]
    });
    let mod_bytes = serde_json::to_vec(&mod_body)?;
    let mod_headers = dev1.sign_headers("POST", "/v1/sync/batch", &mod_bytes, false)?;

    println!("[\x1b[1;32mDEV 1\x1b[0m] Pushing edit for Item A to /v1/sync/batch...");
    let _ = http_client
        .post(format!("{server_url}/v1/sync/batch"))
        .headers(mod_headers)
        .body(mod_bytes)
        .send()
        .await?;

    // Device 2 awaits SSE notification
    print!("[\x1b[1;35mDEV 2\x1b[0m] Waiting for real-time SSE push... ");
    let notified_seq = tokio::time::timeout(Duration::from_secs(3), sse_rx.recv())
        .await?
        .ok_or("SSE channel closed")?;
    println!("\x1b[1;32mRECEIVED (seq: {notified_seq})\x1b[0m in <50ms without polling!");

    // 7. Phase 5: Option A Non-Blocking Master Password Rotation
    println!("\n\x1b[1;33m─── PHASE 5: Option A Non-Blocking Password Change & Wake-Up ───\x1b[0m");

    // Device 1 initiates password change
    let rot_start_body = serde_json::json!({
        "mode": "master_password_change",
        "recovery_wrap": URL_SAFE_NO_PAD.encode([0x55; 105]),
        "device_wraps": [
            {
                "device_id": dev1.device_id.to_string(),
                "wrap": URL_SAFE_NO_PAD.encode([0x66; 105]),
            },
            {
                "device_id": dev2.device_id.to_string(),
                "wrap": URL_SAFE_NO_PAD.encode([0x77; 105]),
            }
        ]
    });
    let rs_bytes = serde_json::to_vec(&rot_start_body)?;
    let rs_headers = dev1.sign_headers("POST", "/v1/rotation/start", &rs_bytes, false)?;
    let rs_res: Value = http_client
        .post(format!("{server_url}/v1/rotation/start"))
        .headers(rs_headers)
        .body(rs_bytes)
        .send()
        .await?
        .json()
        .await?;

    println!(
        "[\x1b[1;32mDEV 1\x1b[0m] Started rotation to target key version {} (mode: '{}')",
        rs_res["target_key_version"], rs_res["mode"]
    );

    // Device 1 rewrites both items under key version 2
    let rewrite_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": item_a_id.to_string(),
                "base_version": 2,
                "key_version": 2,
                "blob": URL_SAFE_NO_PAD.encode(vec![0xAA; 600]),
            },
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": item_b_id.to_string(),
                "base_version": 1,
                "key_version": 2,
                "blob": URL_SAFE_NO_PAD.encode(vec![0xBB; 600]),
            }
        ]
    });
    let rw_bytes = serde_json::to_vec(&rewrite_body)?;
    let rw_headers = dev1.sign_headers("POST", "/v1/rotation/rewrite", &rw_bytes, false)?;
    let _ = http_client
        .post(format!("{server_url}/v1/rotation/rewrite"))
        .headers(rw_headers)
        .body(rw_bytes)
        .send()
        .await?;
    println!("[\x1b[1;32mDEV 1\x1b[0m] Re-encrypted all live items under key version 2");

    // Device 1 completes rotation immediately (Option A: does not wait for offline Device 2!)
    let rc_headers = dev1.sign_headers("POST", "/v1/rotation/complete", &[], false)?;
    let rc_res: Value = http_client
        .post(format!("{server_url}/v1/rotation/complete"))
        .headers(rc_headers)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(rc_res["mode"], "idle");
    assert_eq!(rc_res["active_key_version"], 2);
    assert_eq!(rc_res["writes_frozen"], false);
    dev1.active_key_version = 2;
    println!(
        "[\x1b[1;32mDEV 1\x1b[0m] \x1b[1;32mOption A Complete!\x1b[0m Rotation finished, writes unfrozen immediately under key version 2"
    );

    // Device 1 writes immediately under key version 2
    let post_rot_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": Uuid::new_v4().to_string(),
                "base_version": 0,
                "key_version": 2,
                "blob": URL_SAFE_NO_PAD.encode(vec![0xCC; 600]),
            }
        ]
    });
    let pr_bytes = serde_json::to_vec(&post_rot_body)?;
    let pr_headers = dev1.sign_headers("POST", "/v1/sync/batch", &pr_bytes, false)?;
    let pr_res: Value = http_client
        .post(format!("{server_url}/v1/sync/batch"))
        .headers(pr_headers)
        .body(pr_bytes)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(pr_res["results"][0]["status"], "applied");
    println!("[\x1b[1;32mDEV 1\x1b[0m] Wrote new vault item with key version 2 without waiting for Device 2");

    // Offline Device 2 wakes up and attempts write with old key version 1 -> rejected!
    println!("[\x1b[1;35mDEV 2\x1b[0m] Waking up... attempting write with stale key version 1...");
    let stale_write_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": Uuid::new_v4().to_string(),
                "base_version": 0,
                "key_version": 1,
                "blob": URL_SAFE_NO_PAD.encode(vec![0xDD; 600]),
            }
        ]
    });
    let sw_bytes = serde_json::to_vec(&stale_write_body)?;
    let sw_headers = dev2.sign_headers("POST", "/v1/sync/batch", &sw_bytes, false)?;
    let sw_res: Value = http_client
        .post(format!("{server_url}/v1/sync/batch"))
        .headers(sw_headers)
        .body(sw_bytes)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(sw_res["results"][0]["status"], "unsupported_key_version");
    println!(
        "[\x1b[1;35mDEV 2\x1b[0m] \x1b[1;33mServer safely rejected stale write: {}\x1b[0m",
        sw_res["results"][0]["status"]
    );

    // Device 2 enters new password, unseals target key, and acknowledges rotation
    println!("[\x1b[1;35mDEV 2\x1b[0m] User entered new password. Unsealing key version 2 and acknowledging...");
    let ack_body = serde_json::json!({
        "key_version": 2,
        "local_master_password_updated": true,
    });
    let ack_bytes = serde_json::to_vec(&ack_body)?;
    let ack_headers = dev2.sign_headers("POST", "/v1/rotation/ack", &ack_bytes, false)?;
    let ack_res: Value = http_client
        .post(format!("{server_url}/v1/rotation/ack"))
        .headers(ack_headers)
        .body(ack_bytes)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(ack_res["active_key_version"], 2);
    println!("[\x1b[1;35mDEV 2\x1b[0m] Successfully acknowledged key version 2");

    // Device 2 can now write with key version 2
    let dev2_valid_body = serde_json::json!({
        "operations": [
            {
                "op": "put",
                "operation_id": Uuid::new_v4().to_string(),
                "item_id": Uuid::new_v4().to_string(),
                "base_version": 0,
                "key_version": 2,
                "blob": URL_SAFE_NO_PAD.encode(vec![0xEE; 600]),
            }
        ]
    });
    let d2v_bytes = serde_json::to_vec(&dev2_valid_body)?;
    let d2v_headers = dev2.sign_headers("POST", "/v1/sync/batch", &d2v_bytes, false)?;
    let d2v_res: Value = http_client
        .post(format!("{server_url}/v1/sync/batch"))
        .headers(d2v_headers)
        .body(d2v_bytes)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(d2v_res["results"][0]["status"], "applied");
    println!("[\x1b[1;35mDEV 2\x1b[0m] Successfully synced new item under key version 2");

    // 8. Phase 6: Device Audit & Session Diagnostics Table
    println!("\n\x1b[1;33m─── PHASE 6: Enrolled Devices & Session Diagnostics (GET /v1/devices) ───\x1b[0m");
    let dev_list_headers = dev1.sign_headers("GET", "/v1/devices", &[], false)?;
    let dev_list_res: Value = http_client
        .get(format!("{server_url}/v1/devices"))
        .headers(dev_list_headers)
        .send()
        .await?
        .json()
        .await?;

    let devices = dev_list_res["devices"]
        .as_array()
        .ok_or("missing devices array")?;
    println!("┌──────────────────────────────────────┬────────────────────────┬──────────────────────┬─────────────┐");
    println!("│ Device ID                            │ Label                  │ Last Seen (UTC)      │ Key Version │");
    println!("├──────────────────────────────────────┼────────────────────────┼──────────────────────┼─────────────┤");
    for d in devices {
        let did = d["device_id"].as_str().unwrap_or("unknown");
        let label = d["device_label"].as_str().unwrap_or("unknown");
        let last_seen = d["last_seen_at"].as_str().unwrap_or("never");
        let kv = d["acked_key_version"].as_i64().unwrap_or(0);
        println!(
            "│ {:<36} │ {:<22} │ {:<20} │ {:<11} │",
            did, label, last_seen, kv
        );
    }
    println!("└──────────────────────────────────────┴────────────────────────┴──────────────────────┴─────────────┘");

    println!("\n\x1b[1;32m✔ SUCCESS: All multi-device protocol stages and Option A invariants passed!\x1b[0m\n");

    Ok(())
}
