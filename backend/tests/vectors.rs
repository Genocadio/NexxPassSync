#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::VerifyingKey;
use nexxpass_sync_server::sync::compute_operation_hash;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn load_fixture() -> Value {
    let raw = include_str!("fixtures/protocol-v1.json");
    serde_json::from_str(raw).expect("valid fixture json")
}

#[test]
fn test_operation_hash_put_vector() {
    let fixture = load_fixture();
    let account_id = hex_to_bytes(fixture["account"]["id_hex"].as_str().unwrap());
    let item_id = Uuid::parse_str(fixture["inputs"]["item_id"].as_str().unwrap()).unwrap();
    let blob_bytes = hex_to_bytes(fixture["item_blob"]["envelope_hex"].as_str().unwrap());

    let mut hasher = Sha256::new();
    hasher.update(&blob_bytes);
    let payload_digest: [u8; 32] = hasher.finalize().into();

    let computed = compute_operation_hash(
        &account_id,
        0x01,
        &item_id,
        0, // base_version 0 for create
        1, // key_version 1
        &payload_digest,
    );

    let expected_hex = fixture["operation_hash_put"]["hash_hex"].as_str().unwrap();
    assert_eq!(
        computed
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        expected_hex
    );
}

#[test]
fn test_operation_hash_delete_vector() {
    let fixture = load_fixture();
    let account_id = hex_to_bytes(fixture["account"]["id_hex"].as_str().unwrap());
    let item_id = Uuid::parse_str(fixture["inputs"]["item_id"].as_str().unwrap()).unwrap();
    let zero_digest = [0u8; 32];

    let computed = compute_operation_hash(
        &account_id,
        0x02,
        &item_id,
        1, // base_version 1
        0, // key_version 0 for delete
        &zero_digest,
    );

    let expected_hex = fixture["operation_hash_delete"]["hash_hex"]
        .as_str()
        .unwrap();
    assert_eq!(
        computed
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        expected_hex
    );
}

#[test]
fn test_device_pub_digest_vector() {
    let fixture = load_fixture();
    let device_id = Uuid::parse_str(fixture["inputs"]["device_id"].as_str().unwrap()).unwrap();
    let ed25519_pub = hex_to_bytes(fixture["device"]["ed25519_pub_hex"].as_str().unwrap());
    let x25519_pub = hex_to_bytes(fixture["device"]["x25519_pub_hex"].as_str().unwrap());

    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    hasher.update(&ed25519_pub);
    hasher.update(&x25519_pub);
    let computed: [u8; 32] = hasher.finalize().into();

    let expected_hex = fixture["device"]["pub_digest_hex"].as_str().unwrap();
    assert_eq!(
        computed
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        expected_hex
    );
}

#[test]
fn test_signature_verification_vector() {
    let fixture = load_fixture();
    let sig_obj = &fixture["signature"];
    let body = sig_obj["body"].as_str().unwrap().as_bytes();
    let ed25519_pub = hex_to_bytes(fixture["device"]["ed25519_pub_hex"].as_str().unwrap());
    // Note: for test, timestamp in fixture is 1760000000 (future timestamp relative to test execution),
    // but we can verify canonical string and ed25519 signature directly:
    let canonical = sig_obj["canonical_string"].as_str().unwrap();
    let sig_bytes = hex_to_bytes(sig_obj["signature_hex"].as_str().unwrap());
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    let key: [u8; 32] = ed25519_pub.as_slice().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&key).unwrap();

    // Verify Dalek verifies signature over exact canonical string bytes
    assert!(vk.verify_strict(canonical.as_bytes(), &sig).is_ok());

    // Verify SHA256 of body matches body_sha256_hex
    let mut body_hasher = Sha256::new();
    body_hasher.update(body);
    let body_digest = body_hasher.finalize();
    assert_eq!(
        body_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        sig_obj["body_sha256_hex"].as_str().unwrap()
    );
}

#[test]
fn test_page_receipt_vector() {
    let fixture = load_fixture();
    let account_id = hex_to_bytes(fixture["account"]["id_hex"].as_str().unwrap());
    let device_id = Uuid::parse_str(fixture["inputs"]["device_id"].as_str().unwrap()).unwrap();
    let session_id = Uuid::parse_str(fixture["inputs"]["session_id"].as_str().unwrap()).unwrap();
    let token_key_bytes = hex_to_bytes(fixture["inputs"]["token_hmac_key_hex"].as_str().unwrap());
    let token_key: [u8; 32] = token_key_bytes.as_slice().try_into().unwrap();

    let receipt_obj = &fixture["page_receipt"];
    let page_number = receipt_obj["page_number"].as_u64().unwrap() as u32;
    let terminal_seq = receipt_obj["terminal_seq"].as_u64().unwrap();
    let expected_b64u = receipt_obj["bytes_b64u"].as_str().unwrap();

    let encoded = nexxpass_sync_server::pull::encode_page_receipt(
        &token_key,
        &account_id,
        &device_id,
        &nexxpass_sync_server::pull::PageReceiptData {
            rv: 1,
            session_id,
            page_number,
            terminal_seq,
        },
    )
    .unwrap();

    assert_eq!(encoded, expected_b64u);

    // Verify decoding
    let decoded = nexxpass_sync_server::pull::decode_page_receipt(
        &token_key,
        &account_id,
        &device_id,
        &encoded,
    )
    .unwrap();

    assert_eq!(decoded.rv, 1);
    assert_eq!(decoded.session_id, session_id);
    assert_eq!(decoded.page_number, page_number);
    assert_eq!(decoded.terminal_seq, terminal_seq);
}
