use axum::{
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    Extension, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use unicode_normalization::is_nfc;
use uuid::Uuid;

use crate::{
    auth::{lock_active_device_for_mutation, AuthenticatedPrincipal},
    error::AppError,
    state::AppState,
};

const MAX_PENDING_PER_ACCOUNT: i64 = 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub target_account_id: String,
    pub device_id: String,
    pub device_ed25519_pub: String,
    pub device_x25519_pub: String,
    pub device_label: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub pairing_id: String,
    pub expires_at: String,
    pub device_pub_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub pairing_id: String,
    pub account_id: String,
    pub device_id: String,
    pub device_ed25519_pub: String,
    pub device_x25519_pub: String,
    pub expiry: String,
    pub active_key_version: i64,
    pub wrap: String,
    pub target_key_version: Option<i64>,
    pub target_wrap: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceRegistrationResponse {
    pub device_id: String,
    pub active_key_version: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_key_version: Option<i64>,
}

struct ValidatedApproval {
    pairing_id: Uuid,
    account_id: Vec<u8>,
    device_id: Uuid,
    ed25519_pub: Vec<u8>,
    x25519_pub: Vec<u8>,
    expiry: String,
    active_key_version: i64,
    active_wrap: Vec<u8>,
    target_key_version: Option<i64>,
    target_wrap: Option<Vec<u8>>,
}

pub async fn create_pairing_challenge(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Json(request): Json<ChallengeRequest>,
) -> Result<(StatusCode, Json<ChallengeResponse>), AppError> {
    if uri.path() != "/v1/pairings" || uri.query().is_some() {
        return Err(AppError::MalformedRequest);
    }
    require_protocol_v1(&headers)?;
    let target_account_id = decode_exact(&request.target_account_id, 32)?;
    let device_id = parse_canonical_uuid(&request.device_id)?;
    let ed25519_pub = decode_exact(&request.device_ed25519_pub, 32)?;
    let x25519_pub = decode_exact(&request.device_x25519_pub, 32)?;
    validate_ed25519_public_key(&ed25519_pub)?;
    if request.device_label.is_empty()
        || request.device_label.chars().count() > 100
        || request.device_label.contains('\0')
        || !is_nfc(&request.device_label)
    {
        return Err(AppError::InvalidInput);
    }

    // The proposed device identity is committed into the challenge; the account
    // row is deliberately not queried here, preventing account enumeration.
    let device_pub_digest = device_digest(device_id, &ed25519_pub, &x25519_pub);
    let pairing_id = Uuid::new_v4();
    let mut tx = state.database.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
        .bind(&target_account_id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM pairing_challenges WHERE expires_at <= now()")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO pairing_challenges \
         (pairing_id, target_account_id, device_id, device_pub_digest, device_label, expires_at) \
         VALUES ($1, $2, $3, $4, $5, now() + interval '5 minutes')",
    )
    .bind(pairing_id)
    .bind(&target_account_id)
    .bind(device_id)
    .bind(device_pub_digest)
    .bind(&request.device_label)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM pairing_challenges WHERE pairing_id IN ( \
             SELECT pairing_id FROM pairing_challenges \
             WHERE target_account_id = $1 AND status = 'pending' \
             ORDER BY created_at DESC, pairing_id DESC OFFSET $2)",
    )
    .bind(&target_account_id)
    .bind(MAX_PENDING_PER_ACCOUNT)
    .execute(&mut *tx)
    .await?;
    let expires_at: String = sqlx::query_scalar(
        "SELECT to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
         FROM pairing_challenges WHERE pairing_id = $1",
    )
    .bind(pairing_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(ChallengeResponse {
            pairing_id: pairing_id.to_string(),
            expires_at,
            device_pub_digest: hex_lower(&device_pub_digest),
        }),
    ))
}

#[axum::debug_handler]
pub async fn approve_pairing(
    State(state): State<AppState>,
    Path(pairing_id): Path<Uuid>,
    OriginalUri(uri): OriginalUri,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<ApprovalRequest>,
) -> Result<Json<DeviceRegistrationResponse>, AppError> {
    if uri.query().is_some() || request.pairing_id != pairing_id.to_string() {
        return Err(AppError::MalformedRequest);
    }
    let approval = validate_approval(request)?;
    if approval.pairing_id != pairing_id || approval.account_id != principal.account_id {
        return Err(AppError::PairingChallengeInvalid);
    }

    let mut tx = state.database.begin().await?;
    lock_active_device_for_mutation(&mut tx, &principal).await?;
    let challenge = sqlx::query(
        "SELECT target_account_id, device_id, device_pub_digest, device_label, status, \
                expires_at <= now() AS expired, \
                to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS expiry \
         FROM pairing_challenges WHERE pairing_id = $1 FOR UPDATE",
    )
    .bind(pairing_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::PairingChallengeInvalid)?;
    let challenge_account: Vec<u8> = challenge.try_get("target_account_id")?;
    let challenge_device_id: Uuid = challenge.try_get("device_id")?;
    let expected_digest: Vec<u8> = challenge.try_get("device_pub_digest")?;
    let device_label: String = challenge.try_get("device_label")?;
    let challenge_status: String = challenge.try_get("status")?;
    let expired: bool = challenge.try_get("expired")?;
    let challenge_expiry: String = challenge.try_get("expiry")?;
    if challenge_status != "pending"
        || expired
        || challenge_account != approval.account_id
        || challenge_device_id != approval.device_id
        || challenge_expiry != approval.expiry
        || expected_digest
            != device_digest(
                approval.device_id,
                &approval.ed25519_pub,
                &approval.x25519_pub,
            )
    {
        return Err(AppError::PairingChallengeInvalid);
    }

    let account = sqlx::query(
        "SELECT active_key_version, rotation_mode, rotation_target_key_version \
         FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&approval.account_id)
    .fetch_one(&mut *tx)
    .await?;
    let active_key_version: i64 = account.try_get("active_key_version")?;
    let rotation_mode: String = account.try_get("rotation_mode")?;
    let target_key_version: Option<i64> = account.try_get("rotation_target_key_version")?;
    if active_key_version != approval.active_key_version {
        return Err(AppError::PairingChallengeInvalid);
    }
    let target_key_version = match rotation_mode.as_str() {
        "idle" if approval.target_key_version.is_none() && approval.target_wrap.is_none() => None,
        "master_password_change"
            if approval.target_key_version == target_key_version
                && approval.target_wrap.is_some() =>
        {
            target_key_version
        }
        "routine" | "compromise" => return Err(AppError::RotationInProgress),
        _ => return Err(AppError::PairingChallengeInvalid),
    };

    let device_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE account_id = $1 AND device_id = $2)",
    )
    .bind(&approval.account_id)
    .bind(approval.device_id)
    .fetch_one(&mut *tx)
    .await?;
    if device_exists {
        return Err(AppError::PairingChallengeInvalid);
    }

    let insert_device = sqlx::query(
        "INSERT INTO devices \
         (account_id, device_id, device_ed25519_pub, device_x25519_pub, device_label, \
          last_seen_seq, issued_through) VALUES ($1, $2, $3, $4, $5, 0, 0)",
    )
    .bind(&approval.account_id)
    .bind(approval.device_id)
    .bind(&approval.ed25519_pub)
    .bind(&approval.x25519_pub)
    .bind(&device_label)
    .execute(&mut *tx)
    .await;
    if let Err(error) = insert_device {
        if error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .as_deref()
            == Some("23505")
        {
            return Err(AppError::PairingChallengeInvalid);
        }
        return Err(error.into());
    }

    insert_wrap(
        &mut tx,
        &approval.account_id,
        active_key_version,
        approval.device_id,
        &approval.active_wrap,
        "active",
    )
    .await?;
    if let Some(target_version) = target_key_version {
        let wrap = approval
            .target_wrap
            .as_deref()
            .ok_or(AppError::PairingChallengeInvalid)?;
        insert_wrap(
            &mut tx,
            &approval.account_id,
            target_version,
            approval.device_id,
            wrap,
            "pending",
        )
        .await?;
        sqlx::query(
            "INSERT INTO rotation_participants (account_id, key_version, device_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(&approval.account_id)
        .bind(target_version)
        .bind(approval.device_id)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query("UPDATE accounts SET keyring_version = keyring_version + 1 WHERE account_id = $1")
        .bind(&approval.account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE pairing_challenges SET status = 'consumed', consumed_at = now() \
         WHERE pairing_id = $1 AND status = 'pending'",
    )
    .bind(pairing_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO account_events \
         (account_id, event_id, event_type, actor, actor_device_id) \
         VALUES ($1, $2, 'device_paired', 'device', $3)",
    )
    .bind(&approval.account_id)
    .bind(Uuid::now_v7())
    .bind(principal.device_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(DeviceRegistrationResponse {
        device_id: approval.device_id.to_string(),
        active_key_version,
        target_key_version,
    }))
}

async fn insert_wrap(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &[u8],
    key_version: i64,
    device_id: Uuid,
    wrap: &[u8],
    status: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO key_wraps (account_id, key_version, recipient, wrap, status) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(account_id)
    .bind(key_version)
    .bind(device_id.to_string())
    .bind(wrap)
    .bind(status)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn validate_approval(request: ApprovalRequest) -> Result<ValidatedApproval, AppError> {
    let pairing_id = parse_canonical_uuid(&request.pairing_id)?;
    let account_id = decode_exact(&request.account_id, 32)?;
    let device_id = parse_canonical_uuid(&request.device_id)?;
    let ed25519_pub = decode_exact(&request.device_ed25519_pub, 32)?;
    let x25519_pub = decode_exact(&request.device_x25519_pub, 32)?;
    validate_ed25519_public_key(&ed25519_pub)?;
    if request.active_key_version < 1 || request.active_key_version > u32::MAX as i64 {
        return Err(AppError::InvalidInput);
    }
    let active_wrap = decode_exact(&request.wrap, 105)?;
    let target_wrap = request
        .target_wrap
        .as_deref()
        .map(|wrap| decode_exact(wrap, 105))
        .transpose()?;
    if request.target_key_version.is_some() != target_wrap.is_some() {
        return Err(AppError::InvalidInput);
    }
    Ok(ValidatedApproval {
        pairing_id,
        account_id,
        device_id,
        ed25519_pub,
        x25519_pub,
        expiry: request.expiry,
        active_key_version: request.active_key_version,
        active_wrap,
        target_key_version: request.target_key_version,
        target_wrap,
    })
}

fn require_protocol_v1(headers: &HeaderMap) -> Result<(), AppError> {
    let mut values = headers.get_all("x-nexxpass-protocol").iter();
    let value = values
        .next()
        .and_then(|header| header.to_str().ok())
        .ok_or(AppError::UnsupportedProtocolVersion)?;
    if values.next().is_some() || value != "1" {
        return Err(AppError::UnsupportedProtocolVersion);
    }
    Ok(())
}

fn parse_canonical_uuid(value: &str) -> Result<Uuid, AppError> {
    let uuid = Uuid::parse_str(value).map_err(|_| AppError::InvalidInput)?;
    if uuid.to_string() != value || uuid.get_version_num() != 4 {
        return Err(AppError::InvalidInput);
    }
    Ok(uuid)
}

fn decode_exact(value: &str, expected_len: usize) -> Result<Vec<u8>, AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::InvalidInput)?;
    if bytes.len() != expected_len || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(AppError::InvalidInput);
    }
    Ok(bytes)
}

fn validate_ed25519_public_key(bytes: &[u8]) -> Result<(), AppError> {
    let key: [u8; 32] = bytes.try_into().map_err(|_| AppError::InvalidInput)?;
    VerifyingKey::from_bytes(&key).map_err(|_| AppError::InvalidInput)?;
    Ok(())
}

fn device_digest(device_id: Uuid, ed25519_pub: &[u8], x25519_pub: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(device_id.as_bytes());
    digest.update(ed25519_pub);
    digest.update(x25519_pub);
    digest.finalize().into()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{decode_exact, device_digest, parse_canonical_uuid};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use uuid::Uuid;

    #[test]
    fn uuid_parser_accepts_canonical_v4_only() {
        let uuid = Uuid::new_v4();
        assert!(parse_canonical_uuid(&uuid.to_string()).is_ok_and(|parsed| parsed == uuid));

        let non_v4 = Uuid::now_v7();
        assert!(parse_canonical_uuid(&non_v4.to_string()).is_err());
        assert!(parse_canonical_uuid(&uuid.to_string().to_uppercase()).is_err());
    }

    #[test]
    fn base64url_decoder_requires_exact_length_and_canonical_encoding() {
        let encoded = URL_SAFE_NO_PAD.encode([0x5a; 32]);
        assert!(decode_exact(&encoded, 32).is_ok_and(|bytes| bytes == vec![0x5a; 32]));
        assert!(decode_exact(&encoded, 31).is_err());
        assert!(decode_exact(&format!("{encoded}="), 32).is_err());
    }

    #[test]
    fn device_digest_binds_id_and_both_public_keys() {
        let device_id = Uuid::new_v4();
        let ed25519 = [0x11; 32];
        let x25519 = [0x22; 32];
        let digest = device_digest(device_id, &ed25519, &x25519);

        assert_eq!(digest, device_digest(device_id, &ed25519, &x25519));
        assert_ne!(digest, device_digest(Uuid::new_v4(), &ed25519, &x25519));
        assert_ne!(digest, device_digest(device_id, &[0x12; 32], &x25519));
        assert_ne!(digest, device_digest(device_id, &ed25519, &[0x23; 32]));
    }
}
