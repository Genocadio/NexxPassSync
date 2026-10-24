use axum::{
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, Method},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use unicode_normalization::is_nfc;
use uuid::Uuid;

use crate::{
    auth::{consume_nonce, verify_raw_signature},
    error::AppError,
    state::AppState,
};

const MAX_BODY_BYTES: usize = 128 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    account_id: String,
    identity_ed25519_pub: String,
    identity_x25519_pub: String,
    derivation_version: u16,
    recovery_wrap: String,
    device: DeviceRegistration,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRegistration {
    device_id: String,
    device_ed25519_pub: String,
    device_x25519_pub: String,
    device_label: String,
    wrap: String,
}

#[derive(Serialize)]
pub struct RegistrationResponse {
    account_id: String,
    device_id: String,
    active_key_version: u32,
}

struct ValidatedRegistration {
    account_id: Vec<u8>,
    identity_ed25519_pub: Vec<u8>,
    identity_x25519_pub: Vec<u8>,
    derivation_version: i16,
    recovery_wrap: Vec<u8>,
    device_id: Uuid,
    device_ed25519_pub: Vec<u8>,
    device_x25519_pub: Vec<u8>,
    device_label: String,
    device_wrap: Vec<u8>,
}

pub async fn register_account(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(axum::http::StatusCode, Json<RegistrationResponse>), AppError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(AppError::RequestTooLarge);
    }
    if method != Method::POST || uri.path() != "/v1/accounts" {
        return Err(AppError::MalformedRequest);
    }
    if uri.query().is_some() {
        return Err(AppError::MalformedRequest);
    }
    let request: RegistrationRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::MalformedRequest)?;
    let validated = validate_registration(request)?;
    if headers.contains_key("x-nexxpass-account")
        || headers.contains_key("x-nexxpass-key")
        || headers.contains_key("x-nexxpass-device")
        || headers.contains_key("x-nexxpass-countersign")
    {
        return Err(AppError::MalformedRequest);
    }
    let nonce = verify_raw_signature(
        &headers,
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or_default(),
        &body,
        &validated.identity_ed25519_pub,
    )?;
    consume_nonce(&state, &validated.identity_ed25519_pub, &nonce).await?;

    let mut tx = state.database.begin().await?;
    let retired: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM deleted_accounts WHERE account_id = $1)")
            .bind(&validated.account_id)
            .fetch_one(&mut *tx)
            .await?;
    if retired {
        return Err(AppError::AccountIdRetired);
    }

    let registration = insert_registration(&mut tx, &validated).await?;
    tx.commit().await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(RegistrationResponse {
            account_id: registration.0,
            device_id: registration.1,
            active_key_version: 1,
        }),
    ))
}

fn validate_registration(request: RegistrationRequest) -> Result<ValidatedRegistration, AppError> {
    if request.derivation_version != 1 {
        return Err(AppError::InvalidInput);
    }
    if request.device.device_label.is_empty()
        || request.device.device_label.chars().count() > 100
        || request.device.device_label.contains('\0')
        || !is_nfc(&request.device.device_label)
    {
        return Err(AppError::InvalidInput);
    }
    let device_id =
        Uuid::parse_str(&request.device.device_id).map_err(|_| AppError::InvalidInput)?;
    if device_id.to_string() != request.device.device_id {
        return Err(AppError::InvalidInput);
    }

    let account_id = decode_exact(&request.account_id, 32)?;
    let identity_ed25519_pub = decode_exact(&request.identity_ed25519_pub, 32)?;
    let identity_x25519_pub = decode_exact(&request.identity_x25519_pub, 32)?;
    let recovery_wrap = decode_exact(&request.recovery_wrap, 105)?;
    let device_ed25519_pub = decode_exact(&request.device.device_ed25519_pub, 32)?;
    let device_x25519_pub = decode_exact(&request.device.device_x25519_pub, 32)?;
    let device_wrap = decode_exact(&request.device.wrap, 105)?;
    validate_ed25519_public_key(&identity_ed25519_pub)?;
    validate_ed25519_public_key(&device_ed25519_pub)?;

    Ok(ValidatedRegistration {
        account_id,
        identity_ed25519_pub,
        identity_x25519_pub,
        derivation_version: request.derivation_version as i16,
        recovery_wrap,
        device_id,
        device_ed25519_pub,
        device_x25519_pub,
        device_label: request.device.device_label,
        device_wrap,
    })
}

async fn insert_registration(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account: &ValidatedRegistration,
) -> Result<(String, String), AppError> {
    let insert_account = sqlx::query(
        "INSERT INTO accounts \
         (account_id, identity_ed25519_pub, identity_x25519_pub, derivation_version, \
          active_key_version, next_key_version, keyring_version, status) \
         VALUES ($1, $2, $3, $4, 1, 2, 1, 'active')",
    )
    .bind(&account.account_id)
    .bind(&account.identity_ed25519_pub)
    .bind(&account.identity_x25519_pub)
    .bind(account.derivation_version)
    .execute(&mut **tx)
    .await;
    if let Err(error) = insert_account {
        if error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .as_deref()
            == Some("23505")
        {
            return Err(AppError::Conflict);
        }
        return Err(error.into());
    }

    sqlx::query(
        "INSERT INTO devices \
         (account_id, device_id, device_ed25519_pub, device_x25519_pub, device_label, \
          first_sync_at, last_seen_seq, issued_through) \
         VALUES ($1, $2, $3, $4, $5, now(), 0, 0)",
    )
    .bind(&account.account_id)
    .bind(account.device_id)
    .bind(&account.device_ed25519_pub)
    .bind(&account.device_x25519_pub)
    .bind(&account.device_label)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO key_wraps (account_id, key_version, recipient, wrap, status) \
         VALUES ($1, 1, 'recovery', $2, 'active'), ($1, 1, $3, $4, 'active')",
    )
    .bind(&account.account_id)
    .bind(&account.recovery_wrap)
    .bind(account.device_id.to_string())
    .bind(&account.device_wrap)
    .execute(&mut **tx)
    .await?;

    Ok((
        URL_SAFE_NO_PAD.encode(&account.account_id),
        account.device_id.to_string(),
    ))
}

fn decode_exact(value: &str, expected: usize) -> Result<Vec<u8>, AppError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::InvalidInput)?;
    if decoded.len() != expected || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(AppError::InvalidInput);
    }
    Ok(decoded)
}

fn validate_ed25519_public_key(bytes: &[u8]) -> Result<(), AppError> {
    let key: [u8; 32] = bytes.try_into().map_err(|_| AppError::InvalidInput)?;
    VerifyingKey::from_bytes(&key).map_err(|_| AppError::InvalidInput)?;
    Ok(())
}
