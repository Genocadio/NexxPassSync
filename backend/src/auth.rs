use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::{to_bytes, Body},
    extract::OriginalUri,
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

const BODY_LIMIT: usize = 1024 * 1024;
const NONCE_TTL_HOURS: i64 = 48;
const TIMESTAMP_WINDOW_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    Device,
    Identity,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedPrincipal {
    pub account_id: Vec<u8>,
    pub kind: PrincipalKind,
    pub device_id: Option<Uuid>,
}

pub async fn authenticate_device(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let (mut parts, body) = request.into_parts();
    let body = to_bytes(body, BODY_LIMIT)
        .await
        .map_err(|_| AppError::RequestTooLarge)?;
    let headers = parts.headers.clone();
    let original_uri = parts
        .extensions
        .get::<OriginalUri>()
        .map(|uri| uri.0.clone())
        .unwrap_or_else(|| parts.uri.clone());
    let query = original_uri.query().unwrap_or_default();
    if original_uri.query().is_some() || !canonical_path(original_uri.path()) {
        return Err(AppError::MalformedRequest);
    }
    if headers.contains_key("x-nexxpass-countersign")
        && original_uri.path() != "/v1/accounts/migrate"
    {
        return Err(AppError::MalformedRequest);
    }

    let protocol = unique_header(&headers, "x-nexxpass-protocol")?;
    if protocol != Some("1") {
        return Err(AppError::UnsupportedProtocolVersion);
    }
    let account_text = required_header(&headers, "x-nexxpass-account")?;
    let account_id = decode_exact(account_text, 32).map_err(|_| AppError::MalformedRequest)?;
    let key_kind = required_header(&headers, "x-nexxpass-key")?;
    let (principal_kind, device_id, principal_id, public_key, account_status, revoked) =
        match key_kind {
            "device" => {
                let device_text = required_header(&headers, "x-nexxpass-device")?;
                let device_id =
                    Uuid::parse_str(device_text).map_err(|_| AppError::MalformedRequest)?;
                if device_id.to_string() != device_text {
                    return Err(AppError::MalformedRequest);
                }
                let row = sqlx::query(
                    "SELECT a.status, d.device_ed25519_pub, (d.revoked_at IS NOT NULL) AS is_revoked \
                     FROM accounts a JOIN devices d ON d.account_id = a.account_id \
                     WHERE a.account_id = $1 AND d.device_id = $2",
                )
                .bind(&account_id)
                .bind(device_id)
                .fetch_optional(&state.database)
                .await?;
                let Some(row) = row else {
                    return Err(AppError::InvalidSignature);
                };
                let public_key: Vec<u8> = row.try_get("device_ed25519_pub")?;
                let status: String = row.try_get("status")?;
                let revoked: bool = row.try_get("is_revoked")?;
                let mut principal_id = account_id.clone();
                principal_id.extend_from_slice(device_id.as_bytes());
                (
                    PrincipalKind::Device,
                    Some(device_id),
                    principal_id,
                    public_key,
                    status,
                    revoked,
                )
            }
            "identity" => {
                if headers.contains_key("x-nexxpass-device") {
                    return Err(AppError::MalformedRequest);
                }
                let row = sqlx::query(
                    "SELECT status, identity_ed25519_pub FROM accounts WHERE account_id = $1",
                )
                .bind(&account_id)
                .fetch_optional(&state.database)
                .await?;
                let Some(row) = row else {
                    return Err(AppError::InvalidSignature);
                };
                let public_key: Vec<u8> = row.try_get("identity_ed25519_pub")?;
                let status: String = row.try_get("status")?;
                let mut principal_id = account_id.clone();
                principal_id.extend_from_slice(b"identity");
                (
                    PrincipalKind::Identity,
                    None,
                    principal_id,
                    public_key,
                    status,
                    false,
                )
            }
            _ => return Err(AppError::MalformedRequest),
        };

    let nonce = verify_raw_signature(
        &headers,
        parts.method.as_str(),
        original_uri.path(),
        query,
        &body,
        &public_key,
    )?;
    consume_nonce(&state, &principal_id, &nonce).await?;

    if account_status == "suspended" {
        return Err(AppError::AccountSuspended);
    }
    if principal_kind == PrincipalKind::Identity && account_status == "identity_locked" {
        return Err(AppError::IdentityLocked);
    }
    if revoked {
        return Err(AppError::DeviceRevoked);
    }

    let principal = AuthenticatedPrincipal {
        account_id,
        kind: principal_kind,
        device_id,
    };
    parts.extensions.insert(principal);
    let request = Request::from_parts(parts, Body::from(body));
    Ok(next.run(request).await)
}

pub fn verify_raw_signature(
    headers: &HeaderMap,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, AppError> {
    let protocol = unique_header(headers, "x-nexxpass-protocol")?;
    if protocol != Some("1") {
        return Err(AppError::UnsupportedProtocolVersion);
    }
    if !method.is_ascii() || method.bytes().any(|byte| byte.is_ascii_lowercase()) {
        return Err(AppError::MalformedRequest);
    }
    if !canonical_path(path) || !query.is_empty() {
        return Err(AppError::MalformedRequest);
    }
    let timestamp = required_header(headers, "x-nexxpass-timestamp")?;
    let timestamp_num = timestamp
        .parse::<u64>()
        .map_err(|_| AppError::MalformedRequest)?;
    if timestamp_num.to_string() != timestamp {
        return Err(AppError::MalformedRequest);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Unavailable)?
        .as_secs();
    if now.abs_diff(timestamp_num) > TIMESTAMP_WINDOW_SECONDS {
        return Err(AppError::TimestampOutOfRange);
    }
    let nonce_text = required_header(headers, "x-nexxpass-nonce")?;
    let nonce = decode_exact(nonce_text, 16).map_err(|_| AppError::MalformedRequest)?;
    let signature = decode_exact(required_header(headers, "x-nexxpass-signature")?, 64)
        .map_err(|_| AppError::MalformedRequest)?;
    let signature = Signature::from_slice(&signature).map_err(|_| AppError::MalformedRequest)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| AppError::InvalidSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| AppError::InvalidSignature)?;

    let body_digest = Sha256::digest(body);
    let canonical = format!(
        "NPSSv1\n{method}\n{path}\n{query}\n{timestamp}\n{nonce_text}\n{}",
        hex_lower(&body_digest)
    );
    verifying_key
        .verify_strict(canonical.as_bytes(), &signature)
        .map_err(|_| AppError::InvalidSignature)?;
    Ok(nonce)
}

pub async fn consume_nonce(
    state: &AppState,
    principal_id: &[u8],
    nonce: &[u8],
) -> Result<(), AppError> {
    if nonce.len() != 16 {
        return Err(AppError::MalformedRequest);
    }
    sqlx::query("DELETE FROM request_nonces WHERE expires_at <= now()")
        .execute(&state.database)
        .await?;
    let inserted = sqlx::query(
        "INSERT INTO request_nonces (principal_id, nonce, expires_at) \
         VALUES ($1, $2, now() + ($3 * interval '1 hour')) ON CONFLICT DO NOTHING",
    )
    .bind(principal_id)
    .bind(nonce)
    .bind(NONCE_TTL_HOURS)
    .execute(&state.database)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(AppError::ReplayDetected);
    }
    Ok(())
}

/// Re-checks device authorization while holding locks in the global order:
/// account first, then device. Call inside every account mutation transaction.
pub async fn lock_active_device_for_mutation(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal: &AuthenticatedPrincipal,
) -> Result<(), AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;
    let account_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM accounts WHERE account_id = $1 FOR UPDATE")
            .bind(&principal.account_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(account_status) = account_status else {
        return Err(AppError::InvalidSignature);
    };
    if account_status == "suspended" {
        return Err(AppError::AccountSuspended);
    }
    if account_status == "deletion_pending" {
        return Err(AppError::AccountDeletionPending);
    }

    let revoked: Option<bool> = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM devices \
         WHERE account_id = $1 AND device_id = $2 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await?;
    match revoked {
        Some(false) => Ok(()),
        Some(true) => Err(AppError::DeviceRevoked),
        None => Err(AppError::InvalidSignature),
    }
}

fn required_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, AppError> {
    unique_header(headers, name)?.ok_or(AppError::MalformedRequest)
}

fn unique_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, AppError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AppError::MalformedRequest);
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| AppError::MalformedRequest)
}

pub(crate) fn decode_exact(value: &str, expected: usize) -> Result<Vec<u8>, AppError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::MalformedRequest)?;
    if decoded.len() != expected || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(AppError::MalformedRequest);
    }
    Ok(decoded)
}

fn canonical_path(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') || path.ends_with('/') || path.contains("//") {
        return false;
    }
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return false;
                }
                let (Some(high), Some(low)) =
                    (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
                else {
                    return false;
                };
                let decoded = (high << 4) | low;
                if is_unreserved(decoded) {
                    return false;
                }
                index += 3;
            }
            byte if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) => index += 1,
            _ => return false,
        }
    }
    !path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
