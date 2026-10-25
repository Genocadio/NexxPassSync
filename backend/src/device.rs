use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Extension, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::{decode_exact, hex_lower, AuthenticatedPrincipal, PrincipalKind},
    error::AppError,
    state::AppState,
};

#[derive(Serialize)]
pub struct WrapDto {
    pub key_version: i64,
    pub recipient: String,
    pub status: String,
    pub wrap: String,
}

#[derive(Serialize)]
pub struct RecoveryWrapsResponse {
    pub wraps: Vec<WrapDto>,
}

#[derive(Deserialize)]
pub struct RecoveryDeviceRegistration {
    pub device_id: String,
    pub device_ed25519_pub: String,
    pub device_x25519_pub: String,
    pub device_label: String,
    pub wrap: String,
    pub target_wrap: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceRegistrationResult {
    pub device_id: String,
    pub active_key_version: i64,
}

#[derive(Serialize)]
pub struct DevicePublic {
    pub device_id: String,
    pub device_label: String,
    pub device_ed25519_pub: String,
    pub device_x25519_pub: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_sync_at: Option<String>,
    pub last_seen_seq: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acked_key_version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DevicePublic>,
}

#[derive(Serialize)]
pub struct AccountStatusResult {
    pub account_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_requested_at: Option<String>,
}

#[derive(Deserialize)]
pub struct MigrationRecoveryWrap {
    pub key_version: i64,
    pub wrap: String,
}

#[derive(Deserialize)]
pub struct IdentityMigration {
    pub identity_ed25519_pub: String,
    pub identity_x25519_pub: String,
    pub derivation_version: i16,
    pub recovery_wraps: Vec<MigrationRecoveryWrap>,
}

/// GET /v1/accounts/recovery
pub async fn get_recovery_wraps(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<RecoveryWrapsResponse>, AppError> {
    if principal.kind != PrincipalKind::Identity {
        return Err(AppError::InvalidSignature);
    }

    state.rate_limiter.check_rate_limit(
        &format!("recovery:{}", URL_SAFE_NO_PAD.encode(&principal.account_id)),
        10,
        std::time::Duration::from_secs(60),
    )?;

    let status_row = sqlx::query("SELECT status FROM accounts WHERE account_id = $1")
        .bind(&principal.account_id)
        .fetch_optional(&state.database)
        .await?;
    let Some(status_row) = status_row else {
        return Err(AppError::InvalidSignature);
    };
    let status: String = status_row.try_get("status")?;
    if status == "deletion_pending" {
        return Err(AppError::AccountDeletionPending);
    }
    if status == "suspended" {
        return Err(AppError::AccountSuspended);
    }

    let rows = sqlx::query(
        "SELECT key_version, recipient, status, wrap FROM key_wraps \
         WHERE account_id = $1 AND recipient = 'recovery' \
         ORDER BY key_version ASC",
    )
    .bind(&principal.account_id)
    .fetch_all(&state.database)
    .await?;

    let mut wraps = Vec::with_capacity(rows.len());
    for row in rows {
        let wrap_bytes: Vec<u8> = row.try_get("wrap")?;
        wraps.push(WrapDto {
            key_version: row.try_get("key_version")?,
            recipient: row.try_get("recipient")?,
            status: row.try_get("status")?,
            wrap: URL_SAFE_NO_PAD.encode(wrap_bytes),
        });
    }

    // Coalesce recovery_wraps_read event within 10 minutes.
    let recent_event = sqlx::query(
        "SELECT 1 FROM account_events \
         WHERE account_id = $1 AND event_type = 'recovery_wraps_read' \
           AND created_at > now() - interval '10 minutes'",
    )
    .bind(&principal.account_id)
    .fetch_optional(&state.database)
    .await?;

    if recent_event.is_none() {
        let event_id = Uuid::now_v7();
        let _ = sqlx::query(
            "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
             VALUES ($1, $2, 'recovery_wraps_read', 'identity', NULL)",
        )
        .bind(&principal.account_id)
        .bind(event_id)
        .execute(&state.database)
        .await;
    }

    Ok(Json(RecoveryWrapsResponse { wraps }))
}

/// POST /v1/devices
pub async fn register_device_recovery(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<RecoveryDeviceRegistration>,
) -> Result<(StatusCode, Json<DeviceRegistrationResult>), AppError> {
    if principal.kind != PrincipalKind::Identity {
        return Err(AppError::InvalidSignature);
    }

    state.rate_limiter.check_rate_limit(
        &format!("recovery:{}", URL_SAFE_NO_PAD.encode(&principal.account_id)),
        10,
        std::time::Duration::from_secs(60),
    )?;

    let device_id = Uuid::parse_str(&request.device_id).map_err(|_| AppError::MalformedRequest)?;
    if device_id.to_string() != request.device_id {
        return Err(AppError::MalformedRequest);
    }
    let device_ed25519_pub =
        decode_exact(&request.device_ed25519_pub, 32).map_err(|_| AppError::MalformedRequest)?;
    let device_x25519_pub =
        decode_exact(&request.device_x25519_pub, 32).map_err(|_| AppError::MalformedRequest)?;
    if request.device_label.is_empty() || request.device_label.chars().count() > 100 {
        return Err(AppError::InvalidInput);
    }
    let wrap = decode_exact(&request.wrap, 105).map_err(|_| AppError::InvalidInput)?;
    let target_wrap = if let Some(tw) = &request.target_wrap {
        Some(decode_exact(tw, 105).map_err(|_| AppError::InvalidInput)?)
    } else {
        None
    };

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT status, active_key_version, rotation_mode, rotation_target_key_version \
         FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let status: String = account_row.try_get("status")?;
    if status == "deletion_pending" {
        return Err(AppError::AccountDeletionPending);
    }
    if status == "suspended" {
        return Err(AppError::AccountSuspended);
    }
    if status == "identity_locked" {
        return Err(AppError::IdentityLocked);
    }

    // Check device doesn't already exist on this account.
    let existing_device =
        sqlx::query("SELECT 1 FROM devices WHERE account_id = $1 AND device_id = $2")
            .bind(&principal.account_id)
            .bind(device_id)
            .fetch_optional(&mut *tx)
            .await?;
    if existing_device.is_some() {
        return Err(AppError::Conflict);
    }

    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM devices WHERE account_id = $1 AND revoked_at IS NULL",
    )
    .bind(&principal.account_id)
    .fetch_one(&mut *tx)
    .await?;
    if active_count >= 10 {
        return Err(AppError::QuotaExceeded);
    }

    let active_key_version: i64 = account_row.try_get("active_key_version")?;
    let rotation_mode: String = account_row.try_get("rotation_mode")?;
    let rotation_target_key_version: Option<i64> =
        account_row.try_get("rotation_target_key_version")?;

    let is_rotating = rotation_mode != "idle";
    if is_rotating && target_wrap.is_none() {
        return Err(AppError::InvalidInput);
    }
    if !is_rotating && target_wrap.is_some() {
        return Err(AppError::InvalidInput);
    }

    sqlx::query(
        "INSERT INTO devices (account_id, device_id, device_ed25519_pub, device_x25519_pub, \
                             device_label, created_at, last_seen_at) \
         VALUES ($1, $2, $3, $4, $5, now(), now())",
    )
    .bind(&principal.account_id)
    .bind(device_id)
    .bind(&device_ed25519_pub)
    .bind(&device_x25519_pub)
    .bind(&request.device_label)
    .execute(&mut *tx)
    .await?;

    let device_id_str = device_id.to_string();
    sqlx::query(
        "INSERT INTO key_wraps (account_id, key_version, recipient, wrap, status) \
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(&principal.account_id)
    .bind(active_key_version)
    .bind(&device_id_str)
    .bind(&wrap)
    .execute(&mut *tx)
    .await?;

    if let (true, Some(target_version), Some(tw)) =
        (is_rotating, rotation_target_key_version, target_wrap)
    {
        sqlx::query(
            "INSERT INTO key_wraps (account_id, key_version, recipient, wrap, status) \
             VALUES ($1, $2, $3, $4, 'pending')",
        )
        .bind(&principal.account_id)
        .bind(target_version)
        .bind(&device_id_str)
        .bind(&tw)
        .execute(&mut *tx)
        .await?;

        if rotation_mode == "compromise" {
            sqlx::query(
                "INSERT INTO rotation_participants (account_id, key_version, device_id, key_acknowledged_at) \
                 VALUES ($1, $2, $3, now())",
            )
            .bind(&principal.account_id)
            .bind(target_version)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "UPDATE devices SET acked_key_version = $2 WHERE account_id = $1 AND device_id = $3",
            )
            .bind(&principal.account_id)
            .bind(target_version)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO rotation_participants (account_id, key_version, device_id) \
                 VALUES ($1, $2, $3)",
            )
            .bind(&principal.account_id)
            .bind(target_version)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        }
    }

    let event_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
         VALUES ($1, $2, 'device_registered_via_recovery', 'identity', NULL)",
    )
    .bind(&principal.account_id)
    .bind(event_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(DeviceRegistrationResult {
            device_id: device_id.to_string(),
            active_key_version,
        }),
    ))
}

/// GET /v1/devices
pub async fn list_devices(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<DeviceListResponse>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }

    let rows = sqlx::query(
        "SELECT device_id, device_label, device_ed25519_pub, device_x25519_pub, \
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at, \
                to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS last_seen_at, \
                to_char(first_sync_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS first_sync_at, \
                last_seen_seq, acked_key_version, \
                to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS revoked_at \
         FROM devices WHERE account_id = $1 ORDER BY created_at ASC",
    )
    .bind(&principal.account_id)
    .fetch_all(&state.database)
    .await?;

    let mut devices = Vec::with_capacity(rows.len());
    for row in rows {
        let dev_id: Uuid = row.try_get("device_id")?;
        let ed_pub: Vec<u8> = row.try_get("device_ed25519_pub")?;
        let x_pub: Vec<u8> = row.try_get("device_x25519_pub")?;
        devices.push(DevicePublic {
            device_id: dev_id.to_string(),
            device_label: row.try_get("device_label")?,
            device_ed25519_pub: URL_SAFE_NO_PAD.encode(ed_pub),
            device_x25519_pub: URL_SAFE_NO_PAD.encode(x_pub),
            created_at: row.try_get("created_at")?,
            last_seen_at: row.try_get("last_seen_at")?,
            first_sync_at: row.try_get("first_sync_at")?,
            last_seen_seq: row.try_get("last_seen_seq")?,
            acked_key_version: row.try_get("acked_key_version")?,
            revoked_at: row.try_get("revoked_at")?,
        });
    }

    Ok(Json(DeviceListResponse { devices }))
}

/// DELETE /v1/devices/{device_id}
pub async fn revoke_device(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(target_device_id_str): Path<String>,
) -> Result<Json<DeviceRegistrationResult>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;
    let target_device_id =
        Uuid::parse_str(&target_device_id_str).map_err(|_| AppError::MalformedRequest)?;
    if target_device_id.to_string() != target_device_id_str {
        return Err(AppError::MalformedRequest);
    }

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT status, active_key_version FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let status: String = account_row.try_get("status")?;
    if status == "deletion_pending" {
        return Err(AppError::AccountDeletionPending);
    }
    if status == "suspended" {
        return Err(AppError::AccountSuspended);
    }
    let active_key_version: i64 = account_row.try_get("active_key_version")?;

    let dev_row = sqlx::query(
        "SELECT (revoked_at IS NOT NULL) AS is_revoked FROM devices \
         WHERE account_id = $1 AND device_id = $2 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .bind(target_device_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(dev_row) = dev_row else {
        return Err(AppError::NotFound);
    };

    let is_revoked: bool = dev_row.try_get("is_revoked")?;
    if !is_revoked {
        sqlx::query(
            "UPDATE devices SET revoked_at = now(), revoked_reason = 'user_revocation' \
             WHERE account_id = $1 AND device_id = $2",
        )
        .bind(&principal.account_id)
        .bind(target_device_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM key_wraps WHERE account_id = $1 AND recipient = $2")
            .bind(&principal.account_id)
            .bind(target_device_id.to_string())
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "UPDATE rotation_participants SET revoked_at = now() \
             WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
        .bind(&principal.account_id)
        .bind(target_device_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE accounts SET rotation_owner_device_id = NULL, rotation_lease_expires_at = NULL \
             WHERE account_id = $1 AND rotation_owner_device_id = $2",
        )
        .bind(&principal.account_id)
        .bind(target_device_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM sync_sessions WHERE account_id = $1 AND device_id = $2")
            .bind(&principal.account_id)
            .bind(target_device_id)
            .execute(&mut *tx)
            .await?;

        let event_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
             VALUES ($1, $2, 'device_revoked', 'device', $3)",
        )
        .bind(&principal.account_id)
        .bind(event_id)
        .bind(caller_device_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(Json(DeviceRegistrationResult {
        device_id: target_device_id.to_string(),
        active_key_version,
    }))
}

/// POST /v1/accounts/lock
pub async fn lock_account(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<AccountStatusResult>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query("SELECT status FROM accounts WHERE account_id = $1 FOR UPDATE")
        .bind(&principal.account_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let current_status: String = account_row.try_get("status")?;
    if current_status == "deletion_pending" {
        return Err(AppError::AccountDeletionPending);
    }
    if current_status == "suspended" {
        return Err(AppError::AccountSuspended);
    }

    if current_status != "identity_locked" {
        sqlx::query("UPDATE accounts SET status = 'identity_locked' WHERE account_id = $1")
            .bind(&principal.account_id)
            .execute(&mut *tx)
            .await?;

        let event_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
             VALUES ($1, $2, 'identity_locked', 'device', $3)",
        )
        .bind(&principal.account_id)
        .bind(event_id)
        .bind(caller_device_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(Json(AccountStatusResult {
        account_id: URL_SAFE_NO_PAD.encode(&principal.account_id),
        status: "identity_locked".to_string(),
        deletion_requested_at: None,
    }))
}

/// POST /v1/accounts/migrate
pub async fn migrate_identity(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<AccountStatusResult>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;

    let request: IdentityMigration =
        serde_json::from_slice(&body).map_err(|_| AppError::MalformedRequest)?;

    let identity_ed25519_pub =
        decode_exact(&request.identity_ed25519_pub, 32).map_err(|_| AppError::MalformedRequest)?;
    let identity_x25519_pub =
        decode_exact(&request.identity_x25519_pub, 32).map_err(|_| AppError::MalformedRequest)?;
    if request.derivation_version <= 0 {
        return Err(AppError::InvalidInput);
    }
    if request.recovery_wraps.len() != 1 {
        return Err(AppError::InvalidInput);
    }
    let recovery_wrap = &request.recovery_wraps[0];
    let wrap_bytes = decode_exact(&recovery_wrap.wrap, 105).map_err(|_| AppError::InvalidInput)?;

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT status, active_key_version, rotation_mode, identity_ed25519_pub \
         FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let status: String = account_row.try_get("status")?;
    if status == "deletion_pending" {
        return Err(AppError::AccountDeletionPending);
    }
    if status == "suspended" {
        return Err(AppError::AccountSuspended);
    }
    let rotation_mode: String = account_row.try_get("rotation_mode")?;
    if rotation_mode != "idle" {
        return Err(AppError::RotationInProgress);
    }

    let active_key_version: i64 = account_row.try_get("active_key_version")?;
    if recovery_wrap.key_version != active_key_version {
        return Err(AppError::InvalidInput);
    }

    // Verify optional countersignature if present.
    if let Some(countersign_header) = headers.get("x-nexxpass-countersign") {
        let countersign_str = countersign_header
            .to_str()
            .map_err(|_| AppError::MalformedRequest)?;
        let countersign_sig_bytes =
            decode_exact(countersign_str, 64).map_err(|_| AppError::MalformedRequest)?;
        let signature = Signature::from_slice(&countersign_sig_bytes)
            .map_err(|_| AppError::MalformedRequest)?;

        let old_identity_pub: Vec<u8> = account_row.try_get("identity_ed25519_pub")?;
        let old_pub_key: [u8; 32] = old_identity_pub
            .try_into()
            .map_err(|_| AppError::InvalidSignature)?;
        let old_verifying_key =
            VerifyingKey::from_bytes(&old_pub_key).map_err(|_| AppError::InvalidSignature)?;

        let body_hash_hex = hex_lower(&Sha256::digest(&body));
        let mut preimage = Vec::with_capacity(9 + 32 + 64);
        preimage.extend_from_slice(b"NPSIdMig1");
        preimage.extend_from_slice(&principal.account_id);
        preimage.extend_from_slice(body_hash_hex.as_bytes());

        old_verifying_key
            .verify_strict(&preimage, &signature)
            .map_err(|_| AppError::InvalidSignature)?;
    }

    // Replace stored identity keys, derivation version, set status active.
    sqlx::query(
        "UPDATE accounts \
         SET identity_ed25519_pub = $2, identity_x25519_pub = $3, derivation_version = $4, \
             status = 'active' \
         WHERE account_id = $1",
    )
    .bind(&principal.account_id)
    .bind(&identity_ed25519_pub)
    .bind(&identity_x25519_pub)
    .bind(request.derivation_version)
    .execute(&mut *tx)
    .await?;

    // Delete old recovery wraps.
    sqlx::query("DELETE FROM key_wraps WHERE account_id = $1 AND recipient = 'recovery'")
        .bind(&principal.account_id)
        .execute(&mut *tx)
        .await?;

    // Insert new recovery wrap.
    sqlx::query(
        "INSERT INTO key_wraps (account_id, key_version, recipient, wrap, status) \
         VALUES ($1, $2, 'recovery', $3, 'active')",
    )
    .bind(&principal.account_id)
    .bind(active_key_version)
    .bind(&wrap_bytes)
    .execute(&mut *tx)
    .await?;

    let event_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
         VALUES ($1, $2, 'identity_migrated', 'device', $3)",
    )
    .bind(&principal.account_id)
    .bind(event_id)
    .bind(caller_device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(AccountStatusResult {
        account_id: URL_SAFE_NO_PAD.encode(&principal.account_id),
        status: "active".to_string(),
        deletion_requested_at: None,
    }))
}

/// DELETE /v1/accounts
pub async fn delete_account(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<AccountStatusResult>, AppError> {
    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT status, \
                to_char(deletion_requested_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS deletion_requested_at \
         FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let status: String = account_row.try_get("status")?;
    if status == "suspended" {
        return Err(AppError::AccountSuspended);
    }

    if principal.kind == PrincipalKind::Device && status != "identity_locked" {
        return Err(AppError::InvalidSignature);
    }

    if status == "deletion_pending" {
        let deletion_requested_at: Option<String> = account_row.try_get("deletion_requested_at")?;
        return Ok(Json(AccountStatusResult {
            account_id: URL_SAFE_NO_PAD.encode(&principal.account_id),
            status: "deletion_pending".to_string(),
            deletion_requested_at,
        }));
    }

    let updated_row = sqlx::query(
        "UPDATE accounts \
         SET status = 'deletion_pending', deletion_requested_at = now() \
         WHERE account_id = $1 \
         RETURNING to_char(deletion_requested_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS deletion_requested_at",
    )
    .bind(&principal.account_id)
    .fetch_one(&mut *tx)
    .await?;

    let deletion_requested_at: Option<String> = updated_row.try_get("deletion_requested_at")?;

    let event_id = Uuid::now_v7();
    let (actor, actor_device_id) = match principal.kind {
        PrincipalKind::Device => ("device", principal.device_id),
        PrincipalKind::Identity => ("identity", None),
    };

    sqlx::query(
        "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
         VALUES ($1, $2, 'deletion_requested', $3, $4)",
    )
    .bind(&principal.account_id)
    .bind(event_id)
    .bind(actor)
    .bind(actor_device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(AccountStatusResult {
        account_id: URL_SAFE_NO_PAD.encode(&principal.account_id),
        status: "deletion_pending".to_string(),
        deletion_requested_at,
    }))
}

/// POST /v1/accounts/deletion/cancel
pub async fn cancel_deletion(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<AccountStatusResult>, AppError> {
    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query("SELECT status FROM accounts WHERE account_id = $1 FOR UPDATE")
        .bind(&principal.account_id)
        .fetch_optional(&mut *tx)
        .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let status: String = account_row.try_get("status")?;
    if status != "deletion_pending" {
        return Err(AppError::Conflict);
    }

    sqlx::query(
        "UPDATE accounts \
         SET status = 'active', deletion_requested_at = NULL \
         WHERE account_id = $1",
    )
    .bind(&principal.account_id)
    .execute(&mut *tx)
    .await?;

    let event_id = Uuid::now_v7();
    let (actor, actor_device_id) = match principal.kind {
        PrincipalKind::Device => ("device", principal.device_id),
        PrincipalKind::Identity => ("identity", None),
    };

    sqlx::query(
        "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
         VALUES ($1, $2, 'deletion_cancelled', $3, $4)",
    )
    .bind(&principal.account_id)
    .bind(event_id)
    .bind(actor)
    .bind(actor_device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(AccountStatusResult {
        account_id: URL_SAFE_NO_PAD.encode(&principal.account_id),
        status: "active".to_string(),
        deletion_requested_at: None,
    }))
}
