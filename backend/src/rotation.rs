use std::collections::HashSet;

use axum::{extract::State, Extension, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    account::{rotation_info, RotationInfo},
    auth::{decode_exact, AuthenticatedPrincipal, PrincipalKind},
    error::AppError,
    state::AppState,
    sync::{
        compute_operation_hash, parse_canonical_uuid, BatchResponse, MutationRequest,
        OperationResult, ParsedOp, ValidatedMutation, MAX_BLOB_BYTES, MIN_BLOB_BYTES,
    },
};

#[derive(Deserialize)]
pub struct DeviceWrapItem {
    pub device_id: String,
    pub wrap: String,
}

#[derive(Deserialize)]
pub struct RotationStartRequest {
    pub mode: String,
    pub recovery_wrap: String,
    pub device_wraps: Vec<DeviceWrapItem>,
}

#[derive(Deserialize)]
pub struct RotationAckRequest {
    pub key_version: i64,
    pub local_master_password_updated: Option<bool>,
}

#[derive(Deserialize)]
pub struct RotationRewriteRequest {
    pub operations: Vec<MutationRequest>,
}

/// POST /v1/rotation/start
pub async fn start_rotation(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<RotationStartRequest>,
) -> Result<Json<RotationInfo>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;

    if request.mode != "routine"
        && request.mode != "compromise"
        && request.mode != "master_password_change"
    {
        return Err(AppError::InvalidInput);
    }

    let recovery_wrap =
        decode_exact(&request.recovery_wrap, 105).map_err(|_| AppError::InvalidInput)?;

    if request.device_wraps.is_empty() {
        return Err(AppError::InvalidInput);
    }

    // Validate and collect unique device wraps.
    let mut parsed_wraps = Vec::with_capacity(request.device_wraps.len());
    let mut seen_devices = HashSet::with_capacity(request.device_wraps.len());
    for item in &request.device_wraps {
        let dev_id = Uuid::parse_str(&item.device_id).map_err(|_| AppError::InvalidInput)?;
        if dev_id.to_string() != item.device_id || !seen_devices.insert(dev_id) {
            return Err(AppError::InvalidInput);
        }
        let wrap_bytes = decode_exact(&item.wrap, 105).map_err(|_| AppError::InvalidInput)?;
        parsed_wraps.push((dev_id, wrap_bytes));
    }

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT status, active_key_version, next_key_version, keyring_version, rotation_mode \
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

    let current_rotation_mode: String = account_row.try_get("rotation_mode")?;
    if current_rotation_mode != "idle" {
        return Err(AppError::Conflict);
    }

    // Check caller device is active.
    let caller_dev_row = sqlx::query(
        "SELECT (revoked_at IS NOT NULL) AS is_revoked FROM devices \
         WHERE account_id = $1 AND device_id = $2",
    )
    .bind(&principal.account_id)
    .bind(caller_device_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(caller_dev_row) = caller_dev_row else {
        return Err(AppError::InvalidSignature);
    };
    let is_revoked: bool = caller_dev_row.try_get("is_revoked")?;
    if is_revoked {
        return Err(AppError::DeviceRevoked);
    }

    // Query all active devices on the account.
    let active_devices_rows =
        sqlx::query("SELECT device_id FROM devices WHERE account_id = $1 AND revoked_at IS NULL")
            .bind(&principal.account_id)
            .fetch_all(&mut *tx)
            .await?;

    let active_dev_set: HashSet<Uuid> = active_devices_rows
        .into_iter()
        .map(|r| r.try_get("device_id"))
        .collect::<Result<_, _>>()?;

    if active_dev_set != seen_devices {
        // Must contain exactly one pending wrap for every active device.
        return Err(AppError::Conflict);
    }

    let target_key_version: i64 = account_row.try_get("next_key_version")?;

    let deadline_interval = if request.mode == "compromise" {
        "interval '24 hours'"
    } else {
        "interval '7 days'"
    };

    let update_sql = format!(
        "UPDATE accounts SET \
             rotation_mode = $2, \
             rotation_target_key_version = $3, \
             next_key_version = next_key_version + 1, \
             keyring_version = keyring_version + 1, \
             rotation_owner_device_id = $4, \
             rotation_lease_expires_at = now() + interval '15 minutes', \
             rotation_deadline = now() + {deadline_interval}, \
             rotation_started_at = now() \
         WHERE account_id = $1"
    );

    sqlx::query(&update_sql)
        .bind(&principal.account_id)
        .bind(&request.mode)
        .bind(target_key_version)
        .bind(caller_device_id)
        .execute(&mut *tx)
        .await?;

    // Store pending recovery wrap.
    sqlx::query(
        "INSERT INTO key_wraps (account_id, key_version, recipient, wrap, status) \
         VALUES ($1, $2, 'recovery', $3, 'pending')",
    )
    .bind(&principal.account_id)
    .bind(target_key_version)
    .bind(&recovery_wrap)
    .execute(&mut *tx)
    .await?;

    // Store pending wraps for all active devices and insert into rotation_participants.
    for (dev_id, wrap_bytes) in &parsed_wraps {
        sqlx::query(
            "INSERT INTO key_wraps (account_id, key_version, recipient, wrap, status) \
             VALUES ($1, $2, $3, $4, 'pending')",
        )
        .bind(&principal.account_id)
        .bind(target_key_version)
        .bind(dev_id.to_string())
        .bind(wrap_bytes)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO rotation_participants (account_id, key_version, device_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(&principal.account_id)
        .bind(target_key_version)
        .bind(dev_id)
        .execute(&mut *tx)
        .await?;
    }

    let event_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
         VALUES ($1, $2, 'rotation_started', 'device', $3)",
    )
    .bind(&principal.account_id)
    .bind(event_id)
    .bind(caller_device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let info = rotation_info(&state.database, &principal.account_id).await?;
    Ok(Json(info))
}

/// POST /v1/rotation/heartbeat
pub async fn heartbeat_rotation(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<RotationInfo>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT rotation_mode, rotation_owner_device_id, \
                (rotation_lease_expires_at > now()) AS lease_active \
         FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let rotation_mode: String = account_row.try_get("rotation_mode")?;
    if rotation_mode == "idle" {
        return Err(AppError::Conflict);
    }

    let owner_device_id: Option<Uuid> = account_row.try_get("rotation_owner_device_id")?;
    let lease_active: Option<bool> = account_row.try_get("lease_active")?;

    if owner_device_id != Some(caller_device_id) || lease_active != Some(true) {
        return Err(AppError::Conflict);
    }

    sqlx::query(
        "UPDATE accounts SET rotation_lease_expires_at = now() + interval '15 minutes' \
         WHERE account_id = $1",
    )
    .bind(&principal.account_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let info = rotation_info(&state.database, &principal.account_id).await?;
    Ok(Json(info))
}

/// POST /v1/rotation/resume
pub async fn resume_rotation(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<RotationInfo>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT rotation_mode, rotation_owner_device_id, \
                (rotation_lease_expires_at > now()) AS lease_active \
         FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let rotation_mode: String = account_row.try_get("rotation_mode")?;
    if rotation_mode == "idle" {
        return Err(AppError::Conflict);
    }

    let owner_device_id: Option<Uuid> = account_row.try_get("rotation_owner_device_id")?;
    let lease_active: Option<bool> = account_row.try_get("lease_active")?;

    // Can claim ownership if: owner is None, or lease has expired, or caller is already owner.
    let can_claim = owner_device_id.is_none()
        || lease_active != Some(true)
        || owner_device_id == Some(caller_device_id);

    if !can_claim {
        return Err(AppError::Conflict);
    }

    sqlx::query(
        "UPDATE accounts SET rotation_owner_device_id = $2, \
                             rotation_lease_expires_at = now() + interval '15 minutes' \
         WHERE account_id = $1",
    )
    .bind(&principal.account_id)
    .bind(caller_device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let info = rotation_info(&state.database, &principal.account_id).await?;
    Ok(Json(info))
}

/// POST /v1/rotation/ack
pub async fn ack_rotation(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<RotationAckRequest>,
) -> Result<Json<RotationInfo>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT rotation_mode, rotation_target_key_version \
         FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let rotation_mode: String = account_row.try_get("rotation_mode")?;
    if rotation_mode == "idle" {
        return Err(AppError::Conflict);
    }

    let target_key_version: Option<i64> = account_row.try_get("rotation_target_key_version")?;
    if target_key_version != Some(request.key_version) {
        return Err(AppError::Conflict);
    }

    let is_mpc = rotation_mode == "master_password_change";
    if is_mpc && request.local_master_password_updated != Some(true) {
        return Err(AppError::InvalidInput);
    }

    // Monotonically update device's acked_key_version.
    sqlx::query(
        "UPDATE devices SET acked_key_version = GREATEST(COALESCE(acked_key_version, 0), $2) \
         WHERE account_id = $1 AND device_id = $3",
    )
    .bind(&principal.account_id)
    .bind(request.key_version)
    .bind(caller_device_id)
    .execute(&mut *tx)
    .await?;

    // Record acknowledgement in rotation_participants.
    sqlx::query(
        "UPDATE rotation_participants SET \
             key_acknowledged_at = COALESCE(key_acknowledged_at, now()), \
             local_master_password_updated_at = (CASE WHEN $4 = TRUE THEN COALESCE(local_master_password_updated_at, now()) ELSE local_master_password_updated_at END) \
         WHERE account_id = $1 AND key_version = $2 AND device_id = $3",
    )
    .bind(&principal.account_id)
    .bind(request.key_version)
    .bind(caller_device_id)
    .bind(is_mpc)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let info = rotation_info(&state.database, &principal.account_id).await?;
    Ok(Json(info))
}

/// POST /v1/rotation/complete
pub async fn complete_rotation(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<RotationInfo>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT rotation_mode, rotation_target_key_version \
         FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let rotation_mode: String = account_row.try_get("rotation_mode")?;
    if rotation_mode == "idle" {
        return Err(AppError::Conflict);
    }

    let target_key_version: i64 = account_row
        .try_get::<Option<i64>, _>("rotation_target_key_version")?
        .ok_or(AppError::Conflict)?;

    // Sweep check: live items under older key version must be 0.
    let old_items_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM items \
         WHERE account_id = $1 AND key_version < $2 AND deleted = FALSE",
    )
    .bind(&principal.account_id)
    .bind(target_key_version)
    .fetch_one(&mut *tx)
    .await?;

    if old_items_count > 0 {
        return Err(AppError::Conflict);
    }

    // Acknowledgement checks.
    if rotation_mode == "compromise" {
        let unacked_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM rotation_participants \
             WHERE account_id = $1 AND key_version = $2 AND revoked_at IS NULL AND key_acknowledged_at IS NULL",
        )
        .bind(&principal.account_id)
        .bind(target_key_version)
        .fetch_one(&mut *tx)
        .await?;

        if unacked_count > 0 {
            return Err(AppError::Conflict);
        }
    } else if rotation_mode == "master_password_change" {
        let unacked_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM rotation_participants \
             WHERE account_id = $1 AND key_version = $2 AND revoked_at IS NULL \
               AND (key_acknowledged_at IS NULL OR local_master_password_updated_at IS NULL)",
        )
        .bind(&principal.account_id)
        .bind(target_key_version)
        .fetch_one(&mut *tx)
        .await?;

        if unacked_count > 0 {
            return Err(AppError::Conflict);
        }
    }

    // Activate pending wraps, delete old wraps.
    sqlx::query("DELETE FROM key_wraps WHERE account_id = $1 AND key_version < $2")
        .bind(&principal.account_id)
        .bind(target_key_version)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "UPDATE key_wraps SET status = 'active' WHERE account_id = $1 AND key_version = $2",
    )
    .bind(&principal.account_id)
    .bind(target_key_version)
    .execute(&mut *tx)
    .await?;

    // Clear rotation state, set active key version, increment keyring_version.
    sqlx::query(
        "UPDATE accounts SET \
             active_key_version = $2, \
             keyring_version = keyring_version + 1, \
             rotation_mode = 'idle', \
             rotation_target_key_version = NULL, \
             rotation_owner_device_id = NULL, \
             rotation_lease_expires_at = NULL, \
             rotation_deadline = NULL, \
             rotation_started_at = NULL \
         WHERE account_id = $1",
    )
    .bind(&principal.account_id)
    .bind(target_key_version)
    .execute(&mut *tx)
    .await?;

    let event_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
         VALUES ($1, $2, 'rotation_completed', 'device', $3)",
    )
    .bind(&principal.account_id)
    .bind(event_id)
    .bind(caller_device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let info = rotation_info(&state.database, &principal.account_id).await?;
    Ok(Json(info))
}

/// POST /v1/rotation/abort
pub async fn abort_rotation(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<RotationInfo>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT rotation_mode, rotation_target_key_version \
         FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&principal.account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let rotation_mode: String = account_row.try_get("rotation_mode")?;
    // Routine rotations only can abort.
    if rotation_mode != "routine" {
        return Err(AppError::Conflict);
    }

    let target_key_version: i64 = account_row
        .try_get::<Option<i64>, _>("rotation_target_key_version")?
        .ok_or(AppError::Conflict)?;

    // Precondition 1: before any target-key item is written.
    let target_items_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM items WHERE account_id = $1 AND key_version = $2")
            .bind(&principal.account_id)
            .bind(target_key_version)
            .fetch_one(&mut *tx)
            .await?;

    let target_changes_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM item_changes WHERE account_id = $1 AND key_version = $2",
    )
    .bind(&principal.account_id)
    .bind(target_key_version)
    .fetch_one(&mut *tx)
    .await?;

    if target_items_count > 0 || target_changes_count > 0 {
        return Err(AppError::Conflict);
    }

    // Precondition 2: before any device has acknowledged the target key.
    let acked_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM rotation_participants \
         WHERE account_id = $1 AND key_version = $2 AND key_acknowledged_at IS NOT NULL",
    )
    .bind(&principal.account_id)
    .bind(target_key_version)
    .fetch_one(&mut *tx)
    .await?;

    if acked_count > 0 {
        return Err(AppError::Conflict);
    }

    // Remove pending wraps.
    sqlx::query("DELETE FROM key_wraps WHERE account_id = $1 AND key_version = $2")
        .bind(&principal.account_id)
        .bind(target_key_version)
        .execute(&mut *tx)
        .await?;

    // Remove participant entries.
    sqlx::query("DELETE FROM rotation_participants WHERE account_id = $1 AND key_version = $2")
        .bind(&principal.account_id)
        .bind(target_key_version)
        .execute(&mut *tx)
        .await?;

    // Clear rotation state on accounts (next_key_version is permanently retired).
    sqlx::query(
        "UPDATE accounts SET \
             rotation_mode = 'idle', \
             rotation_target_key_version = NULL, \
             rotation_owner_device_id = NULL, \
             rotation_lease_expires_at = NULL, \
             rotation_deadline = NULL, \
             rotation_started_at = NULL \
         WHERE account_id = $1",
    )
    .bind(&principal.account_id)
    .execute(&mut *tx)
    .await?;

    let event_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
         VALUES ($1, $2, 'rotation_aborted', 'device', $3)",
    )
    .bind(&principal.account_id)
    .bind(event_id)
    .bind(caller_device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let info = rotation_info(&state.database, &principal.account_id).await?;
    Ok(Json(info))
}

/// POST /v1/rotation/rewrite
pub async fn rewrite_rotation(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<RotationRewriteRequest>,
) -> Result<Json<BatchResponse>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;

    if request.operations.is_empty() || request.operations.len() > 100 {
        return Err(AppError::InvalidInput);
    }

    let account_id = principal.account_id.clone();

    // In-memory validation before starting transaction.
    let mut seen_op_ids = HashSet::with_capacity(request.operations.len());
    let mut seen_item_ids = HashSet::with_capacity(request.operations.len());
    let mut validated_mutations = Vec::with_capacity(request.operations.len());

    for op in &request.operations {
        let operation_uuid = parse_canonical_uuid(&op.operation_id)?;
        if !seen_op_ids.insert(operation_uuid) {
            return Err(AppError::InvalidInput);
        }

        let item_uuid = parse_canonical_uuid(&op.item_id)?;
        if !seen_item_ids.insert(item_uuid) {
            return Err(AppError::InvalidInput);
        }

        if op.op != "put" {
            return Err(AppError::InvalidInput);
        }

        let Some(kv) = op.key_version else {
            return Err(AppError::InvalidInput);
        };
        if kv == 0 || kv > u32::MAX as u64 {
            return Err(AppError::InvalidInput);
        }
        let key_version_u32 = kv as u32;

        let Some(blob_str) = &op.blob else {
            return Err(AppError::InvalidInput);
        };
        let decoded = URL_SAFE_NO_PAD
            .decode(blob_str)
            .map_err(|_| AppError::InvalidInput)?;
        if URL_SAFE_NO_PAD.encode(&decoded) != *blob_str {
            return Err(AppError::InvalidInput);
        }
        if decoded.len() < MIN_BLOB_BYTES || decoded.len() > MAX_BLOB_BYTES {
            return Err(AppError::InvalidInput);
        }

        let mut blob_hasher = Sha256::new();
        blob_hasher.update(&decoded);
        let payload_digest: [u8; 32] = blob_hasher.finalize().into();

        let op_hash = compute_operation_hash(
            &account_id,
            0x01,
            &item_uuid,
            op.base_version,
            key_version_u32,
            &payload_digest,
        );

        validated_mutations.push(ValidatedMutation {
            operation_id: operation_uuid,
            item_id: item_uuid,
            base_version: op.base_version,
            op: ParsedOp::Put {
                key_version: key_version_u32,
                payload_digest,
                decoded_blob: decoded,
            },
            op_hash,
        });
    }

    let mut tx = state.database.begin().await?;

    let account_row = sqlx::query(
        "SELECT rotation_mode, rotation_target_key_version, rotation_owner_device_id, \
                (rotation_lease_expires_at > now()) AS lease_active, seq_counter \
         FROM accounts WHERE account_id = $1 FOR UPDATE",
    )
    .bind(&account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let rotation_mode: String = account_row.try_get("rotation_mode")?;
    if rotation_mode != "master_password_change" {
        return Err(AppError::Conflict);
    }

    let owner_device_id: Option<Uuid> = account_row.try_get("rotation_owner_device_id")?;
    let lease_active: Option<bool> = account_row.try_get("lease_active")?;
    if owner_device_id != Some(caller_device_id) || lease_active != Some(true) {
        return Err(AppError::Conflict);
    }

    let target_key_version: i64 = account_row
        .try_get::<Option<i64>, _>("rotation_target_key_version")?
        .ok_or(AppError::Conflict)?;

    // All ops must be at target key version.
    for m in &validated_mutations {
        if let ParsedOp::Put { key_version, .. } = m.op {
            if key_version as i64 != target_key_version {
                return Err(AppError::InvalidInput);
            }
        }
    }

    let mut seq_counter: i64 = account_row.try_get("seq_counter")?;
    let initial_seq_counter = seq_counter;

    let mut current_ciphertext_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(octet_length(blob)), 0)::bigint \
         FROM items WHERE account_id = $1 AND deleted = FALSE",
    )
    .bind(&account_id)
    .fetch_one(&mut *tx)
    .await?;

    let mut results = Vec::with_capacity(validated_mutations.len());

    for mutation in validated_mutations {
        let existing_op = sqlx::query(
            "SELECT op_hash, status, item_version, seq \
             FROM operations WHERE account_id = $1 AND operation_id = $2",
        )
        .bind(&account_id)
        .bind(mutation.operation_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(existing_row) = existing_op {
            let existing_hash: Vec<u8> = existing_row.try_get("op_hash")?;
            if existing_hash != mutation.op_hash {
                return Err(AppError::OperationIdReused);
            }
            let item_version: Option<i64> = existing_row.try_get("item_version")?;
            let seq: Option<i64> = existing_row.try_get("seq")?;
            results.push(OperationResult {
                operation_id: mutation.operation_id.to_string(),
                status: "duplicate".to_string(),
                version: item_version.map(|v| v as u64),
                seq: seq.map(|s| s as u64),
            });
            continue;
        }

        let retired =
            sqlx::query("SELECT 1 FROM retired_item_ids WHERE account_id = $1 AND item_id = $2")
                .bind(&account_id)
                .bind(mutation.item_id)
                .fetch_optional(&mut *tx)
                .await?;

        if retired.is_some() {
            results.push(OperationResult {
                operation_id: mutation.operation_id.to_string(),
                status: "item_deleted".to_string(),
                version: None,
                seq: None,
            });
            continue;
        }

        let current_item = sqlx::query(
            "SELECT version, seq, deleted, octet_length(blob) AS blob_len \
             FROM items WHERE account_id = $1 AND item_id = $2",
        )
        .bind(&account_id)
        .bind(mutation.item_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let ParsedOp::Put {
            key_version,
            decoded_blob,
            ..
        } = mutation.op
        {
            let old_blob_len: i64 = match &current_item {
                Some(row) => {
                    let is_del: bool = row.try_get("deleted")?;
                    if is_del {
                        0
                    } else {
                        row.try_get::<Option<i32>, _>("blob_len")?.unwrap_or(0) as i64
                    }
                }
                None => 0,
            };
            let new_blob_len = decoded_blob.len() as i64;
            let net_diff = new_blob_len - old_blob_len;
            if current_ciphertext_bytes + net_diff > 100 * 1024 * 1024 {
                return Err(AppError::QuotaExceeded);
            }
            current_ciphertext_bytes += net_diff;

            let next_version = if let Some(item_row) = current_item {
                let is_deleted: bool = item_row.try_get("deleted")?;
                if is_deleted {
                    results.push(OperationResult {
                        operation_id: mutation.operation_id.to_string(),
                        status: "item_deleted".to_string(),
                        version: None,
                        seq: None,
                    });
                    continue;
                }
                let current_version: i64 = item_row.try_get("version")?;
                if current_version as u64 != mutation.base_version {
                    results.push(OperationResult {
                        operation_id: mutation.operation_id.to_string(),
                        status: "base_version_conflict".to_string(),
                        version: None,
                        seq: None,
                    });
                    continue;
                }
                (current_version + 1) as u64
            } else {
                if mutation.base_version > 0 {
                    results.push(OperationResult {
                        operation_id: mutation.operation_id.to_string(),
                        status: "item_gone".to_string(),
                        version: None,
                        seq: None,
                    });
                    continue;
                }
                1u64
            };

            seq_counter += 1;

            sqlx::query(
                "INSERT INTO items (account_id, item_id, blob, key_version, version, seq, deleted, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, FALSE, now()) \
                 ON CONFLICT (account_id, item_id) DO UPDATE SET \
                     blob = EXCLUDED.blob, \
                     key_version = EXCLUDED.key_version, \
                     version = EXCLUDED.version, \
                     seq = EXCLUDED.seq, \
                     deleted = FALSE, \
                     updated_at = now()",
            )
            .bind(&account_id)
            .bind(mutation.item_id)
            .bind(&decoded_blob)
            .bind(key_version as i64)
            .bind(next_version as i64)
            .bind(seq_counter)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO item_changes (account_id, seq, item_id, version, key_version, blob, deleted, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, FALSE, now())",
            )
            .bind(&account_id)
            .bind(seq_counter)
            .bind(mutation.item_id)
            .bind(next_version as i64)
            .bind(key_version as i64)
            .bind(&decoded_blob)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO operations (account_id, operation_id, op_hash, status, item_version, seq, created_at) \
                 VALUES ($1, $2, $3, 'applied', $4, $5, now())",
            )
            .bind(&account_id)
            .bind(mutation.operation_id)
            .bind(mutation.op_hash)
            .bind(next_version as i64)
            .bind(seq_counter)
            .execute(&mut *tx)
            .await?;

            results.push(OperationResult {
                operation_id: mutation.operation_id.to_string(),
                status: "applied".to_string(),
                version: Some(next_version),
                seq: Some(seq_counter as u64),
            });
        }
    }

    if seq_counter > initial_seq_counter {
        sqlx::query("UPDATE accounts SET seq_counter = $2 WHERE account_id = $1")
            .bind(&account_id)
            .bind(seq_counter)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    Ok(Json(BatchResponse { results }))
}
