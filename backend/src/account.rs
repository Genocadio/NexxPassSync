use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, Extension, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use sqlx::{PgPool, Row};

use crate::{
    auth::{
        compute_offline_lease_token, AuthenticatedPrincipal, PrincipalKind, OFFLINE_LEASE_SECONDS,
    },
    error::AppError,
    state::AppState,
};

#[derive(Serialize)]
pub struct AccountMeResponse {
    account_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion_requested_at: Option<String>,
    identity_ed25519_pub: String,
    identity_x25519_pub: String,
    derivation_version: i16,
    active_key_version: i64,
    keyring_version: i64,
    rotation: RotationInfo,
    device: DeviceInfo,
    checkpoint: Checkpoint,
    sync_policy: SyncPolicyInfo,
    wraps: Vec<KeyWrap>,
    events: Vec<AccountEvent>,
}

#[derive(Serialize)]
struct SyncPolicyInfo {
    server_time_unix: u64,
    offline_lease_seconds: u64,
    lease_expires_unix: u64,
    lease_token: String,
    pause_after_offline_days: u32,
    wipe_on_revocation: bool,
    re_enable_requires_new_account: bool,
}

#[derive(Serialize)]
struct DeviceInfo {
    device_id: String,
    last_seen_seq: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_sync_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acked_key_version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<String>,
}

#[derive(Serialize)]
struct Checkpoint {
    last_seen_seq: i64,
    tombstone_floor_seq: i64,
    change_floor_seq: i64,
}

#[derive(Serialize)]
struct KeyWrap {
    key_version: i64,
    recipient: String,
    status: String,
    wrap: String,
}

#[derive(Serialize)]
pub struct RotationInfo {
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_key_version: Option<i64>,
    active_key_version: i64,
    keyring_version: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deadline: Option<String>,
    writes_frozen: bool,
    required_device_count: i64,
    acknowledged_device_count: i64,
}

#[derive(Serialize)]
struct AccountEvent {
    event_id: String,
    #[serde(rename = "type")]
    event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    timestamp: String,
}

pub async fn get_account_me(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<AccountMeResponse>, AppError> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }
    let device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;
    let row = sqlx::query(
        "SELECT a.status, a.identity_ed25519_pub, a.identity_x25519_pub, \
                a.derivation_version, a.active_key_version, a.keyring_version, \
                to_char(a.deletion_requested_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS deletion_requested_at, \
                a.tombstone_floor_seq, a.change_floor_seq, d.last_seen_seq, \
                d.acked_key_version, \
                to_char(d.first_sync_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS first_sync_at, \
                to_char(d.last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS last_seen_at, \
                to_char(d.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS revoked_at \
         FROM accounts a JOIN devices d ON d.account_id = a.account_id \
         WHERE a.account_id = $1 AND d.device_id = $2",
    )
    .bind(&principal.account_id)
    .bind(device_id)
    .fetch_optional(&state.database)
    .await?
    .ok_or(AppError::InvalidSignature)?;

    let status: String = row.try_get("status")?;
    let identity_ed25519_pub: Vec<u8> = row.try_get("identity_ed25519_pub")?;
    let identity_x25519_pub: Vec<u8> = row.try_get("identity_x25519_pub")?;
    let derivation_version: i16 = row.try_get("derivation_version")?;
    let active_key_version: i64 = row.try_get("active_key_version")?;
    let keyring_version: i64 = row.try_get("keyring_version")?;
    let deletion_requested_at: Option<String> = row.try_get("deletion_requested_at")?;
    let last_seen_seq: i64 = row.try_get("last_seen_seq")?;
    let tombstone_floor_seq: i64 = row.try_get("tombstone_floor_seq")?;
    let change_floor_seq: i64 = row.try_get("change_floor_seq")?;
    let first_sync_at: Option<String> = row.try_get("first_sync_at")?;
    let last_seen_at: Option<String> = row.try_get("last_seen_at")?;
    let acked_key_version: Option<i64> = row.try_get("acked_key_version")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    if revoked_at.is_some() {
        return Err(AppError::DeviceRevoked);
    }

    // Touch device activity timestamp
    let _ = sqlx::query(
        "UPDATE devices SET last_seen_at = now() WHERE account_id = $1 AND device_id = $2",
    )
    .bind(&principal.account_id)
    .bind(device_id)
    .execute(&state.database)
    .await;

    let rotation = rotation_info(&state.database, &principal.account_id).await?;

    let wrap_rows = sqlx::query(
        "SELECT key_version, recipient, status, wrap FROM key_wraps \
         WHERE account_id = $1 AND recipient = $2 ORDER BY key_version",
    )
    .bind(&principal.account_id)
    .bind(device_id.to_string())
    .fetch_all(&state.database)
    .await?;
    let mut wraps = Vec::with_capacity(wrap_rows.len());
    for row in wrap_rows {
        let wrap: Vec<u8> = row.try_get("wrap")?;
        wraps.push(KeyWrap {
            key_version: row.try_get("key_version")?,
            recipient: row.try_get("recipient")?,
            status: row.try_get("status")?,
            wrap: URL_SAFE_NO_PAD.encode(wrap),
        });
    }

    let event_rows = sqlx::query(
        "SELECT event_id, event_type, actor_device_id, actor, \
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS timestamp \
         FROM account_events WHERE account_id = $1 ORDER BY created_at DESC, event_id DESC LIMIT 50",
    )
    .bind(&principal.account_id)
    .fetch_all(&state.database)
    .await?;
    let mut events = Vec::with_capacity(event_rows.len());
    for row in event_rows {
        let event_id: uuid::Uuid = row.try_get("event_id")?;
        let actor_device_id: Option<uuid::Uuid> = row.try_get("actor_device_id")?;
        let event_actor: String = row.try_get("actor")?;
        events.push(AccountEvent {
            event_id: event_id.to_string(),
            event_type: row.try_get("event_type")?,
            actor_device_id: actor_device_id.map(|id| id.to_string()),
            actor: (event_actor == "identity").then_some(event_actor),
            timestamp: row.try_get("timestamp")?,
        });
    }

    let server_time_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Unavailable)?
        .as_secs();
    let lease_expires_unix = server_time_unix.saturating_add(OFFLINE_LEASE_SECONDS);
    let lease_token = compute_offline_lease_token(
        &state.token_hmac_key,
        &principal.account_id,
        &device_id,
        server_time_unix,
        lease_expires_unix,
    )?;

    Ok(Json(AccountMeResponse {
        account_id: URL_SAFE_NO_PAD.encode(&principal.account_id),
        status,
        deletion_requested_at,
        identity_ed25519_pub: URL_SAFE_NO_PAD.encode(identity_ed25519_pub),
        identity_x25519_pub: URL_SAFE_NO_PAD.encode(identity_x25519_pub),
        derivation_version,
        active_key_version,
        keyring_version,
        rotation,
        device: DeviceInfo {
            device_id: device_id.to_string(),
            last_seen_seq,
            first_sync_at,
            last_seen_at,
            acked_key_version,
            revoked_at,
        },
        checkpoint: Checkpoint {
            last_seen_seq,
            tombstone_floor_seq,
            change_floor_seq,
        },
        sync_policy: SyncPolicyInfo {
            server_time_unix,
            offline_lease_seconds: OFFLINE_LEASE_SECONDS,
            lease_expires_unix,
            lease_token,
            pause_after_offline_days: 7,
            wipe_on_revocation: true,
            re_enable_requires_new_account: true,
        },
        wraps,
        events,
    }))
}

pub async fn rotation_info(database: &PgPool, account_id: &[u8]) -> Result<RotationInfo, AppError> {
    let row = sqlx::query(
        "SELECT rotation_mode, rotation_target_key_version, active_key_version, keyring_version, \
                rotation_owner_device_id, \
                to_char(rotation_lease_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS lease_expires_at, \
                to_char(rotation_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS deadline \
         FROM accounts WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(database)
    .await?
    .ok_or(AppError::InvalidSignature)?;
    let mode: String = row.try_get("rotation_mode")?;
    let target_key_version: Option<i64> = row.try_get("rotation_target_key_version")?;
    let active_key_version: i64 = row.try_get("active_key_version")?;
    let keyring_version: i64 = row.try_get("keyring_version")?;
    let owner_device_id: Option<uuid::Uuid> = row.try_get("rotation_owner_device_id")?;
    let lease_expires_at: Option<String> = row.try_get("lease_expires_at")?;
    let deadline: Option<String> = row.try_get("deadline")?;
    let (required_device_count, acknowledged_device_count) = if let Some(target_key_version) =
        target_key_version
    {
        let counts = sqlx::query(
                "SELECT COUNT(*) AS required_count, \
                        COUNT(*) FILTER (WHERE key_acknowledged_at IS NOT NULL \
                            AND ($3 = FALSE OR local_master_password_updated_at IS NOT NULL)) AS acknowledged_count \
                 FROM rotation_participants \
                 WHERE account_id = $1 AND key_version = $2 AND revoked_at IS NULL",
            )
            .bind(account_id)
            .bind(target_key_version)
            .bind(mode == "master_password_change")
            .fetch_one(database)
            .await?;
        (
            counts.try_get("required_count")?,
            counts.try_get("acknowledged_count")?,
        )
    } else {
        (0, 0)
    };
    Ok(RotationInfo {
        writes_frozen: mode == "master_password_change",
        mode,
        target_key_version,
        active_key_version,
        keyring_version,
        owner_device_id: owner_device_id.map(|id| id.to_string()),
        lease_expires_at,
        deadline,
        required_device_count,
        acknowledged_device_count,
    })
}
