use std::{collections::HashSet, convert::Infallible};

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    Extension, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use uuid::Uuid;

use crate::{
    auth::{AuthenticatedPrincipal, PrincipalKind},
    error::AppError,
    state::AppState,
};

const MAX_BATCH_OPERATIONS: usize = 100;
pub(crate) const MIN_BLOB_BYTES: usize = 552;
pub(crate) const MAX_BLOB_BYTES: usize = 65536;
pub(crate) const MAX_LIVE_ITEMS: i64 = 25_000;
pub(crate) const MAX_CIPHERTEXT_BYTES: i64 = 50 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRequest {
    pub operations: Vec<MutationRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationRequest {
    pub op: String,
    pub operation_id: String,
    pub item_id: String,
    pub base_version: u64,
    pub key_version: Option<u64>,
    pub blob: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchResponse {
    pub results: Vec<OperationResult>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationResult {
    pub operation_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

pub enum ParsedOp {
    Put {
        key_version: u32,
        decoded_blob: Vec<u8>,
        payload_digest: [u8; 32],
    },
    Delete,
}

pub struct ValidatedMutation {
    pub operation_id: Uuid,
    pub item_id: Uuid,
    pub base_version: u64,
    pub op: ParsedOp,
    pub op_hash: [u8; 32],
}

pub fn compute_operation_hash(
    account_id: &[u8],
    op_tag: u8,
    item_id: &Uuid,
    base_version: u64,
    key_version: u32,
    payload_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"NPSOp1");
    hasher.update(account_id);
    hasher.update([op_tag]);
    hasher.update(item_id.as_bytes());
    hasher.update(base_version.to_be_bytes());
    hasher.update(key_version.to_be_bytes());
    hasher.update(payload_digest);
    hasher.finalize().into()
}

pub async fn handle_sync_batch(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<BatchRequest>,
) -> Result<Json<BatchResponse>, AppError> {
    if principal.kind != PrincipalKind::Device || principal.device_id.is_none() {
        return Err(AppError::InvalidSignature);
    }
    let device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;
    let account_id = principal.account_id;

    if request.operations.is_empty() || request.operations.len() > MAX_BATCH_OPERATIONS {
        return Err(AppError::InvalidInput);
    }

    // Validate uniqueness of operation_id and item_id within the batch before beginning transaction.
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

        match op.op.as_str() {
            "put" => {
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
                        decoded_blob: decoded,
                        payload_digest,
                    },
                    op_hash,
                });
            }
            "delete" => {
                if op.key_version.is_some() || op.blob.is_some() {
                    return Err(AppError::InvalidInput);
                }
                let zero_digest = [0u8; 32];
                let op_hash = compute_operation_hash(
                    &account_id,
                    0x02,
                    &item_uuid,
                    op.base_version,
                    0,
                    &zero_digest,
                );

                validated_mutations.push(ValidatedMutation {
                    operation_id: operation_uuid,
                    item_id: item_uuid,
                    base_version: op.base_version,
                    op: ParsedOp::Delete,
                    op_hash,
                });
            }
            _ => return Err(AppError::InvalidInput),
        }
    }

    let mut tx = state.database.begin().await?;

    // Global lock order: lock accounts row first.
    let account_row = sqlx::query(
        "SELECT status, active_key_version, rotation_mode, rotation_target_key_version, seq_counter \
         FROM accounts \
         WHERE account_id = $1 \
         FOR UPDATE",
    )
    .bind(&account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(account_row) = account_row else {
        return Err(AppError::InvalidSignature);
    };

    let status: String = account_row.try_get("status")?;
    if status == "suspended" {
        return Err(AppError::AccountSuspended);
    }
    if status == "deletion_pending" {
        return Err(AppError::AccountDeletionPending);
    }

    // Re-verify device active state inside account lock transaction.
    let device_row = sqlx::query(
        "SELECT (revoked_at IS NOT NULL) AS is_revoked \
         FROM devices \
         WHERE account_id = $1 AND device_id = $2",
    )
    .bind(&account_id)
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(device_row) = device_row else {
        return Err(AppError::InvalidSignature);
    };
    let is_revoked: bool = device_row.try_get("is_revoked")?;
    if is_revoked {
        return Err(AppError::DeviceRevoked);
    }

    let rotation_mode: String = account_row.try_get("rotation_mode")?;
    if rotation_mode == "master_password_change" {
        return Err(AppError::RotationInProgress);
    }

    let active_key_version: i64 = account_row.try_get("active_key_version")?;
    let rotation_target_key_version: Option<i64> =
        account_row.try_get("rotation_target_key_version")?;
    let mut seq_counter: i64 = account_row.try_get("seq_counter")?;
    let initial_seq_counter = seq_counter;

    let (mut current_live_items, mut current_ciphertext_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*)::bigint, COALESCE(SUM(octet_length(blob)), 0)::bigint \
         FROM items WHERE account_id = $1 AND deleted = FALSE",
    )
    .bind(&account_id)
    .fetch_one(&mut *tx)
    .await?;

    let mut results = Vec::with_capacity(validated_mutations.len());

    for mutation in validated_mutations {
        let op_row = sqlx::query(
            "SELECT op_hash, status, item_version, seq \
             FROM operations \
             WHERE account_id = $1 AND operation_id = $2",
        )
        .bind(&account_id)
        .bind(mutation.operation_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(existing_op) = op_row {
            let stored_hash: Vec<u8> = existing_op.try_get("op_hash")?;
            if stored_hash != mutation.op_hash {
                // Different hash for same operation_id rejects the batch as a whole with 422.
                return Err(AppError::OperationIdReused);
            }
            let item_version: Option<i64> = existing_op.try_get("item_version")?;
            let seq: Option<i64> = existing_op.try_get("seq")?;
            results.push(OperationResult {
                operation_id: mutation.operation_id.to_string(),
                status: "duplicate".to_string(),
                version: item_version.map(|v| v as u64),
                seq: seq.map(|s| s as u64),
            });
            continue;
        }

        // Validate key version against rotation state.
        if let ParsedOp::Put { key_version, .. } = mutation.op {
            let kv = key_version as i64;
            let is_allowed = match rotation_mode.as_str() {
                "idle" => kv == active_key_version,
                "routine" => kv == active_key_version || rotation_target_key_version == Some(kv),
                "compromise" => rotation_target_key_version == Some(kv),
                _ => false,
            };

            if !is_allowed {
                results.push(OperationResult {
                    operation_id: mutation.operation_id.to_string(),
                    status: "unsupported_key_version".to_string(),
                    version: None,
                    seq: None,
                });
                continue;
            }
        }

        // Check permanent retirement marker.
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

        // Lookup current item state.
        let current_item = sqlx::query(
            "SELECT version, seq, deleted, octet_length(blob) AS blob_len \
             FROM items WHERE account_id = $1 AND item_id = $2",
        )
        .bind(&account_id)
        .bind(mutation.item_id)
        .fetch_optional(&mut *tx)
        .await?;

        match mutation.op {
            ParsedOp::Put {
                key_version,
                decoded_blob,
                ..
            } => {
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
                let is_new_item = match &current_item {
                    Some(row) => row.try_get::<bool, _>("deleted")?,
                    None => true,
                };
                if is_new_item && current_live_items + 1 > MAX_LIVE_ITEMS {
                    return Err(AppError::QuotaExceeded);
                }
                let new_blob_len = decoded_blob.len() as i64;
                let net_diff = new_blob_len - old_blob_len;
                if current_ciphertext_bytes + net_diff > MAX_CIPHERTEXT_BYTES {
                    return Err(AppError::QuotaExceeded);
                }
                if is_new_item {
                    current_live_items += 1;
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
            ParsedOp::Delete => {
                let Some(item_row) = current_item else {
                    let status = if mutation.base_version > 0 {
                        "item_gone"
                    } else {
                        "conflict"
                    };
                    results.push(OperationResult {
                        operation_id: mutation.operation_id.to_string(),
                        status: status.to_string(),
                        version: None,
                        seq: None,
                    });
                    continue;
                };

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

                let old_blob_len: i64 =
                    item_row.try_get::<Option<i32>, _>("blob_len")?.unwrap_or(0) as i64;
                current_live_items = current_live_items.saturating_sub(1);
                current_ciphertext_bytes = current_ciphertext_bytes.saturating_sub(old_blob_len);

                let next_version = (current_version + 1) as u64;
                seq_counter += 1;

                sqlx::query(
                    "UPDATE items SET blob = NULL, key_version = 0, version = $3, seq = $4, deleted = TRUE, updated_at = now() \
                     WHERE account_id = $1 AND item_id = $2",
                )
                .bind(&account_id)
                .bind(mutation.item_id)
                .bind(next_version as i64)
                .bind(seq_counter)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO retired_item_ids (account_id, item_id, retired_at) \
                     VALUES ($1, $2, now()) \
                     ON CONFLICT (account_id, item_id) DO NOTHING",
                )
                .bind(&account_id)
                .bind(mutation.item_id)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO item_changes (account_id, seq, item_id, version, key_version, blob, deleted, created_at) \
                     VALUES ($1, $2, $3, $4, 0, NULL, TRUE, now())",
                )
                .bind(&account_id)
                .bind(seq_counter)
                .bind(mutation.item_id)
                .bind(next_version as i64)
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
    }

    if seq_counter != initial_seq_counter {
        sqlx::query("UPDATE accounts SET seq_counter = $2 WHERE account_id = $1")
            .bind(&account_id)
            .bind(seq_counter)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    if seq_counter != initial_seq_counter {
        let _ = state.sync_notifier.send(crate::state::SyncNotification {
            account_id: account_id.clone(),
            seq: seq_counter,
        });
    }

    Ok(Json(BatchResponse { results }))
}

/// GET /v1/sync/events
/// Real-time Server-Sent Events (SSE) notification stream.
/// Emits sequence updates `{"seq": N}` whenever changes are committed to the account.
pub async fn handle_sync_events(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<
    Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>> + Send + 'static>,
    AppError,
> {
    if principal.kind != PrincipalKind::Device {
        return Err(AppError::InvalidSignature);
    }

    let target_account_id = principal.account_id;
    let rx = state.sync_notifier.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(notification) if notification.account_id == target_account_id => {
            let data = serde_json::json!({
                "seq": notification.seq,
            });
            Some(Ok(Event::default().event("sync").data(data.to_string())))
        }
        _ => None,
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    ))
}

pub(crate) fn parse_canonical_uuid(value: &str) -> Result<Uuid, AppError> {
    let uuid = Uuid::parse_str(value).map_err(|_| AppError::InvalidInput)?;
    if uuid.to_string() != value || uuid.get_version_num() != 4 {
        return Err(AppError::InvalidInput);
    }
    Ok(uuid)
}
