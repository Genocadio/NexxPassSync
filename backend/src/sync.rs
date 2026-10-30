use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    Extension, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio_stream::{wrappers::BroadcastStream, Stream};
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
pub(crate) const MAX_HISTORY_CIPHERTEXT_BYTES: i64 = 100 * 1024 * 1024;

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
    pub delete_proof: Option<String>,
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
    Delete {
        proof: Vec<u8>,
    },
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
                if op.delete_proof.is_some() {
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
                let Some(proof) = &op.delete_proof else {
                    return Err(AppError::DeleteProofRequired);
                };
                let decoded_proof = URL_SAFE_NO_PAD
                    .decode(proof)
                    .map_err(|_| AppError::InvalidInput)?;
                if URL_SAFE_NO_PAD.encode(&decoded_proof) != *proof || decoded_proof.len() != 64 {
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
                    op: ParsedOp::Delete {
                        proof: decoded_proof,
                    },
                    op_hash,
                });
            }
            _ => return Err(AppError::InvalidInput),
        }
    }

    let mut tx = state.database.begin().await?;

    // Global lock order: lock accounts row first.
    let account_row = sqlx::query(
        "SELECT status, identity_ed25519_pub, active_key_version, rotation_mode, rotation_target_key_version, seq_counter \
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
    if status == "sync_disabled" {
        return Err(AppError::SyncDisabled);
    }

    let identity_public_key: Vec<u8> = account_row.try_get("identity_ed25519_pub")?;
    for mutation in &validated_mutations {
        if let ParsedOp::Delete { proof } = &mutation.op {
            verify_delete_proof(
                &identity_public_key,
                proof,
                &account_id,
                &mutation.item_id,
                mutation.base_version,
            )?;
        }
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

    // Touch device activity timestamp and set first_sync_at if this is the first batch
    sqlx::query(
        "UPDATE devices SET last_seen_at = now(), first_sync_at = COALESCE(first_sync_at, now()) \
         WHERE account_id = $1 AND device_id = $2",
    )
    .bind(&account_id)
    .bind(device_id)
    .execute(&mut *tx)
    .await?;

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

    let batch_op_ids: Vec<Uuid> = validated_mutations.iter().map(|m| m.operation_id).collect();
    let batch_item_ids: Vec<Uuid> = validated_mutations.iter().map(|m| m.item_id).collect();

    let existing_op_rows = sqlx::query(
        "SELECT operation_id, op_hash, item_version, seq \
         FROM operations \
         WHERE account_id = $1 AND operation_id = ANY($2)",
    )
    .bind(&account_id)
    .bind(&batch_op_ids)
    .fetch_all(&mut *tx)
    .await?;

    struct CachedOperationState {
        op_hash: Vec<u8>,
        item_version: Option<i64>,
        seq: Option<i64>,
    }

    let mut existing_ops: HashMap<Uuid, CachedOperationState> =
        HashMap::with_capacity(existing_op_rows.len());
    for row in existing_op_rows {
        let op_id: Uuid = row.try_get("operation_id")?;
        let op_hash: Vec<u8> = row.try_get("op_hash")?;
        let item_version: Option<i64> = row.try_get("item_version")?;
        let seq: Option<i64> = row.try_get("seq")?;
        existing_ops.insert(
            op_id,
            CachedOperationState {
                op_hash,
                item_version,
                seq,
            },
        );
    }

    let retired_rows = sqlx::query(
        "SELECT item_id FROM retired_item_ids WHERE account_id = $1 AND item_id = ANY($2)",
    )
    .bind(&account_id)
    .bind(&batch_item_ids)
    .fetch_all(&mut *tx)
    .await?;

    let mut retired_items: HashSet<Uuid> = HashSet::with_capacity(retired_rows.len());
    for row in retired_rows {
        retired_items.insert(row.try_get("item_id")?);
    }

    let item_rows = sqlx::query(
        "SELECT item_id, version, deleted, octet_length(blob) AS blob_len \
         FROM items WHERE account_id = $1 AND item_id = ANY($2)",
    )
    .bind(&account_id)
    .bind(&batch_item_ids)
    .fetch_all(&mut *tx)
    .await?;

    struct CachedItemState {
        version: i64,
        deleted: bool,
        blob_len: i64,
    }

    let mut current_items: HashMap<Uuid, CachedItemState> = HashMap::with_capacity(item_rows.len());
    for row in item_rows {
        let item_id: Uuid = row.try_get("item_id")?;
        let version: i64 = row.try_get("version")?;
        let deleted: bool = row.try_get("deleted")?;
        let blob_len = row.try_get::<Option<i32>, _>("blob_len")?.unwrap_or(0) as i64;
        current_items.insert(
            item_id,
            CachedItemState {
                version,
                deleted,
                blob_len,
            },
        );
    }

    for mutation in validated_mutations {
        if let Some(existing_op) = existing_ops.get(&mutation.operation_id) {
            if existing_op.op_hash.as_slice() != mutation.op_hash {
                // Different hash for same operation_id rejects the batch as a whole with 422.
                return Err(AppError::OperationIdReused);
            }
            results.push(OperationResult {
                operation_id: mutation.operation_id.to_string(),
                status: "duplicate".to_string(),
                version: existing_op.item_version.map(|v| v as u64),
                seq: existing_op.seq.map(|s| s as u64),
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
        if retired_items.contains(&mutation.item_id) {
            results.push(OperationResult {
                operation_id: mutation.operation_id.to_string(),
                status: "item_deleted".to_string(),
                version: None,
                seq: None,
            });
            continue;
        }

        // Lookup current item state.
        let current_item = current_items.get(&mutation.item_id);

        match mutation.op {
            ParsedOp::Put {
                key_version,
                decoded_blob,
                ..
            } => {
                let old_blob_len: i64 = match current_item {
                    Some(row) => {
                        if row.deleted {
                            0
                        } else {
                            row.blob_len
                        }
                    }
                    None => 0,
                };
                let is_new_item = match current_item {
                    Some(row) => row.deleted,
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
                    if item_row.deleted {
                        results.push(OperationResult {
                            operation_id: mutation.operation_id.to_string(),
                            status: "item_deleted".to_string(),
                            version: None,
                            seq: None,
                        });
                        continue;
                    }
                    if item_row.version as u64 != mutation.base_version {
                        results.push(OperationResult {
                            operation_id: mutation.operation_id.to_string(),
                            status: "base_version_conflict".to_string(),
                            version: None,
                            seq: None,
                        });
                        continue;
                    }
                    (item_row.version + 1) as u64
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
            ParsedOp::Delete { proof } => {
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

                if item_row.deleted {
                    results.push(OperationResult {
                        operation_id: mutation.operation_id.to_string(),
                        status: "item_deleted".to_string(),
                        version: None,
                        seq: None,
                    });
                    continue;
                }

                if item_row.version as u64 != mutation.base_version {
                    results.push(OperationResult {
                        operation_id: mutation.operation_id.to_string(),
                        status: "base_version_conflict".to_string(),
                        version: None,
                        seq: None,
                    });
                    continue;
                }

                let old_blob_len = item_row.blob_len;
                current_live_items = current_live_items.saturating_sub(1);
                current_ciphertext_bytes = current_ciphertext_bytes.saturating_sub(old_blob_len);

                let next_version = (item_row.version + 1) as u64;
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
                    "INSERT INTO item_changes (account_id, seq, item_id, version, key_version, blob, deleted, delete_proof, created_at) \
                     VALUES ($1, $2, $3, $4, 0, NULL, TRUE, $5, now())",
                )
                .bind(&account_id)
                .bind(seq_counter)
                .bind(mutation.item_id)
                .bind(next_version as i64)
                .bind(proof)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "DELETE FROM attachment_blobs WHERE account_id = $1 AND record_id = $2",
                )
                .bind(&account_id)
                .bind(mutation.item_id)
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

        // Enforce the 100 MB (2x live quota) historical ciphertext cap on item_changes (Plan §8).
        let history_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(octet_length(blob)), 0)::bigint \
             FROM item_changes WHERE account_id = $1",
        )
        .bind(&account_id)
        .fetch_one(&mut *tx)
        .await?;

        if history_bytes > MAX_HISTORY_CIPHERTEXT_BYTES {
            let active_sessions: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sync_sessions \
                 WHERE account_id = $1 AND expires_at > now()",
            )
            .bind(&account_id)
            .fetch_one(&mut *tx)
            .await?;

            if active_sessions == 0 {
                let pruned_seqs: Vec<i64> = sqlx::query_scalar(
                    "DELETE FROM item_changes ic \
                     USING items i \
                     WHERE ic.account_id = $1 \
                       AND i.account_id = ic.account_id \
                       AND i.item_id = ic.item_id \
                       AND ic.seq < i.seq \
                     RETURNING ic.seq",
                )
                .bind(&account_id)
                .fetch_all(&mut *tx)
                .await?;

                if let Some(max_pruned_seq) = pruned_seqs.into_iter().max() {
                    sqlx::query(
                        "UPDATE accounts \
                         SET change_floor_seq = GREATEST(change_floor_seq, $2) \
                         WHERE account_id = $1",
                    )
                    .bind(&account_id)
                    .bind(max_pruned_seq)
                    .execute(&mut *tx)
                    .await?;

                    let event_id = Uuid::now_v7();
                    sqlx::query(
                        "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
                         VALUES ($1, $2, 'history_cap_prune', 'device', $3)",
                    )
                    .bind(&account_id)
                    .bind(event_id)
                    .bind(device_id)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }
    }

    tx.commit().await?;

    if seq_counter != initial_seq_counter {
        let _ = state.sync_notifier.send(crate::state::SyncNotification {
            account_id: account_id.clone(),
            seq: Some(seq_counter),
            revoked_device_id: None,
            revoked_reason: None,
            revocation_proof: None,
        });
    }

    Ok(Json(BatchResponse { results }))
}

struct SseDropGuard(std::sync::Arc<crate::state::Metrics>);
impl Drop for SseDropGuard {
    fn drop(&mut self) {
        self.0
            .active_sse_connections
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

struct SyncEventStream {
    inner: BroadcastStream<crate::state::SyncNotification>,
    target_account_id: Vec<u8>,
    caller_device_id: Uuid,
    terminated: bool,
    _guard: SseDropGuard,
}

impl Stream for SyncEventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.terminated {
            return Poll::Ready(None);
        }
        loop {
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(notification)))
                    if notification.account_id == self.target_account_id =>
                {
                    if notification.revoked_device_id == Some(self.caller_device_id) {
                        self.terminated = true;
                        let data = serde_json::json!({
                            "device_id": self.caller_device_id.to_string(),
                            "wipe_required": true,
                            "reason": notification.revoked_reason.unwrap_or_else(|| "user_revocation".to_string()),
                            "revocation_proof": notification.revocation_proof,
                        });
                        return Poll::Ready(Some(Ok(Event::default()
                            .event("revoked")
                            .data(data.to_string()))));
                    }
                    if let Some(seq) = notification.seq {
                        let data = serde_json::json!({
                            "seq": seq,
                        });
                        return Poll::Ready(Some(Ok(Event::default()
                            .event("sync")
                            .data(data.to_string()))));
                    }
                }
                Poll::Ready(Some(_)) => continue,
                Poll::Ready(None) => {
                    self.terminated = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// GET /v1/sync/events
/// Real-time Server-Sent Events (SSE) notification stream.
/// Emits sequence updates `{"seq": N}` whenever changes are committed to the account,
/// and emits a final `event: revoked` with `"wipe_required": true` before closing
/// if the connected device is revoked or sync is disabled.
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
    let caller_device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;

    // Touch device activity timestamp
    let _ = sqlx::query(
        "UPDATE devices SET last_seen_at = now() WHERE account_id = $1 AND device_id = $2",
    )
    .bind(&principal.account_id)
    .bind(caller_device_id)
    .execute(&state.database)
    .await;

    let target_account_id = principal.account_id;
    state
        .metrics
        .active_sse_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let guard = SseDropGuard(state.metrics.clone());

    let rx = state.sync_notifier.subscribe();
    let stream = SyncEventStream {
        inner: BroadcastStream::new(rx),
        target_account_id,
        caller_device_id,
        terminated: false,
        _guard: guard,
    };

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

pub(crate) fn delete_proof_message(
    account_id: &[u8],
    item_id: &Uuid,
    base_version: u64,
    version: u64,
) -> Vec<u8> {
    format!(
        "NexxPass/Tombstone/v1\n{}\n{}\n{}\n{}",
        URL_SAFE_NO_PAD.encode(account_id),
        item_id,
        base_version,
        version
    )
    .into_bytes()
}

fn verify_delete_proof(
    public_key: &[u8],
    proof: &[u8],
    account_id: &[u8],
    item_id: &Uuid,
    base_version: u64,
) -> Result<(), AppError> {
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| AppError::InvalidSignature)?;
    let identity_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| AppError::InvalidSignature)?;
    let signature = Signature::from_slice(proof).map_err(|_| AppError::InvalidSignature)?;
    let version = base_version.checked_add(1).ok_or(AppError::InvalidInput)?;
    identity_key
        .verify_strict(
            &delete_proof_message(account_id, item_id, base_version, version),
            &signature,
        )
        .map_err(|_| AppError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn delete_proofs_are_bound_to_account_item_and_version() {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let account_id = [0x24; 32];
        let item_id = Uuid::from_u128(0xc4b0_d7b4_9c27_4ed8_9d8b_2249_9e43_6a20);
        let message = delete_proof_message(&account_id, &item_id, 4, 5);
        let signature = key.sign(&message);
        let verifying_key = key.verifying_key();

        assert!(verify_delete_proof(
            &verifying_key.to_bytes(),
            &signature.to_bytes(),
            &account_id,
            &item_id,
            4
        )
        .is_ok());
        assert!(verify_delete_proof(
            &verifying_key.to_bytes(),
            &signature.to_bytes(),
            &account_id,
            &item_id,
            5
        )
        .is_err());
        assert!(verify_delete_proof(
            &verifying_key.to_bytes(),
            &signature.to_bytes(),
            &[0x25; 32],
            &item_id,
            4
        )
        .is_err());
        assert!(verify_delete_proof(
            &verifying_key.to_bytes(),
            &signature.to_bytes(),
            &account_id,
            &Uuid::new_v4(),
            4
        )
        .is_err());
    }
}
