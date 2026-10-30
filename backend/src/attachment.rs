use axum::{
    extract::{Path, State},
    Extension, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::{lock_active_device_for_mutation, AuthenticatedPrincipal},
    error::AppError,
    state::AppState,
};

pub const MAX_ATTACHMENT_PLAINTEXT_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_ATTACHMENT_ENVELOPE_BYTES: usize = MAX_ATTACHMENT_PLAINTEXT_BYTES + 64 * 1024;
pub const MAX_ATTACHMENT_REQUEST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ATTACHMENT_QUOTA_BYTES: i64 = 50 * 1024 * 1024;
const MAX_ATTACHMENTS_PER_RECORD: usize = 100;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadAttachmentRequest {
    pub key_version: u64,
    pub blob: String,
}

#[derive(Debug, Serialize)]
pub struct AttachmentBlobResponse {
    pub record_id: String,
    pub attachment_id: String,
    pub key_version: u64,
    pub blob: String,
}

#[derive(Debug, Serialize)]
pub struct AttachmentUploadResponse {
    pub status: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileAttachmentsRequest {
    pub keep_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReconcileAttachmentsResponse {
    pub removed: u64,
}

pub async fn put_attachment(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path((record_text, attachment_text)): Path<(String, String)>,
    Json(request): Json<UploadAttachmentRequest>,
) -> Result<Json<AttachmentUploadResponse>, AppError> {
    let record_id = parse_canonical_uuid(&record_text)?;
    let attachment_id = parse_canonical_uuid(&attachment_text)?;
    if request.key_version == 0 || request.key_version > u32::MAX as u64 {
        return Err(AppError::InvalidInput);
    }

    let blob = decode_attachment_envelope(&request.blob)?;

    let mut tx = state.database.begin().await?;
    lock_active_device_for_mutation(&mut tx, &principal).await?;
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
    if status == "suspended" {
        return Err(AppError::AccountSuspended);
    }
    if status == "deletion_pending" {
        return Err(AppError::AccountDeletionPending);
    }
    if status == "sync_disabled" {
        return Err(AppError::SyncDisabled);
    }
    let rotation_mode: String = account_row.try_get("rotation_mode")?;
    if rotation_mode == "master_password_change" {
        return Err(AppError::RotationInProgress);
    }
    let active_key_version: i64 = account_row.try_get("active_key_version")?;
    let target_key_version: Option<i64> = account_row.try_get("rotation_target_key_version")?;
    let key_version = request.key_version as i64;
    let key_version_allowed = match rotation_mode.as_str() {
        "idle" => key_version == active_key_version,
        "routine" => key_version == active_key_version || target_key_version == Some(key_version),
        "compromise" => target_key_version == Some(key_version),
        _ => false,
    };
    if !key_version_allowed {
        return Err(AppError::InvalidInput);
    }

    let existing = sqlx::query(
        "SELECT record_id, octet_length(blob)::bigint AS blob_bytes \
         FROM attachment_blobs WHERE account_id = $1 AND attachment_id = $2",
    )
    .bind(&principal.account_id)
    .bind(attachment_id)
    .fetch_optional(&mut *tx)
    .await?;
    let is_new_attachment = existing.is_none();
    let replaced_bytes = if let Some(row) = existing {
        let existing_record_id: Uuid = row.try_get("record_id")?;
        if existing_record_id != record_id {
            return Err(AppError::Conflict);
        }
        row.try_get::<i64, _>("blob_bytes")?
    } else {
        0
    };

    let current_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(octet_length(blob)), 0)::bigint \
         FROM attachment_blobs WHERE account_id = $1",
    )
    .bind(&principal.account_id)
    .fetch_one(&mut *tx)
    .await?;
    let updated_total = current_bytes
        .saturating_sub(replaced_bytes)
        .saturating_add(blob.len() as i64);
    if updated_total > MAX_ATTACHMENT_QUOTA_BYTES {
        return Err(AppError::QuotaExceeded);
    }

    let record_attachment_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM attachment_blobs \
         WHERE account_id = $1 AND record_id = $2 AND attachment_id <> $3",
    )
    .bind(&principal.account_id)
    .bind(record_id)
    .bind(attachment_id)
    .fetch_one(&mut *tx)
    .await?;
    if is_new_attachment && record_attachment_count >= MAX_ATTACHMENTS_PER_RECORD as i64 {
        return Err(AppError::QuotaExceeded);
    }

    sqlx::query(
        "INSERT INTO attachment_blobs \
         (account_id, record_id, attachment_id, key_version, blob, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, now(), now()) \
         ON CONFLICT (account_id, attachment_id) DO UPDATE SET \
         key_version = EXCLUDED.key_version, blob = EXCLUDED.blob, updated_at = now()",
    )
    .bind(&principal.account_id)
    .bind(record_id)
    .bind(attachment_id)
    .bind(key_version)
    .bind(&blob)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(AttachmentUploadResponse { status: "stored" }))
}

pub async fn get_attachment(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path((record_text, attachment_text)): Path<(String, String)>,
) -> Result<Json<AttachmentBlobResponse>, AppError> {
    let record_id = parse_canonical_uuid(&record_text)?;
    let attachment_id = parse_canonical_uuid(&attachment_text)?;
    let mut tx = state.database.begin().await?;
    lock_active_device_for_mutation(&mut tx, &principal).await?;
    let row = sqlx::query(
        "SELECT key_version, blob FROM attachment_blobs \
         WHERE account_id = $1 AND record_id = $2 AND attachment_id = $3",
    )
    .bind(&principal.account_id)
    .bind(record_id)
    .bind(attachment_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Err(AppError::NotFound);
    };
    let key_version: i64 = row.try_get("key_version")?;
    let blob: Vec<u8> = row.try_get("blob")?;
    tx.commit().await?;

    Ok(Json(AttachmentBlobResponse {
        record_id: record_id.to_string(),
        attachment_id: attachment_id.to_string(),
        key_version: key_version as u64,
        blob: URL_SAFE_NO_PAD.encode(blob),
    }))
}

pub async fn reconcile_attachments(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(record_text): Path<String>,
    Json(request): Json<ReconcileAttachmentsRequest>,
) -> Result<Json<ReconcileAttachmentsResponse>, AppError> {
    let record_id = parse_canonical_uuid(&record_text)?;
    if request.keep_ids.len() > MAX_ATTACHMENTS_PER_RECORD {
        return Err(AppError::InvalidInput);
    }
    let mut keep_ids = Vec::with_capacity(request.keep_ids.len());
    for value in &request.keep_ids {
        let id = parse_canonical_uuid(value)?;
        if keep_ids.contains(&id) {
            return Err(AppError::InvalidInput);
        }
        keep_ids.push(id);
    }

    let mut tx = state.database.begin().await?;
    lock_active_device_for_mutation(&mut tx, &principal).await?;
    let record_is_live: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM items \
         WHERE account_id = $1 AND item_id = $2 AND deleted = FALSE)",
    )
    .bind(&principal.account_id)
    .bind(record_id)
    .fetch_one(&mut *tx)
    .await?;
    if !record_is_live {
        return Err(AppError::NotFound);
    }

    let result = sqlx::query(
        "DELETE FROM attachment_blobs \
         WHERE account_id = $1 AND record_id = $2 AND NOT (attachment_id = ANY($3))",
    )
    .bind(&principal.account_id)
    .bind(record_id)
    .bind(&keep_ids)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(ReconcileAttachmentsResponse {
        removed: result.rows_affected(),
    }))
}

fn parse_canonical_uuid(value: &str) -> Result<Uuid, AppError> {
    let id = Uuid::parse_str(value).map_err(|_| AppError::InvalidInput)?;
    if id.to_string() != value {
        return Err(AppError::InvalidInput);
    }
    Ok(id)
}

fn decode_attachment_envelope(value: &str) -> Result<Vec<u8>, AppError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::InvalidInput)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value
        || decoded.len() < 41
        || decoded.len() > MAX_ATTACHMENT_ENVELOPE_BYTES
    {
        return Err(AppError::InvalidInput);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn attachment_ids_must_be_canonical_uuids() {
        let valid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        assert_eq!(parse_canonical_uuid(valid).unwrap().to_string(), valid);
        assert!(parse_canonical_uuid("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA").is_err());
        assert!(parse_canonical_uuid("not-a-uuid").is_err());
    }

    #[test]
    fn attachment_envelopes_require_canonical_base64url_and_bounded_size() {
        let valid = URL_SAFE_NO_PAD.encode([7u8; 41]);
        assert_eq!(decode_attachment_envelope(&valid).unwrap().len(), 41);
        assert!(decode_attachment_envelope("AQ==").is_err());
        let padded = base64::engine::general_purpose::URL_SAFE.encode([7u8; 41]);
        assert!(decode_attachment_envelope(&padded).is_err());
        let too_large = URL_SAFE_NO_PAD.encode(vec![0u8; MAX_ATTACHMENT_ENVELOPE_BYTES + 1]);
        assert!(decode_attachment_envelope(&too_large).is_err());
    }
}
