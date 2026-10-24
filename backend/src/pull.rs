use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, Extension, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::{AuthenticatedPrincipal, PrincipalKind},
    error::AppError,
    state::AppState,
};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_PAGE_SIZE: i64 = 100;
const MAX_PAGE_SIZE: i64 = 1000;
const SESSION_TTL_SECONDS: u64 = 24 * 3600;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequest {
    pub checkpoint: Option<u64>,
    pub page_size: Option<i64>,
    pub continuation_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PullPage {
    pub sync_session_id: String,
    pub items: Vec<ItemState>,
    pub high_watermark: u64,
    pub page_cursor: u64,
    pub done: bool,
    pub page_receipt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ItemState {
    pub item_id: String,
    pub version: u64,
    pub seq: u64,
    pub deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRequest {
    pub sync_session_id: String,
    pub terminal_seq: u64,
    pub page_receipt: String,
}

#[derive(Debug, Serialize)]
pub struct AckResponse {
    pub status: String,
    pub last_seen_seq: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ContinuationTokenData {
    pub tkv: u8,
    pub epoch: u64,
    pub session_id: Uuid,
    pub page_number: u32,
    pub high_watermark: u64,
    pub next_cursor: u64,
    pub expiry_unix: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PageReceiptData {
    pub rv: u8,
    pub session_id: Uuid,
    pub page_number: u32,
    pub terminal_seq: u64,
}

pub fn encode_continuation_token(
    key: &[u8; 32],
    account_id: &[u8],
    device_id: &Uuid,
    data: &ContinuationTokenData,
) -> Result<String, AppError> {
    let mut body = [0u8; 53];
    body[0] = data.tkv;
    body[1..9].copy_from_slice(&data.epoch.to_be_bytes());
    body[9..25].copy_from_slice(data.session_id.as_bytes());
    body[25..29].copy_from_slice(&data.page_number.to_be_bytes());
    body[29..37].copy_from_slice(&data.high_watermark.to_be_bytes());
    body[37..45].copy_from_slice(&data.next_cursor.to_be_bytes());
    body[45..53].copy_from_slice(&data.expiry_unix.to_be_bytes());

    let mut mac_input = Vec::with_capacity(53 + account_id.len() + 16);
    mac_input.extend_from_slice(&body);
    mac_input.extend_from_slice(account_id);
    mac_input.extend_from_slice(device_id.as_bytes());

    let mut hmac = HmacSha256::new_from_slice(key).map_err(|_| AppError::Unavailable)?;
    hmac.update(&mac_input);
    let tag = hmac.finalize().into_bytes();

    let mut raw = [0u8; 69];
    raw[0..53].copy_from_slice(&body);
    raw[53..69].copy_from_slice(&tag[0..16]);

    Ok(URL_SAFE_NO_PAD.encode(raw))
}

pub fn decode_continuation_token(
    key: &[u8; 32],
    account_id: &[u8],
    device_id: &Uuid,
    encoded: &str,
) -> Result<ContinuationTokenData, AppError> {
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::InvalidInput)?;
    if raw.len() != 69 || URL_SAFE_NO_PAD.encode(&raw) != encoded {
        return Err(AppError::InvalidInput);
    }
    if raw[0] != 1 {
        return Err(AppError::InvalidInput);
    }

    let mut mac_input = Vec::with_capacity(53 + account_id.len() + 16);
    mac_input.extend_from_slice(&raw[0..53]);
    mac_input.extend_from_slice(account_id);
    mac_input.extend_from_slice(device_id.as_bytes());

    let mut hmac = HmacSha256::new_from_slice(key).map_err(|_| AppError::Unavailable)?;
    hmac.update(&mac_input);
    let tag = hmac.finalize().into_bytes();

    if raw[53..69] != tag[0..16] {
        return Err(AppError::InvalidInput);
    }

    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&raw[1..9]);
    let epoch = u64::from_be_bytes(epoch_bytes);

    let session_id = Uuid::from_slice(&raw[9..25]).map_err(|_| AppError::InvalidInput)?;

    let mut page_num_bytes = [0u8; 4];
    page_num_bytes.copy_from_slice(&raw[25..29]);
    let page_number = u32::from_be_bytes(page_num_bytes);

    let mut hw_bytes = [0u8; 8];
    hw_bytes.copy_from_slice(&raw[29..37]);
    let high_watermark = u64::from_be_bytes(hw_bytes);

    let mut cursor_bytes = [0u8; 8];
    cursor_bytes.copy_from_slice(&raw[37..45]);
    let next_cursor = u64::from_be_bytes(cursor_bytes);

    let mut expiry_bytes = [0u8; 8];
    expiry_bytes.copy_from_slice(&raw[45..53]);
    let expiry_unix = u64::from_be_bytes(expiry_bytes);

    Ok(ContinuationTokenData {
        tkv: raw[0],
        epoch,
        session_id,
        page_number,
        high_watermark,
        next_cursor,
        expiry_unix,
    })
}

pub fn encode_page_receipt(
    key: &[u8; 32],
    account_id: &[u8],
    device_id: &Uuid,
    data: &PageReceiptData,
) -> Result<String, AppError> {
    let mut body = [0u8; 29];
    body[0] = data.rv;
    body[1..17].copy_from_slice(data.session_id.as_bytes());
    body[17..21].copy_from_slice(&data.page_number.to_be_bytes());
    body[21..29].copy_from_slice(&data.terminal_seq.to_be_bytes());

    let mut mac_input = Vec::with_capacity(29 + account_id.len() + 16);
    mac_input.extend_from_slice(&body);
    mac_input.extend_from_slice(account_id);
    mac_input.extend_from_slice(device_id.as_bytes());

    let mut hmac = HmacSha256::new_from_slice(key).map_err(|_| AppError::Unavailable)?;
    hmac.update(&mac_input);
    let tag = hmac.finalize().into_bytes();

    let mut raw = [0u8; 45];
    raw[0..29].copy_from_slice(&body);
    raw[29..45].copy_from_slice(&tag[0..16]);

    Ok(URL_SAFE_NO_PAD.encode(raw))
}

pub fn decode_page_receipt(
    key: &[u8; 32],
    account_id: &[u8],
    device_id: &Uuid,
    encoded: &str,
) -> Result<PageReceiptData, AppError> {
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::InvalidInput)?;
    if raw.len() != 45 || URL_SAFE_NO_PAD.encode(&raw) != encoded {
        return Err(AppError::InvalidInput);
    }
    if raw[0] != 1 {
        return Err(AppError::InvalidInput);
    }

    let mut mac_input = Vec::with_capacity(29 + account_id.len() + 16);
    mac_input.extend_from_slice(&raw[0..29]);
    mac_input.extend_from_slice(account_id);
    mac_input.extend_from_slice(device_id.as_bytes());

    let mut hmac = HmacSha256::new_from_slice(key).map_err(|_| AppError::Unavailable)?;
    hmac.update(&mac_input);
    let tag = hmac.finalize().into_bytes();

    if raw[29..45] != tag[0..16] {
        return Err(AppError::InvalidInput);
    }

    let session_id = Uuid::from_slice(&raw[1..17]).map_err(|_| AppError::InvalidInput)?;

    let mut page_num_bytes = [0u8; 4];
    page_num_bytes.copy_from_slice(&raw[17..21]);
    let page_number = u32::from_be_bytes(page_num_bytes);

    let mut term_seq_bytes = [0u8; 8];
    term_seq_bytes.copy_from_slice(&raw[21..29]);
    let terminal_seq = u64::from_be_bytes(term_seq_bytes);

    Ok(PageReceiptData {
        rv: raw[0],
        session_id,
        page_number,
        terminal_seq,
    })
}

pub async fn handle_sync_pull(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<PullRequest>,
) -> Result<Json<PullPage>, AppError> {
    if principal.kind != PrincipalKind::Device || principal.device_id.is_none() {
        return Err(AppError::InvalidSignature);
    }
    let device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;
    let account_id = principal.account_id;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Unavailable)?
        .as_secs();

    if let Some(token_str) = &request.continuation_token {
        if request.checkpoint.is_some() || request.page_size.is_some() {
            return Err(AppError::InvalidInput);
        }

        let token_data =
            decode_continuation_token(&state.token_hmac_key, &account_id, &device_id, token_str)?;

        if token_data.epoch != state.deployment_epoch || token_data.expiry_unix <= now_unix {
            return Err(AppError::InvalidInput);
        }

        let mut tx = state.database.begin().await?;

        // Lock device row only (never accounts).
        let device_row = sqlx::query(
            "SELECT (revoked_at IS NOT NULL) AS is_revoked FROM devices WHERE account_id = $1 AND device_id = $2 FOR UPDATE",
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

        let session_row = sqlx::query(
            "SELECT deployment_epoch, high_watermark, page_size, page_position, is_full_snapshot, is_completed, is_abandoned, expires_at \
             FROM sync_sessions \
             WHERE session_id = $1 AND account_id = $2 AND device_id = $3 \
             FOR UPDATE",
        )
        .bind(token_data.session_id)
        .bind(&account_id)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(session_row) = session_row else {
            return Err(AppError::InvalidInput);
        };

        let is_completed: bool = session_row.try_get("is_completed")?;
        let is_abandoned: bool = session_row.try_get("is_abandoned")?;
        let session_hw: i64 = session_row.try_get("high_watermark")?;
        let session_page_size: i32 = session_row.try_get("page_size")?;
        let current_page: i32 = session_row.try_get("page_position")?;
        let is_full_snapshot: bool = session_row.try_get("is_full_snapshot")?;

        if is_completed
            || is_abandoned
            || session_hw as u64 != token_data.high_watermark
            || (current_page + 1) as u32 != token_data.page_number
        {
            return Err(AppError::InvalidInput);
        }

        let page_items = fetch_page_items(
            &mut tx,
            &account_id,
            token_data.next_cursor as i64,
            token_data.high_watermark as i64,
            session_page_size as i64,
            is_full_snapshot,
        )
        .await?;

        let (done, page_cursor, next_cursor) = if page_items.len() < session_page_size as usize
            || page_items
                .last()
                .map(|i| i.seq)
                .unwrap_or(token_data.next_cursor)
                >= token_data.high_watermark
        {
            (true, token_data.high_watermark, token_data.high_watermark)
        } else {
            let last_seq = page_items
                .last()
                .map(|i| i.seq)
                .unwrap_or(token_data.next_cursor);
            (false, last_seq, last_seq)
        };

        sqlx::query(
            "UPDATE sync_sessions SET page_position = $2, current_cursor = $3, is_completed = $4 WHERE session_id = $1",
        )
        .bind(token_data.session_id)
        .bind(token_data.page_number as i32)
        .bind(page_cursor as i64)
        .bind(done)
        .execute(&mut *tx)
        .await?;

        let receipt_str = encode_page_receipt(
            &state.token_hmac_key,
            &account_id,
            &device_id,
            &PageReceiptData {
                rv: 1,
                session_id: token_data.session_id,
                page_number: token_data.page_number,
                terminal_seq: page_cursor,
            },
        )?;

        let continuation_token = if done {
            None
        } else {
            Some(encode_continuation_token(
                &state.token_hmac_key,
                &account_id,
                &device_id,
                &ContinuationTokenData {
                    tkv: 1,
                    epoch: state.deployment_epoch,
                    session_id: token_data.session_id,
                    page_number: token_data.page_number + 1,
                    high_watermark: token_data.high_watermark,
                    next_cursor,
                    expiry_unix: token_data.expiry_unix,
                },
            )?)
        };

        tx.commit().await?;

        return Ok(Json(PullPage {
            sync_session_id: token_data.session_id.to_string(),
            items: page_items,
            high_watermark: token_data.high_watermark,
            page_cursor,
            done,
            page_receipt: receipt_str,
            continuation_token,
        }));
    }

    // New session branch:
    let checkpoint = request.checkpoint.unwrap_or(0);
    let page_size = request
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);

    let mut tx = state.database.begin().await?;

    // Lock device row only (never accounts).
    let device_row = sqlx::query(
        "SELECT last_seen_seq, (revoked_at IS NOT NULL) AS is_revoked FROM devices WHERE account_id = $1 AND device_id = $2 FOR UPDATE",
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
    let last_seen_seq: i64 = device_row.try_get("last_seen_seq")?;

    // Plain committed read of accounts (lock-free capture of high watermark H).
    let account_row = sqlx::query(
        "SELECT seq_counter, tombstone_floor_seq, change_floor_seq, status FROM accounts WHERE account_id = $1",
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

    let high_watermark: i64 = account_row.try_get("seq_counter")?;
    let tombstone_floor: i64 = account_row.try_get("tombstone_floor_seq")?;
    let change_floor: i64 = account_row.try_get("change_floor_seq")?;

    let is_full_snapshot = checkpoint == 0;
    if !is_full_snapshot {
        if (checkpoint as i64) < tombstone_floor || (checkpoint as i64) < change_floor {
            return Err(AppError::ResyncRequired);
        }
        if checkpoint != last_seen_seq as u64 {
            return Err(AppError::InvalidInput);
        }
    }

    // Abandon any prior incomplete session for this device.
    sqlx::query(
        "UPDATE sync_sessions SET is_abandoned = TRUE \
         WHERE account_id = $1 AND device_id = $2 AND is_completed = FALSE AND is_abandoned = FALSE",
    )
    .bind(&account_id)
    .bind(device_id)
    .execute(&mut *tx)
    .await?;

    let session_id = Uuid::new_v4();
    let expiry_unix = now_unix + SESSION_TTL_SECONDS;

    let page_items = fetch_page_items(
        &mut tx,
        &account_id,
        checkpoint as i64,
        high_watermark,
        page_size,
        is_full_snapshot,
    )
    .await?;

    let (done, page_cursor, next_cursor) = if (checkpoint as i64) >= high_watermark
        || page_items.len() < page_size as usize
        || page_items.last().map(|i| i.seq).unwrap_or(checkpoint) >= high_watermark as u64
    {
        (true, high_watermark as u64, high_watermark as u64)
    } else {
        let last_seq = page_items.last().map(|i| i.seq).unwrap_or(checkpoint);
        (false, last_seq, last_seq)
    };

    sqlx::query(
        "INSERT INTO sync_sessions ( \
             session_id, account_id, device_id, deployment_epoch, high_watermark, \
             current_cursor, page_size, page_position, acknowledged_page, is_full_snapshot, \
             is_completed, is_abandoned, created_at, expires_at \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, 0, $8, $9, FALSE, now(), now() + interval '24 hours')",
    )
    .bind(session_id)
    .bind(&account_id)
    .bind(device_id)
    .bind(state.deployment_epoch as i64)
    .bind(high_watermark)
    .bind(page_cursor as i64)
    .bind(page_size as i32)
    .bind(is_full_snapshot)
    .bind(done)
    .execute(&mut *tx)
    .await?;

    let receipt_str = encode_page_receipt(
        &state.token_hmac_key,
        &account_id,
        &device_id,
        &PageReceiptData {
            rv: 1,
            session_id,
            page_number: 1,
            terminal_seq: page_cursor,
        },
    )?;

    let continuation_token = if done {
        None
    } else {
        Some(encode_continuation_token(
            &state.token_hmac_key,
            &account_id,
            &device_id,
            &ContinuationTokenData {
                tkv: 1,
                epoch: state.deployment_epoch,
                session_id,
                page_number: 2,
                high_watermark: high_watermark as u64,
                next_cursor,
                expiry_unix,
            },
        )?)
    };

    tx.commit().await?;

    Ok(Json(PullPage {
        sync_session_id: session_id.to_string(),
        items: page_items,
        high_watermark: high_watermark as u64,
        page_cursor,
        done,
        page_receipt: receipt_str,
        continuation_token,
    }))
}

pub async fn handle_sync_ack(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<AckRequest>,
) -> Result<Json<AckResponse>, AppError> {
    if principal.kind != PrincipalKind::Device || principal.device_id.is_none() {
        return Err(AppError::InvalidSignature);
    }
    let device_id = principal.device_id.ok_or(AppError::InvalidSignature)?;
    let account_id = principal.account_id;

    let receipt_data = decode_page_receipt(
        &state.token_hmac_key,
        &account_id,
        &device_id,
        &request.page_receipt,
    )?;

    if receipt_data.session_id.to_string() != request.sync_session_id
        || receipt_data.terminal_seq != request.terminal_seq
    {
        return Err(AppError::InvalidInput);
    }

    let mut tx = state.database.begin().await?;

    // Lock device row.
    let device_row = sqlx::query(
        "SELECT last_seen_seq, (revoked_at IS NOT NULL) AS is_revoked FROM devices WHERE account_id = $1 AND device_id = $2 FOR UPDATE",
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
    let mut last_seen_seq: i64 = device_row.try_get("last_seen_seq")?;

    let session_row = sqlx::query(
        "SELECT high_watermark, page_position, acknowledged_page, is_full_snapshot, is_completed, is_abandoned, expires_at \
         FROM sync_sessions \
         WHERE session_id = $1 AND account_id = $2 AND device_id = $3 \
         FOR UPDATE",
    )
    .bind(receipt_data.session_id)
    .bind(&account_id)
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(session_row) = session_row else {
        return Err(AppError::Conflict);
    };

    let is_abandoned: bool = session_row.try_get("is_abandoned")?;
    if is_abandoned {
        return Err(AppError::Conflict);
    }

    let acknowledged_page: i32 = session_row.try_get("acknowledged_page")?;
    let is_full_snapshot: bool = session_row.try_get("is_full_snapshot")?;
    let high_watermark: i64 = session_row.try_get("high_watermark")?;

    if receipt_data.page_number == acknowledged_page as u32 {
        // Idempotent retry of current acknowledged receipt
        return Ok(Json(AckResponse {
            status: "duplicate".to_string(),
            last_seen_seq: last_seen_seq as u64,
        }));
    }

    if receipt_data.page_number != (acknowledged_page + 1) as u32 {
        // Out of order page acknowledgement!
        return Err(AppError::Conflict);
    }

    sqlx::query(
        "UPDATE sync_sessions SET acknowledged_page = $2, last_acknowledged_receipt = $3 WHERE session_id = $1",
    )
    .bind(receipt_data.session_id)
    .bind(receipt_data.page_number as i32)
    .bind(&request.page_receipt)
    .execute(&mut *tx)
    .await?;

    if !is_full_snapshot {
        if (request.terminal_seq as i64) > last_seen_seq {
            last_seen_seq = request.terminal_seq as i64;
            sqlx::query(
                "UPDATE devices SET last_seen_seq = $3 WHERE account_id = $1 AND device_id = $2",
            )
            .bind(&account_id)
            .bind(device_id)
            .bind(last_seen_seq)
            .execute(&mut *tx)
            .await?;
        }
    } else {
        // For full snapshot, advance last_seen_seq and set first_sync_at ONLY on the final completed page.
        let is_completed: bool = session_row.try_get("is_completed")?;
        if is_completed && request.terminal_seq as i64 == high_watermark {
            last_seen_seq = high_watermark;
            sqlx::query(
                "UPDATE devices SET last_seen_seq = $3, first_sync_at = COALESCE(first_sync_at, now()) \
                 WHERE account_id = $1 AND device_id = $2",
            )
            .bind(&account_id)
            .bind(device_id)
            .bind(last_seen_seq)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;

    Ok(Json(AckResponse {
        status: "accepted".to_string(),
        last_seen_seq: last_seen_seq as u64,
    }))
}

async fn fetch_page_items(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &[u8],
    cursor: i64,
    high_watermark: i64,
    limit: i64,
    is_full_snapshot: bool,
) -> Result<Vec<ItemState>, AppError> {
    if cursor >= high_watermark {
        return Ok(Vec::new());
    }

    let rows = sqlx::query(
        "WITH page_seqs AS ( \
             SELECT seq, item_id \
             FROM item_changes \
             WHERE account_id = $1 AND seq > $2 AND seq <= $3 \
             ORDER BY seq ASC \
             LIMIT $4 \
         ) \
         SELECT c.item_id, c.version, c.seq, c.deleted, c.key_version, c.blob, \
                to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS updated_at \
         FROM ( \
             SELECT DISTINCT item_id FROM page_seqs \
         ) items_in_page \
         CROSS JOIN LATERAL ( \
             SELECT item_id, version, seq, deleted, key_version, blob, created_at \
             FROM item_changes \
             WHERE account_id = $1 AND item_id = items_in_page.item_id AND seq <= $3 \
             ORDER BY seq DESC \
             LIMIT 1 \
         ) c \
         ORDER BY c.seq ASC",
    )
    .bind(account_id)
    .bind(cursor)
    .bind(high_watermark)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let deleted: bool = row.try_get("deleted")?;
        if is_full_snapshot && deleted {
            // Full snapshots omit tombstones entirely.
            continue;
        }

        let item_id: Uuid = row.try_get("item_id")?;
        let version: i64 = row.try_get("version")?;
        let seq: i64 = row.try_get("seq")?;
        let key_version: i64 = row.try_get("key_version")?;
        let blob: Option<Vec<u8>> = row.try_get("blob")?;
        let updated_at: String = row.try_get("updated_at")?;

        let (kv_opt, blob_opt) = if deleted {
            (None, None)
        } else {
            (
                Some(key_version as u64),
                blob.map(|b| URL_SAFE_NO_PAD.encode(b)),
            )
        };

        items.push(ItemState {
            item_id: item_id.to_string(),
            version: version as u64,
            seq: seq as u64,
            deleted,
            key_version: kv_opt,
            blob: blob_opt,
            updated_at,
        });
    }

    Ok(items)
}
