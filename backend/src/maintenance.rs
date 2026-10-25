use sqlx::{PgPool, Row};
use uuid::Uuid;

pub const MAINTENANCE_ADVISORY_LOCK_ID: i64 = 0x4e65_7878_5061_7373;

/// Runs all periodic maintenance jobs across the database.
/// Ensures single-runner execution across distributed instances via a Postgres advisory lock.
pub async fn run_maintenance(pool: &PgPool) -> Result<Option<MaintenanceStats>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    let lock_acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(MAINTENANCE_ADVISORY_LOCK_ID)
        .fetch_one(&mut *conn)
        .await?;

    if !lock_acquired {
        tracing::info!("maintenance advisory lock held by another instance; skipping run");
        return Ok(None);
    }

    let stats_res = execute_maintenance(pool).await;

    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(MAINTENANCE_ADVISORY_LOCK_ID)
        .execute(&mut *conn)
        .await;

    stats_res.map(Some)
}

async fn execute_maintenance(pool: &PgPool) -> Result<MaintenanceStats, sqlx::Error> {
    Ok(MaintenanceStats {
        expired_cleaned: cleanup_expired_records(pool).await?,
        deadlines_enforced: enforce_rotation_deadlines(pool).await?,
        unsynced_revoked: revoke_never_synced_devices(pool).await?,
        inactive_revoked: revoke_inactive_devices(pool).await?,
        tombstones_pruned: prune_tombstones(pool).await?,
        accounts_purged: purge_deleted_accounts(pool).await?,
    })
}

#[derive(Default, Debug, Clone, Copy)]
pub struct MaintenanceStats {
    pub expired_cleaned: u64,
    pub deadlines_enforced: u64,
    pub unsynced_revoked: u64,
    pub inactive_revoked: u64,
    pub tombstones_pruned: u64,
    pub accounts_purged: u64,
}

/// Purges expired nonces, expired pairing challenges, expired sync sessions,
/// operations older than 30 days, and account events older than 90 days.
pub async fn cleanup_expired_records(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let mut total = 0;

    let res = sqlx::query("DELETE FROM request_nonces WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    total += res.rows_affected();

    let res =
        sqlx::query("DELETE FROM pairing_challenges WHERE expires_at < now() - interval '1 hour'")
            .execute(pool)
            .await?;
    total += res.rows_affected();

    let res = sqlx::query("DELETE FROM sync_sessions WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    total += res.rows_affected();

    let res = sqlx::query("DELETE FROM operations WHERE created_at < now() - interval '30 days'")
        .execute(pool)
        .await?;
    total += res.rows_affected();

    let res =
        sqlx::query("DELETE FROM account_events WHERE created_at < now() - interval '90 days'")
            .execute(pool)
            .await?;
    total += res.rows_affected();

    Ok(total)
}

/// Enforces rotation deadlines.
/// - routine: if deadline passed and lease expired: auto-aborts if abortable, else clears lease.
/// - compromise: if deadline passed: revokes every unacknowledged device.
pub async fn enforce_rotation_deadlines(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT account_id FROM accounts \
         WHERE rotation_mode <> 'idle' AND rotation_deadline < now()",
    )
    .fetch_all(pool)
    .await?;

    let mut count = 0;
    for row in rows {
        let account_id: Vec<u8> = row.try_get("account_id")?;
        let mut tx = pool.begin().await?;

        let acct = sqlx::query(
            "SELECT rotation_mode, rotation_target_key_version, rotation_owner_device_id, \
                    (rotation_lease_expires_at <= now()) AS lease_expired \
             FROM accounts WHERE account_id = $1 FOR UPDATE",
        )
        .bind(&account_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(acct) = acct else {
            continue;
        };

        let mode: String = acct.try_get("rotation_mode")?;
        let target_key_version: Option<i64> = acct.try_get("rotation_target_key_version")?;
        let lease_expired: Option<bool> = acct.try_get("lease_expired")?;

        if mode == "routine" && lease_expired == Some(true) {
            if let Some(target_kv) = target_key_version {
                // Check if abortable.
                let target_items: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM items WHERE account_id = $1 AND key_version = $2",
                )
                .bind(&account_id)
                .bind(target_kv)
                .fetch_one(&mut *tx)
                .await?;

                let acks: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM rotation_participants \
                     WHERE account_id = $1 AND key_version = $2 AND key_acknowledged_at IS NOT NULL",
                )
                .bind(&account_id)
                .bind(target_kv)
                .fetch_one(&mut *tx)
                .await?;

                if target_items == 0 && acks == 0 {
                    // Auto-abort.
                    sqlx::query("DELETE FROM key_wraps WHERE account_id = $1 AND key_version = $2")
                        .bind(&account_id)
                        .bind(target_kv)
                        .execute(&mut *tx)
                        .await?;

                    sqlx::query(
                        "DELETE FROM rotation_participants WHERE account_id = $1 AND key_version = $2",
                    )
                    .bind(&account_id)
                    .bind(target_kv)
                    .execute(&mut *tx)
                    .await?;

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
                    .bind(&account_id)
                    .execute(&mut *tx)
                    .await?;

                    let event_id = Uuid::now_v7();
                    sqlx::query(
                        "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
                         VALUES ($1, $2, 'rotation_aborted', 'identity', NULL)",
                    )
                    .bind(&account_id)
                    .bind(event_id)
                    .execute(&mut *tx)
                    .await?;
                } else {
                    // Clear lease so any active device can resume.
                    sqlx::query(
                        "UPDATE accounts SET \
                             rotation_owner_device_id = NULL, \
                             rotation_lease_expires_at = NULL \
                         WHERE account_id = $1",
                    )
                    .bind(&account_id)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            count += 1;
        } else if mode == "compromise" {
            if let Some(target_kv) = target_key_version {
                // Revoke every unacknowledged device.
                let unacked_devs = sqlx::query(
                    "SELECT device_id FROM rotation_participants \
                     WHERE account_id = $1 AND key_version = $2 AND revoked_at IS NULL AND key_acknowledged_at IS NULL",
                )
                .bind(&account_id)
                .bind(target_kv)
                .fetch_all(&mut *tx)
                .await?;

                for dev_row in unacked_devs {
                    let dev_id: Uuid = dev_row.try_get("device_id")?;
                    sqlx::query(
                        "UPDATE devices SET revoked_at = now(), revoked_reason = 'rotation_unacknowledged_timeout' \
                         WHERE account_id = $1 AND device_id = $2",
                    )
                    .bind(&account_id)
                    .bind(dev_id)
                    .execute(&mut *tx)
                    .await?;

                    sqlx::query("DELETE FROM key_wraps WHERE account_id = $1 AND recipient = $2")
                        .bind(&account_id)
                        .bind(dev_id.to_string())
                        .execute(&mut *tx)
                        .await?;

                    sqlx::query(
                        "UPDATE rotation_participants SET revoked_at = now() \
                         WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
                    )
                    .bind(&account_id)
                    .bind(dev_id)
                    .execute(&mut *tx)
                    .await?;

                    sqlx::query(
                        "DELETE FROM sync_sessions WHERE account_id = $1 AND device_id = $2",
                    )
                    .bind(&account_id)
                    .bind(dev_id)
                    .execute(&mut *tx)
                    .await?;

                    let event_id = Uuid::now_v7();
                    sqlx::query(
                        "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
                         VALUES ($1, $2, 'device_revoked', 'identity', NULL)",
                    )
                    .bind(&account_id)
                    .bind(event_id)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            count += 1;
        }

        tx.commit().await?;
    }

    Ok(count)
}

/// Revokes devices that never complete first sync after 14 days.
/// (The account's first device is exempt: its first_sync_at is set at registration).
pub async fn revoke_never_synced_devices(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let un_synced = sqlx::query(
        "SELECT account_id, device_id FROM devices \
         WHERE first_sync_at IS NULL \
           AND created_at < now() - interval '14 days' \
           AND revoked_at IS NULL",
    )
    .fetch_all(pool)
    .await?;

    let mut count = 0;
    for row in un_synced {
        let account_id: Vec<u8> = row.try_get("account_id")?;
        let device_id: Uuid = row.try_get("device_id")?;

        let mut tx = pool.begin().await?;

        // Lock account row first.
        let _acct = sqlx::query("SELECT 1 FROM accounts WHERE account_id = $1 FOR UPDATE")
            .bind(&account_id)
            .fetch_optional(&mut *tx)
            .await?;

        sqlx::query(
            "UPDATE devices SET revoked_at = now(), revoked_reason = 'un_synced_timeout' \
             WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
        .bind(&account_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM key_wraps WHERE account_id = $1 AND recipient = $2")
            .bind(&account_id)
            .bind(device_id.to_string())
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "UPDATE rotation_participants SET revoked_at = now() \
             WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
        .bind(&account_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE accounts SET rotation_owner_device_id = NULL, rotation_lease_expires_at = NULL \
             WHERE account_id = $1 AND rotation_owner_device_id = $2",
        )
        .bind(&account_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM sync_sessions WHERE account_id = $1 AND device_id = $2")
            .bind(&account_id)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;

        let event_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
             VALUES ($1, $2, 'device_revoked', 'identity', NULL)",
        )
        .bind(&account_id)
        .bind(event_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        count += 1;
    }

    Ok(count)
}

/// Revokes inactive devices after 180 days, except the account's last active device.
pub async fn revoke_inactive_devices(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let accounts = sqlx::query("SELECT account_id FROM accounts")
        .fetch_all(pool)
        .await?;

    let mut revoked_count = 0;
    for acct_row in accounts {
        let account_id: Vec<u8> = acct_row.try_get("account_id")?;
        let mut tx = pool.begin().await?;

        let _ = sqlx::query("SELECT 1 FROM accounts WHERE account_id = $1 FOR UPDATE")
            .bind(&account_id)
            .fetch_optional(&mut *tx)
            .await?;

        let active_devices = sqlx::query(
            "SELECT device_id, last_seen_at FROM devices \
             WHERE account_id = $1 AND revoked_at IS NULL \
             ORDER BY last_seen_at ASC",
        )
        .bind(&account_id)
        .fetch_all(&mut *tx)
        .await?;

        // If 1 or 0 active devices, skip revoking (never revoke the last active device).
        if active_devices.len() <= 1 {
            continue;
        }

        let mut remaining_active = active_devices.len();
        for dev in active_devices {
            if remaining_active <= 1 {
                break;
            }
            let dev_id: Uuid = dev.try_get("device_id")?;
            let is_stale: bool = sqlx::query_scalar(
                "SELECT (last_seen_at < now() - interval '180 days') FROM devices \
                 WHERE account_id = $1 AND device_id = $2",
            )
            .bind(&account_id)
            .bind(dev_id)
            .fetch_one(&mut *tx)
            .await?;

            if is_stale {
                sqlx::query(
                    "UPDATE devices SET revoked_at = now(), revoked_reason = 'inactivity_timeout' \
                     WHERE account_id = $1 AND device_id = $2",
                )
                .bind(&account_id)
                .bind(dev_id)
                .execute(&mut *tx)
                .await?;

                sqlx::query("DELETE FROM key_wraps WHERE account_id = $1 AND recipient = $2")
                    .bind(&account_id)
                    .bind(dev_id.to_string())
                    .execute(&mut *tx)
                    .await?;

                sqlx::query(
                    "UPDATE rotation_participants SET revoked_at = now() \
                     WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
                )
                .bind(&account_id)
                .bind(dev_id)
                .execute(&mut *tx)
                .await?;

                sqlx::query("DELETE FROM sync_sessions WHERE account_id = $1 AND device_id = $2")
                    .bind(&account_id)
                    .bind(dev_id)
                    .execute(&mut *tx)
                    .await?;

                let event_id = Uuid::now_v7();
                sqlx::query(
                    "INSERT INTO account_events (account_id, event_id, event_type, actor, actor_device_id) \
                     VALUES ($1, $2, 'device_revoked', 'identity', NULL)",
                )
                .bind(&account_id)
                .bind(event_id)
                .execute(&mut *tx)
                .await?;

                remaining_active -= 1;
                revoked_count += 1;
            }
        }

        tx.commit().await?;
    }

    Ok(revoked_count)
}

/// Prunes tombstones older than 90 days and <= min active device checkpoint.
/// Advances `tombstone_floor_seq` to the max purged tombstone sequence.
pub async fn prune_tombstones(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let accounts = sqlx::query("SELECT account_id FROM accounts")
        .fetch_all(pool)
        .await?;

    let mut total_purged = 0;
    for acct_row in accounts {
        let account_id: Vec<u8> = acct_row.try_get("account_id")?;
        let mut tx = pool.begin().await?;

        let _ = sqlx::query("SELECT 1 FROM accounts WHERE account_id = $1 FOR UPDATE")
            .bind(&account_id)
            .fetch_optional(&mut *tx)
            .await?;

        // Find min active device checkpoint.
        let min_checkpoint_row = sqlx::query(
            "SELECT MIN(last_seen_seq) AS min_cp, COUNT(*) AS active_count \
             FROM devices WHERE account_id = $1 AND revoked_at IS NULL",
        )
        .bind(&account_id)
        .fetch_one(&mut *tx)
        .await?;

        let active_count: i64 = min_checkpoint_row.try_get("active_count")?;
        if active_count == 0 {
            continue;
        }
        let min_cp: Option<i64> = min_checkpoint_row.try_get("min_cp")?;
        let Some(min_cp) = min_cp else {
            continue;
        };

        // Find eligible tombstones to delete.
        let purged_seqs: Vec<i64> = sqlx::query_scalar(
            "DELETE FROM items \
             WHERE account_id = $1 \
               AND deleted = TRUE \
               AND updated_at < now() - interval '90 days' \
               AND seq <= $2 \
             RETURNING seq",
        )
        .bind(&account_id)
        .bind(min_cp)
        .fetch_all(&mut *tx)
        .await?;

        if !purged_seqs.is_empty() {
            let max_purged_seq = purged_seqs.into_iter().max().unwrap_or(0);
            sqlx::query(
                "UPDATE accounts \
                 SET tombstone_floor_seq = GREATEST(tombstone_floor_seq, $2) \
                 WHERE account_id = $1",
            )
            .bind(&account_id)
            .bind(max_purged_seq)
            .execute(&mut *tx)
            .await?;

            total_purged += 1;
        }

        tx.commit().await?;
    }

    Ok(total_purged)
}

/// Hard-purges accounts whose 30-day deletion grace period has ended.
/// Writes account_id into `deleted_accounts` permanently, and deletes the account.
pub async fn purge_deleted_accounts(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let pending_accounts = sqlx::query(
        "SELECT account_id FROM accounts \
         WHERE status = 'deletion_pending' \
           AND deletion_requested_at < now() - interval '30 days'",
    )
    .fetch_all(pool)
    .await?;

    let mut purged = 0;
    for row in pending_accounts {
        let account_id: Vec<u8> = row.try_get("account_id")?;
        let mut tx = pool.begin().await?;

        let _ = sqlx::query("SELECT 1 FROM accounts WHERE account_id = $1 FOR UPDATE")
            .bind(&account_id)
            .fetch_optional(&mut *tx)
            .await?;

        sqlx::query(
            "INSERT INTO deleted_accounts (account_id, deleted_at) \
             VALUES ($1, now()) \
             ON CONFLICT (account_id) DO NOTHING",
        )
        .bind(&account_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM accounts WHERE account_id = $1")
            .bind(&account_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        purged += 1;
    }

    Ok(purged)
}
