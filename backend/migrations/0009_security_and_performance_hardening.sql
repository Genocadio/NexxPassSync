-- Migration 0009: Indexes for history pruning, device lifecycle sweeps, and relay account binding

CREATE INDEX IF NOT EXISTS idx_devices_inactive_sweep
    ON devices (last_seen_at)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_devices_unsynced_sweep
    ON devices (created_at)
    WHERE first_sync_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_item_changes_account_seq
    ON item_changes (account_id, seq);

CREATE INDEX IF NOT EXISTS idx_pairing_relays_account_device
    ON pairing_relays (account_id, device_id);
