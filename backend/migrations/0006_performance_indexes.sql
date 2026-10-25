-- Migration 0006: Partial indexes for rotation rewrites and tombstone pruning

CREATE INDEX IF NOT EXISTS idx_items_rotation_rewrite
    ON items (account_id, key_version)
    WHERE deleted = FALSE;

CREATE INDEX IF NOT EXISTS idx_items_tombstone_prune
    ON items (account_id, updated_at)
    WHERE deleted = TRUE;
