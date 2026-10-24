CREATE TABLE sync_sessions (
    session_id UUID PRIMARY KEY,
    account_id BYTEA NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    deployment_epoch BIGINT NOT NULL DEFAULT 1 CHECK (deployment_epoch > 0),
    high_watermark BIGINT NOT NULL CHECK (high_watermark >= 0),
    current_cursor BIGINT NOT NULL CHECK (current_cursor >= 0),
    page_size INTEGER NOT NULL DEFAULT 100 CHECK (page_size > 0),
    page_position INTEGER NOT NULL DEFAULT 1 CHECK (page_position >= 1),
    acknowledged_page INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged_page >= 0),
    last_acknowledged_receipt TEXT,
    is_full_snapshot BOOLEAN NOT NULL,
    is_completed BOOLEAN NOT NULL DEFAULT FALSE,
    is_abandoned BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, device_id) ON DELETE CASCADE
);

CREATE INDEX sync_sessions_active_device_idx
    ON sync_sessions (account_id, device_id, created_at DESC)
    WHERE is_completed = FALSE AND is_abandoned = FALSE;

CREATE INDEX sync_sessions_expiry_idx ON sync_sessions (expires_at);
