ALTER TABLE accounts
    ADD COLUMN rotation_mode TEXT NOT NULL DEFAULT 'idle'
        CHECK (rotation_mode IN ('idle', 'routine', 'compromise', 'master_password_change')),
    ADD COLUMN rotation_target_key_version BIGINT,
    ADD COLUMN rotation_owner_device_id UUID,
    ADD COLUMN rotation_lease_expires_at TIMESTAMPTZ,
    ADD COLUMN rotation_deadline TIMESTAMPTZ,
    ADD COLUMN rotation_started_at TIMESTAMPTZ,
    ADD CONSTRAINT accounts_rotation_target_check
        CHECK (rotation_target_key_version IS NULL OR rotation_target_key_version > active_key_version),
    ADD CONSTRAINT accounts_rotation_state_check
        CHECK (
            (rotation_mode = 'idle' AND rotation_target_key_version IS NULL
                AND rotation_owner_device_id IS NULL AND rotation_lease_expires_at IS NULL
                AND rotation_deadline IS NULL AND rotation_started_at IS NULL)
            OR
            (rotation_mode <> 'idle' AND rotation_target_key_version IS NOT NULL)
        );

ALTER TABLE accounts
    ADD CONSTRAINT accounts_rotation_owner_fk
    FOREIGN KEY (account_id, rotation_owner_device_id)
    REFERENCES devices (account_id, device_id);

CREATE TABLE rotation_participants (
    account_id BYTEA NOT NULL,
    key_version BIGINT NOT NULL CHECK (key_version > 1),
    device_id UUID NOT NULL,
    key_acknowledged_at TIMESTAMPTZ,
    local_master_password_updated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, key_version, device_id),
    FOREIGN KEY (account_id) REFERENCES accounts (account_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, device_id) REFERENCES devices (account_id, device_id)
);

CREATE INDEX rotation_participants_pending_idx
    ON rotation_participants (account_id, key_version)
    WHERE revoked_at IS NULL AND key_acknowledged_at IS NULL;

CREATE TABLE account_events (
    account_id BYTEA NOT NULL REFERENCES accounts (account_id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'device_paired',
        'device_registered_via_recovery',
        'recovery_wraps_read',
        'device_revoked',
        'rotation_started',
        'rotation_completed',
        'rotation_aborted',
        'identity_locked',
        'identity_migrated',
        'deletion_requested',
        'deletion_cancelled',
        'history_cap_prune'
    )),
    actor TEXT NOT NULL CHECK (actor IN ('device', 'identity')),
    actor_device_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, event_id),
    FOREIGN KEY (account_id, actor_device_id) REFERENCES devices (account_id, device_id),
    CHECK ((actor = 'device' AND actor_device_id IS NOT NULL)
        OR (actor = 'identity' AND actor_device_id IS NULL))
);

CREATE INDEX account_events_recent_idx
    ON account_events (account_id, created_at DESC);
