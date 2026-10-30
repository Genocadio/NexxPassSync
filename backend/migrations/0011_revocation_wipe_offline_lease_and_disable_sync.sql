-- Support for remote wipe proofs on device revocation, immediate vault purge
-- when disabling sync ('sync_disabled'), and 7-day offline lease metadata.

ALTER TABLE accounts
    DROP CONSTRAINT IF EXISTS accounts_status_check;

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS sync_disabled_at TIMESTAMPTZ,
    ADD CONSTRAINT accounts_status_check
        CHECK (status IN ('active', 'identity_locked', 'deletion_pending', 'suspended', 'sync_disabled'));

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS revoked_by_device_id UUID,
    ADD COLUMN IF NOT EXISTS revocation_proof BYTEA
        CHECK (revocation_proof IS NULL OR octet_length(revocation_proof) = 64);

ALTER TABLE account_events
    DROP CONSTRAINT IF EXISTS account_events_event_type_check;

ALTER TABLE account_events
    ADD CONSTRAINT account_events_event_type_check
        CHECK (event_type IN (
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
            'history_cap_prune',
            'sync_disabled'
        ));
