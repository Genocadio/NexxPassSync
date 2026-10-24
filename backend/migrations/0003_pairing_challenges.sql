CREATE TABLE pairing_challenges (
    pairing_id UUID PRIMARY KEY,
    target_account_id BYTEA NOT NULL CHECK (octet_length(target_account_id) = 32),
    device_id UUID NOT NULL,
    device_pub_digest BYTEA NOT NULL CHECK (octet_length(device_pub_digest) = 32),
    device_label TEXT NOT NULL CHECK (char_length(device_label) BETWEEN 1 AND 100),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'consumed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX pairing_challenges_pending_idx
    ON pairing_challenges (target_account_id, created_at DESC)
    WHERE status = 'pending';

CREATE INDEX pairing_challenges_expiry_idx ON pairing_challenges (expires_at);
