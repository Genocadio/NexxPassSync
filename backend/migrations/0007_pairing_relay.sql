CREATE TABLE IF NOT EXISTS pairing_relays (
    device_id UUID PRIMARY KEY,
    account_id BYTEA NOT NULL,
    encrypted_payload TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '10 minutes')
);

CREATE INDEX IF NOT EXISTS pairing_relays_expiry_idx ON pairing_relays (expires_at);
