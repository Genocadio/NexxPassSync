CREATE TABLE accounts (
    account_id BYTEA PRIMARY KEY CHECK (octet_length(account_id) = 32),
    identity_ed25519_pub BYTEA NOT NULL CHECK (octet_length(identity_ed25519_pub) = 32),
    identity_x25519_pub BYTEA NOT NULL CHECK (octet_length(identity_x25519_pub) = 32),
    derivation_version SMALLINT NOT NULL CHECK (derivation_version > 0),
    seq_counter BIGINT NOT NULL DEFAULT 0 CHECK (seq_counter >= 0),
    tombstone_floor_seq BIGINT NOT NULL DEFAULT 0 CHECK (tombstone_floor_seq >= 0),
    change_floor_seq BIGINT NOT NULL DEFAULT 0 CHECK (change_floor_seq >= 0),
    active_key_version BIGINT NOT NULL DEFAULT 1 CHECK (active_key_version > 0),
    next_key_version BIGINT NOT NULL DEFAULT 2 CHECK (next_key_version > active_key_version),
    keyring_version BIGINT NOT NULL DEFAULT 1 CHECK (keyring_version > 0),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'identity_locked', 'deletion_pending', 'suspended')),
    deletion_requested_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    account_id BYTEA NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    device_ed25519_pub BYTEA NOT NULL CHECK (octet_length(device_ed25519_pub) = 32),
    device_x25519_pub BYTEA NOT NULL CHECK (octet_length(device_x25519_pub) = 32),
    device_label TEXT NOT NULL CHECK (char_length(device_label) BETWEEN 1 AND 100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_sync_at TIMESTAMPTZ,
    last_seen_seq BIGINT NOT NULL DEFAULT 0 CHECK (last_seen_seq >= 0),
    issued_through BIGINT NOT NULL DEFAULT 0 CHECK (issued_through >= 0),
    acked_key_version BIGINT,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    PRIMARY KEY (account_id, device_id)
);

CREATE TABLE key_wraps (
    account_id BYTEA NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    recipient TEXT NOT NULL,
    wrap BYTEA NOT NULL CHECK (octet_length(wrap) = 105),
    status TEXT NOT NULL CHECK (status IN ('active', 'pending')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, key_version, recipient)
);

CREATE TABLE deleted_accounts (
    account_id BYTEA PRIMARY KEY CHECK (octet_length(account_id) = 32),
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE request_nonces (
    principal_id BYTEA NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 16),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (principal_id, nonce)
);

CREATE INDEX request_nonces_expiry_idx ON request_nonces (expires_at);
