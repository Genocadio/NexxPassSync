CREATE TABLE items (
    account_id BYTEA NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    item_id UUID NOT NULL,
    blob BYTEA,
    key_version BIGINT NOT NULL DEFAULT 0 CHECK (key_version >= 0),
    version BIGINT NOT NULL CHECK (version > 0),
    seq BIGINT NOT NULL CHECK (seq > 0),
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, item_id),
    CONSTRAINT items_payload_check CHECK (
        (deleted = FALSE AND blob IS NOT NULL AND octet_length(blob) BETWEEN 552 AND 65536 AND key_version > 0)
        OR
        (deleted = TRUE AND blob IS NULL AND key_version = 0)
    )
);

CREATE INDEX items_account_seq_idx ON items (account_id, seq);

CREATE TABLE item_changes (
    account_id BYTEA NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    seq BIGINT NOT NULL CHECK (seq > 0),
    item_id UUID NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    key_version BIGINT NOT NULL CHECK (key_version >= 0),
    blob BYTEA,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, seq),
    UNIQUE (account_id, item_id, version),
    CONSTRAINT item_changes_payload_check CHECK (
        (deleted = FALSE AND blob IS NOT NULL AND octet_length(blob) BETWEEN 552 AND 65536 AND key_version > 0)
        OR
        (deleted = TRUE AND blob IS NULL AND key_version = 0)
    )
);

CREATE INDEX item_changes_lookup_idx ON item_changes (account_id, item_id, version DESC);

CREATE TABLE retired_item_ids (
    account_id BYTEA NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    item_id UUID NOT NULL,
    retired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, item_id)
);

CREATE TABLE operations (
    account_id BYTEA NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    operation_id UUID NOT NULL,
    op_hash BYTEA NOT NULL CHECK (octet_length(op_hash) = 32),
    status TEXT NOT NULL CHECK (status IN ('applied', 'duplicate')),
    item_version BIGINT CHECK (item_version > 0),
    seq BIGINT CHECK (seq > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, operation_id)
);

CREATE INDEX operations_retention_idx ON operations (created_at);
