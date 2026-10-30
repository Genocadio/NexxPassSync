CREATE TABLE attachment_blobs (
    account_id BYTEA NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    record_id UUID NOT NULL,
    attachment_id UUID NOT NULL,
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    blob BYTEA NOT NULL CHECK (
        octet_length(blob) BETWEEN 41 AND 10551296
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, attachment_id),
    UNIQUE (account_id, record_id, attachment_id)
);

CREATE INDEX attachment_blobs_record_idx
    ON attachment_blobs (account_id, record_id);
