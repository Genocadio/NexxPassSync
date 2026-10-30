ALTER TABLE item_changes
    ADD COLUMN delete_proof BYTEA;

ALTER TABLE item_changes
    ADD CONSTRAINT item_changes_delete_proof_check CHECK (
        (deleted = TRUE AND (delete_proof IS NULL OR octet_length(delete_proof) = 64))
        OR
        (deleted = FALSE AND delete_proof IS NULL)
    );
