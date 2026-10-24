# Backend continuation plan

This is the developer handoff for continuing the NexxPass Sync backend. The
protocol source of truth remains `../zero-knowledge-sync-server-plan.md`,
`../../nexxpass/docs/crypto-spec.md`, and
`../../nexxpass/docs/openapi/sync-v1.yaml`. Update those documents when a
protocol decision changes; do not silently invent a second wire format here.

## Current state

The Rust/Axum/PostgreSQL service implements signed account registration,
authenticated `GET /v1/accounts/me`, request replay protection, device
pairing, and encrypted item batch mutations (`POST /v1/sync/batch`).

Milestone 0 and Milestone 1 are complete:
- Locked dependencies in `Cargo.lock` and `.github/workflows/ci.yml` providing automated CI checks across formatting (`cargo fmt --check`), strict clippy lints (`-D warnings`), protocol specification vectors (`tests/vectors.rs`), and end-to-end PostgreSQL integration testing (`tests/integration.rs`).
- Normative vectors from `protocol-v1.json` are verified directly: operation hash calculation for both `put` and `delete`, device public key digest calculation, and raw body signature canonicalization.
- Additive database migration `0004_items_and_sync_batch.sql` establishes `items`, immutable `item_changes`, permanent `retired_item_ids`, and `operations` with retention indexes and blob size constraints (552 to 65536 bytes).
- `/v1/sync/batch` handles up to 100 operations in request order under single account-row locking (`SELECT ... FOR UPDATE`), strictly rejects duplicate `operation_id` or `item_id` within a batch, validates key versions against rotation state and write-freeze (`master_password_change`), performs canonical binary `NPSOp1` operation hashing, provides exact retry idempotency, rejects operation ID reuse with changed payload (HTTP 422 `operation_id_reused`), and enforces monotonic version/sequence progression and permanent UUID retirement upon deletion.

The backend does not yet serve sync pulls, acknowledge checkpoints, or
implement recovery or key-rotation transitions. Milestone 2 (Snapshot and incremental
pull with acknowledgements) is the immediate next implementation priority.

## Working agreements

- Preserve zero knowledge: the server stores opaque ciphertext and wraps only.
  Never accept or log a master password, plaintext vault content, DEK, or
  decrypted recovery material.
- Follow the account-first lock order for every mutation. Re-check device
  revocation and account status inside the account-locked transaction.
- Keep request authentication over the exact raw body bytes. Parse only after
  signature verification where the existing route design permits it.
- Use additive SQL migrations. Do not edit migrations already applied to a
  database.
- Add unit tests for canonical encoding, mutation hashes, and state-machine
  decisions; add PostgreSQL integration tests for transaction, replay,
  idempotency, ordering, and concurrent-device behavior. Run `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, and `cargo test` when dependencies
  and PostgreSQL are available.
- Keep API behavior aligned with the protocol docs, and update OpenAPI and this
  plan in the same change as each endpoint.

## Milestones

### 0. Establish a repeatable test environment (Completed)

1. Add a locked dependency graph (`Cargo.lock`) and CI for formatting, clippy,
   unit tests, migrations, and PostgreSQL integration tests.
2. Add test fixtures for signed requests and deterministic UUID/key material.
   Keep production secrets out of fixtures and logs.
3. Add a disposable PostgreSQL test service and test that all migrations apply
   from an empty database and can be rerun safely through SQLx migration state.

**Done when:** CI runs offline/reproducibly after dependency caching, all
migrations apply in CI, and at least one successful and rejected signed request
is covered end to end.

### 1. Encrypted item writes and idempotency (Completed)

Implement `/v1/sync/batch` and the schema from plan §§4, 9, and 10 before pull
pages. Add `items`, immutable `item_changes`, permanent `retired_item_ids`, and
`operations` tables with the documented account-scoped keys and retention
indexes. Validate the full batch before mutation (≤100 operations, ≤1 MiB raw
body, ≤64 KiB decoded blob, unique item and operation IDs). Compute operation
hashes from canonical fields and decoded ciphertext, never JSON serialization.

Apply operations request-order under one account lock. Preserve operation
results for retries; distinguish reuse of an operation ID with a changed hash.
Implement base-version conflicts, tombstones, permanent item-ID retirement,
and the active-key/write-freeze checks. Store and return ciphertext unchanged.

**Done when:** repeated identical operations return the original result;
changed-operation-ID reuse is rejected; stale writes conflict; delete cannot
resurrect an item; accepted operations get monotonic versions and account
sequences atomically; and crash/rollback tests prove no partial mutation.

### 2. Snapshot and incremental pull with acknowledgements

Implement `/v1/sync/pull` and `/v1/sync/ack` using persisted sessions, fixed high
watermarks, server-issued page positions, continuation tokens, and one-use page
receipts as in plan §§7–8 and crypto spec §13. A page receipt is not a
checkpoint. Bind session and receipts to account, device, deployment epoch,
and expiry; allow only one active session per device. Reject incremental
checkpoints below retained floors and require a full snapshot from zero.

**Done when:** concurrent writes after the watermark appear only in a later
pull; pages cannot be skipped or acknowledged out of order; lost-response retry
behavior is covered; a full snapshot omits tombstones while incrementals return
them; and only a completed snapshot acknowledgement sets `first_sync_at`.

### 3. Device management and recovery

Implement recovery-wrap retrieval using identity-key signatures, recovery
device registration, device listing/revocation, and account events. Make
revocation transactional: stop future authentication, remove that device's
wraps, and exclude it from rotation participants and GC watermarks. Preserve
identity-lock behavior and prevent identity-signed recovery after a lock.

**Done when:** an account can recover on a fresh device using only client-side
recovery material; revoked devices cannot authenticate or receive wraps; and
recovery and revocation events are visible to all active devices.

### 4. Cross-device key and master-password rotation

Implement the complete state machine from plan §11; do not ship only a start
route. Required operations include start, lease heartbeat, resume, per-device
key acknowledgement, local master-password migration acknowledgement,
owner-only target-key rewrite, completion, and safe abort where allowed.

For `master_password_change`, freeze ordinary writes from the atomic start
commit until every non-revoked participant has acknowledged both target-key
availability and completion of local migration. The owner may resume with the
old and new master passwords on a replacement device, but only that owner may
rewrite ciphertext to the target key during the freeze. A newly paired device
must receive both versions and join the participant set. Revoking an offline
device must atomically remove it from the required acknowledgement set.
Completion promotes the target key version and unfreezes writes atomically.

The server cannot verify password knowledge, password equality across devices,
or successful plaintext decryption. It enforces signed device assertions and
state transitions; clients must perform encryption, re-encryption, local
password migration, and verification. The API and UI must state this boundary
accurately. Do not use a timeout to silently unfreeze writes.

**Done when:** transaction-level tests cover concurrent writes versus rotation
start, each missing acknowledgement, owner lease expiry/resume, device pairing
during the change, offline-device revocation, retry after lost responses,
completion, and rejection of ordinary writes until completion.

### 5. Quotas, retention, lifecycle, and production readiness

Add request/IP rate limiting (especially unauthenticated pairing), storage and
device quotas, idempotency/session/challenge cleanup, tombstone/history GC,
account deletion lifecycle, operational metrics, and deployment migration
workflow. Review TLS/proxy behavior against raw-body signing. Keep production
migrations separate from application startup and define backup/restore and
incident procedures.

**Done when:** retention and lifecycle jobs are retry-safe under account-first
locking, quotas bound stalled accounts, deployment checks pass, and the Phase 0
review gates in the server plan are closed.

## Suggested implementation order

Complete Milestone 0 first, then implement a vertical slice of batch write,
pull, and acknowledgement so a newly paired device can perform a complete
initial snapshot. Implement recovery next, then the entire rotation state
machine. Pairing alone is not an end-to-end sync release. Keep the service
behind non-production deployment controls until the security and operational
review gates are met.
