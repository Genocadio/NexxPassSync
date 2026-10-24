# Zero-Knowledge Sync Server Implementation Plan

**Status:** Proposed  
**Canonical location:** `nexxpass/docs/zero-knowledge-sync-server-plan.md` — copies in other repositories are read-only mirrors; edit the canonical copy and re-sync.  
**Revision:** 2026-10-21 — design-review amendments: normative-document register, wire-canonicalization decisions, passkey schema alignment, GC-stall runbook, capacity envelope, lifecycle/recovery policy defaults, restore/pairing/session-retry rules, and explicit page-issuance semantics. Second review: pairing-during-rotation consistency, fixed-H snapshot-read correction, delete-op hash rule, pairing account binding, deletion exposure-window precision, canonicalization-fuzz and version-negotiation tests. Third review: recovery-registration liveness during rotation, identity-lock/migration and deletion-cancel flow, first-device and sole-device lifecycle rules, deleted-account markers, rotation quota exemption and history-cap behavior, pairing enumeration and caps, control-plane fail-closed mode, lock-free watermark capture, security-event visibility, and device privilege model. Fourth review (2026-10-22): crypto-spec verified by independent recomputation (46 checks), identity migration unified on the in-place design (crypto-spec §17.2, new `POST /accounts/migrate`, `identity_migrated` event, lock cleared only by migration), error-code table completed, `deleted_accounts` rationale corrected, stale prerequisite/register statuses refreshed, OpenAPI drafted.  
**Scope:** Server-side account, device, key-wrap, encrypted-item sync, retention, and rotation APIs. Client cryptography and local-storage migration remain client work.  
**Protocol source:** the “Zero-Knowledge Sync Backend Plan (v2)” supplied for this project. This document records its server-side decisions and corrections.  
**Prerequisite:** `docs/crypto-spec.md` and `docs/vectors/protocol-v1.json` are present and were independently verified on 2026-10-22 (all §19 vectors recomputed: phrase, derivations, account ID, wraps, blobs, operation hashes, signatures, tokens, receipts). Signed request verification, key-wrap validation, and encrypted-blob validation MAY be implemented against them; the remaining Phase 0 exits are client-side vector agreement, the OpenAPI document, deployment target, and independent review (§14).

## 1. Goals and non-goals

The server is an authenticated, versioned store for opaque encrypted records and opaque key wraps. It must not receive vault keys, recovery seeds, local passwords, or plaintext vault records. Clients encrypt, decrypt, and merge records.

The server is responsible for:

- account and device registration, authorization, and revocation, plus account lock, deletion, and visible security events;
- storing recovery and per-device key wraps;
- ordered, conditional item mutations with retry-safe idempotency;
- bounded incremental and full-snapshot pulls;
- device acknowledgements and safe tombstone collection;
- routine and compromise key-rotation coordination;
- abuse controls, observability that excludes sensitive request content, and reliable backups.

The server does not validate vault plaintext, resolve client conflicts, decide whether a credential is a passkey, or guarantee availability against a malicious operator. It cannot erase ciphertext or key material already copied by a client.

### Passkey scope decision

Sync v1 carries all records in the encrypted record store, including standalone and login-attached passkeys. `docs/record-schema-v3-plan.md` is amended alongside this plan: schema v3 includes the existing first-class `Passkey` record type and `PasskeyData` payload. The server remains opaque to record kinds and transports every item in full snapshots and incremental pulls; it must never filter or omit a record class. Client rollout must preserve passkey private-key material inside the normal encrypted item blob. This removes the prior schema/sync scope contradiction; Phase 0 verifies both documents and client serialization agree before implementation.

## 2. Required specifications before implementation

Check in and review `docs/crypto-spec.md`, including:

1. identity-key derivation and account-ID derivation, with versioning and test vectors;
2. device signing and key-agreement key encoding, validation, and lifecycle;
3. wrap formats and recipient binding for recovery and devices;
4. encrypted blob format, associated data, key-version binding, and size limits;
5. exact canonical request-signature input, HTTP method/path/query/body rules, timestamp window, and nonce format;
6. canonical, unambiguous request hashing for `operation_id` idempotency;
7. error response encoding and cross-platform vectors;
8. domain separation between the identity-signing key and the recovery-wrap key, both derived from the same recovery phrase;
9. message formats for identity lock, identity migration, account deletion, and deletion cancellation (§11.1, §13.2) — defined in `docs/crypto-spec.md` §17; migration is the in-place design (same account ID).

The service may validate public-key encoding and opaque byte lengths. It must not claim to validate that a submitted wrap or blob contains a valid vault key or record.

### 2.1 Normative document register

Phase 0 is not exitable until this set is complete and versioned in-repository:

| Document | Content | Status |
|---|---|---|
| `docs/crypto-spec.md` | identity/account-ID derivation, key encodings, wrap and blob formats, signature input, operation-hash preimage, continuation-token format, key-separation rules, identity lock/migration/deletion message formats, error encodings, test vectors | present (2026-10-21); §15/§17 completed 2026-10-22 |
| `docs/vectors/*.json` | cross-language vectors: account IDs, key encodings, signatures, operation hashes, continuation tokens | present; independently recomputed 2026-10-22 (46 checks, all pass) |
| `docs/openapi/sync-v1.yaml` | OpenAPI schemas, canonical error shapes, quotas, page-size limits | drafted 2026-10-22; pending review |
| `docs/record-schema-v3-plan.md` | record schema v3 including `Passkey` / `PasskeyData` (see §1 passkey scope) | amended; Phase 0 verifies agreement |

`docs/crypto-spec.md` is authoritative for cryptographic and wire encodings. This plan is authoritative for server behavior. Vectors are executable conformance fixtures derived from those documents; a vector mismatch is a failed test to resolve against the normative spec, not a reason to silently override it.

### 2.2 Wire decisions locked now

These are proposed here for confirmation in `docs/crypto-spec.md` before implementation:

1. **Signatures cover raw bytes, never re-serializations.** The signed input is:

   ```
   "NPSSv1" || "\n" || METHOD || "\n" || PATH || "\n" || CANONICAL_QUERY || "\n" ||
   TIMESTAMP || "\n" || NONCE || "\n" || HEX(SHA256(raw_body_bytes))
   ```

   `CANONICAL_QUERY` is RFC 3986-encoded, keys sorted ascending, repeated keys sorted by value, no empty-value ambiguity. Empty bodies hash `SHA256("")`. The server computes the body digest on the bytes as received, **before** any parsing; deployments must not place re-encoding proxies in front of the API. Retries reuse body bytes verbatim and mint a fresh timestamp and nonce.
2. **Operation-hash preimage (§9) is binary, not JSON:**

   ```
   SHA256("NPSOp1" || account_id_32 || op_tag_1 || item_uuid_16 ||
          u64be(base_version) || u32be(key_version) || payload_digest_32)
   ```

   `account_id_32` is the 32-byte account ID; `item_uuid_16` is the UUID's 16 bytes in RFC 4122/network order; `op_tag_1` is `0x01` for put and `0x02` for delete. For a put, `payload_digest_32 = SHA256(decoded_blob_bytes)` and `key_version` is the version the ciphertext is encrypted under. For a delete, `payload_digest_32` is 32 zero bytes and `key_version` contributes `u32be(0)` — a delete body omits the field, so idempotency never depends on a value the server ignores. JSON key order and whitespace never affect idempotency matching. The crypto spec must publish vectors for both operations.
3. **Protocol versioning:** all endpoints live under `/v1/`; clients send `X-NexxPass-Protocol: 1`. Unknown versions return `unsupported_protocol_version`. Breaking changes ship as `/v2/`, never as silent behavior changes under `/v1/`.
4. **Timestamp/nonce coupling:** the timestamp window is ±300 s; nonce retention is 48 h (see §13.1), so a nonce remains rejectable for longer than its timestamp could still be valid.

## 3. Proposed server architecture

- HTTPS API service, PostgreSQL as the source of truth, and optional Redis for shared rate limiting. Store nonces in PostgreSQL initially unless measured traffic justifies Redis; whichever is selected must provide atomic, cluster-wide insert-if-absent with expiry.
- Every account-scoped state mutation first locks the `accounts` row with `SELECT ... FOR UPDATE`, then locks or modifies subordinate rows. This is the global lock order for item writes, acknowledgements, revocation, rotation, and tombstone GC. Pull-session creation is the one exception: it locks only the requesting device’s `devices` row and never takes the account row afterward, so it cannot deadlock with the account-first order (§7).
- Use PostgreSQL transactions for counters and state transitions. Do not allocate item sequence numbers from PostgreSQL `SEQUENCE` objects.
- No request bodies, authorization headers, signatures, nonces, wraps, blobs, recovery material, or decrypted content in logs, traces, crash reports, or analytics.
- API nodes are stateless except for shared database/nonce state. Server signing keys used for opaque sync tokens are metadata-integrity keys, not vault-data keys; keep them in a managed secret store and support versioned rotation.

## 4. Data model

Use UUIDs for device, item, operation, and sync-session identifiers. Account IDs are fixed-width bytes derived as specified by `docs/crypto-spec.md`.

### `accounts`

Identity public key and derivation version; `seq_counter`; `tombstone_floor_seq`; `change_floor_seq`; `active_key_version`; `next_key_version`; `keyring_version`; rotation state, target, owner device, lease expiry, and deadline; `status` (`active`, `identity_locked`, `deletion_pending`, `suspended`) with `deletion_requested_at`; creation time. Initialize `active_key_version = 1` and `next_key_version = 2`. `next_key_version` is a monotonic allocator: a version allocated to a rotation is never reused, including after abort.

### `devices`

Account/device IDs; Ed25519 and X25519 public keys; generic device label; creation and last-seen timestamps; `first_sync_at`; acknowledged `last_seen_seq`; highest server-issued sequence (`issued_through`); highest acknowledged key version; revocation timestamp/reason. A new device begins at sequence zero with no completed initial sync. The exception is the account’s first device, created by `POST /accounts`: it holds the complete initial vault, so the server sets its `first_sync_at` at registration (its `last_seen_seq` starts at zero for the empty account and ordinary acknowledgements advance it). Without this, the never-synced-device job would revoke a single-device account’s only device after 14 days. Devices registered through recovery or pairing complete a full snapshot as usual.

### `key_wraps`

Primary key `(account_id, key_version, recipient)`, where recipient is `recovery` or a device ID. Store opaque wrap bytes and `active`/`pending` status. Revoking a device removes its wraps. Rotation completion activates pending wraps and deletes superseded wraps as specified in the rotation state transition.

### `items`

Primary key `(account_id, id)`; current opaque encrypted blob; key version; item version; latest sequence; deleted flag; update timestamp. A tombstone has no blob. Enforce per-item ciphertext size and account quotas.

### `item_changes`

Accepted item states, immutable while retained, keyed by `(account_id, seq)` with a unique `(account_id, item_id, version)`: item ID, item version, key version, encrypted blob or tombstone marker, and update time. Write the current `items` row and its `item_changes` row in the same transaction. This retained change log is required for fixed-watermark pulls: a mutable current row can move from `seq <= H` to `seq > H` while a page is in progress, making the earlier state unavailable. Incremental pulls return, for each item with any retained change in `(cursor, H]`, its latest state at or before `H`; they do not expose superseded intermediate states for the same item, and an item whose newer state has `seq > H` appears again in a later pull. A full snapshot returns each item’s latest state at or before `H` and omits tombstones. Keep the latest state for each live item and all versions needed by active snapshot sessions; by default also keep states needed by active device checkpoints so lagging devices avoid a full resync. The checkpoint pin is a retention preference, not a correctness requirement: the cap override (§8) and rotation pruning (§11) release it, at the cost of a full resync for the lagging device. Prune older history only under §8’s account lock and advance a `change_floor_seq`; an incremental cursor below either retained-history floor must full-resync. The log contains ciphertext, not plaintext, and its storage counts toward account quotas. For an item whose current row has already moved past H, the latest-at-or-before-H lookup seeks the unique `(account_id, item_id, version)` index; version order and sequence order coincide per item, so no seq-scan of the log is needed.

### `retired_item_ids`

Permanent compact markers keyed by `(account_id, item_id)`, populated atomically when an item is deleted. They contain no credential data. Keep them after a tombstone and its change history are purged so a later create cannot reuse a deleted UUID. Creating an item checks both `items` and `retired_item_ids`. Account deletion may purge these markers because the account ID is never re-issued. Count them toward account metadata quotas and monitor their growth.

### `deleted_accounts`

Permanent markers keyed by 32-byte `account_id`, with deletion time, written in the same transaction that hard-purges an account (§13.2). Nothing else is retained. `POST /accounts` checks this table and rejects a retired ID with `account_id_retired`. This is what enforces "never re-issued": the recovery kit (crypto-spec §5) carries the account ID as a literal, so anyone holding a kit can re-present that exact ID at registration, and an attacker with a compromised kit must be unable to re-register the account they just lost. (The ID is not re-derivable from the phrase itself — it comes from a random `account_seed`, crypto-spec §6 — but the kit carries it, so the practical exposure is the same.) A user who deletes an account must therefore generate a fresh recovery phrase — and with it a fresh account seed and account ID — to register again; the crypto spec and onboarding copy say so.

### `account_events`

Visible, content-free security events: `(account_id, event_id)` with a UUIDv7 `event_id` (time-ordered, so appends from a read path need no account lock), a type (`device_paired`, `device_registered_via_recovery`, `recovery_wraps_read`, `device_revoked`, `rotation_started`, `rotation_completed`, `rotation_aborted`, `identity_locked`, `identity_migrated`, `deletion_requested`, `deletion_cancelled`, `history_cap_prune`), the acting device ID or `identity`, and a timestamp. No request content, keys, or IP addresses. State-change events are written in the same transaction as the change; repeated `recovery_wraps_read` events are coalesced within 10 minutes. `GET /accounts/me` returns the latest 50. Retention is 90 days and at most 500 rows per account. This is the only way existing devices learn that someone used the recovery phrase.

### `operations`

Primary key `(account_id, operation_id)`; canonical request hash; immutable result (status, item version, sequence); creation time. Retain for 30 days. Retention must exceed the documented client retry period with margin.

### `request_nonces`

Unique `(principal_id, nonce)` plus expiry. The principal is the authenticated device or identity key. Insert atomically before handling the request; a duplicate nonce is rejected across all service instances.

### `sync_sessions`

Opaque snapshot-session ID; account and device IDs; deployment epoch; fixed high watermark; current server-issued page position; acknowledged page position; expiry; full-snapshot flag; completion/abandoned flags. Permit at most one active pull session per device; starting a new one abandons its prior incomplete session. Persist the session so a continuation token cannot be edited to choose another watermark or skip to an unissued page. Expired sessions require a new pull. Keep sessions short-lived and clean them up with a scheduled job.

### `pairing_challenges`

Target account ID, bound at creation; random pairing ID; proposed device ID and public-key digest; creation/expiry times; status (`pending`, `consumed`, `expired`); approving device and consumed time. The approval's account ID must equal the target account bound at creation. Store no pairing secret or verification code. Enforce uniqueness for an unexpired proposed device ID within an account when approval commits. Challenge creation does not check that the target account exists (§6.1). Cap pending challenges per target account (initial: 20, evicting the oldest) and per source IP, and purge rows one hour after expiry.

## 5. Authentication and request processing

For each request:

1. Enforce TLS, body-size limits, and basic IP rate limits before parsing large payloads.
2. Parse only canonical request forms. Reject duplicate/ambiguous query keys and non-canonical encodings.
3. Verify timestamp window, request signature, device/account binding, and the request-body digest exactly as specified in `docs/crypto-spec.md` and §2.2. The digest is computed over the raw body bytes as received, before any parsing; no component may re-serialize the body before verification.
4. Atomically consume the nonce. Reject replay.
5. Check account/device existence and active revocation state on every authenticated request. For state-changing requests, repeat the active-state check after acquiring the account row lock, before mutation. This closes the race where a request passes preflight just before another request revokes its device. Revocation takes effect at its transaction commit; already-running reads may finish.
6. Apply endpoint-specific rate and quota checks.
7. For state changes, enter a transaction and lock the account row first.

Authentication failures must not disclose whether an account, device, or item exists. Return structured errors with stable machine-readable codes and no sensitive details.

## 6. API surface

| Endpoint | Authorization and behavior |
|---|---|
| `POST /accounts` | Identity-key-signed registration. Atomically create account, first device, version-1 recovery wrap, and first-device wrap. Make registration idempotent or return a uniform conflict for an existing account. Reject a retired account ID with `account_id_retired` (§4). The first device is created with `first_sync_at` set (§4). |
| `GET /accounts/me` | Active device signature. Return identity public metadata, this device’s eligible wraps, active/keyring versions, rotation state, device status, account status and pending-deletion time, the latest `account_events`, and its server-acknowledged sync checkpoint. |
| `GET /accounts/recovery` | Identity-key signature. Return active and pending recovery wraps, without revealing account existence to unauthenticated callers. Appends a coalesced `recovery_wraps_read` event. Rejected with `identity_locked` after a lock (§11.1) and with `account_deletion_pending` during the deletion grace period. |
| `POST /devices` | Identity-signed recovery registration for a device after recovery; apply device-count quotas. **Permitted during rotation** (§11): the request carries the device’s own wrap for the active key version and, if a rotation is running, for the pending target, and records a `device_registered_via_recovery` event. Rejected with `identity_locked` after a lock. Paired registration uses §6.1; it is allowed during `master_password_change` only with both wraps and is rejected during routine/compromise rotation. |
| `POST /pairings`, `/pairings/{id}/approve` | Create (unauthenticated, rate-limited, bound to a target account) and approve (active device signature) a one-use device-pairing challenge. See §6.1. |
| `GET /devices` | Active device signature; list public device metadata only. |
| `DELETE /devices/{id}` | Active-device signature; revoke atomically, delete wraps, and exclude it from acknowledgements/GC watermarks. |
| `POST /sync/pull` | Active device signature; start or continue an authenticated snapshot session. See §7. |
| `POST /sync/ack` | Active device signature; acknowledge only a server-issued, fully delivered checkpoint. See §8. |
| `POST /sync/batch` | Active device signature; process bounded conditional mutations with per-operation idempotency. See §9. |
| `POST /rotation/start`, `/heartbeat`, `/resume`, `/ack`, `/complete`, `/abort`, `/rewrite` | Active device signature; enforce the state machine in §11. `/rewrite` is restricted to the master-password-change lease owner. |
| `POST /accounts/lock` | Active device signature; sets `identity_locked` so every identity-signed request is rejected. Used for recovery-phrase compromise (§11.1, crypto-spec §17.1). Cleared only by migration. |
| `POST /accounts/migrate` | Active device signature; in-place identity replacement on the same account ID (§11.1, crypto-spec §17.2). Rejected during rotation and during `deletion_pending`. Replaces identity keys, swaps recovery wraps, emits `identity_migrated`, returns the account to `active`. |
| `DELETE /accounts` | Identity signature, or active-device signature when the account is `identity_locked`; begins the 30-day deletion grace period (§13.2). |
| `POST /accounts/deletion/cancel` | Active-device signature, or identity signature unless `identity_locked`; cancels a pending deletion within the grace period. |

Single-item put/delete endpoints, if exposed, must call the same mutation implementation as `/sync/batch` and preserve identical idempotency and transaction semantics.

### 6.1 Device-pairing approval

Pairing uses a short-lived server challenge so an active device approves the exact public keys being registered:

1. The new device generates its Ed25519 and X25519 key pairs and client-generated device ID locally, then creates a pairing request for its target account containing them. The server stores the target account ID, a random pairing ID, a digest of the proposed device ID and keys, creation time, expiry (five minutes), and `pending` status. Apply unauthenticated IP/device-key rate limits; do not register the device yet. Creation does not check whether the target account exists and returns the same response either way, so it is not an enumeration oracle; existence is first checked when an active device approves. Pending-challenge caps are in §4.
2. The existing device scans the request and independently computes a short verification code from the challenge, device ID, and proposed public keys. Both devices display the code; the user compares them and confirms on the existing device.
3. Outside rotation, the existing active device signs an approval binding the pairing ID, proposed device ID and public keys, expiry, account ID, and active key version, then uploads the active-key wrap encrypted to the proposed X25519 key. During `master_password_change` only, it also binds the target key version and target-key wrap. Pairing remains rejected during routine and compromise rotations.
4. In one account-locked transaction, the server verifies the approval signature, challenge digest, target-account match, expiry, one-use status, unused device ID, and wrap-recipient set; registers the device; stores its active wrap and (during master-password change) target wrap; inserts it into the rotation participant set; marks the challenge consumed; initializes its sync watermark to zero; and appends `device_paired`. The new device learns that approval committed by polling `GET /accounts/me` signed with its proposed device key; until then that call returns the uniform authentication failure.

Replays, expired challenges, changed public keys, wrong-account approvals, and challenge reuse are rejected. Pairing during `master_password_change` adds the new device to the required acknowledgements, so completion remains blocked until it has applied target ciphertext and acknowledged its local password migration. The verification code is a user confirmation aid; the signature and challenge binding provide the protocol authorization.

### Error codes

Use stable codes for malformed/non-canonical input, authentication/replay/clock skew, conflict, deleted/gone item, resync required, request or quota limit, operation-ID reuse, invalid input, unsupported key version, rotation in progress, retired account ID, identity-locked account, pending account deletion, rate limiting, and temporary service failure. Include `Retry-After` for retryable service/rate-limit responses. Do not return plaintext or secret bytes in errors.

## 7. Pull protocol with server-bound snapshots

Replace client-chosen `until` values with server-issued continuation tokens.

1. The first pull supplies the client’s durable checkpoint and page-size preference. In one short transaction that locks only the requesting device’s `devices` row (never the account row), the server validates the checkpoint against device state, abandons any prior incomplete session, captures `H` by reading the committed `accounts.seq_counter`, creates a short-lived `sync_sessions` row, selects the first page, and records its page number, terminal position, receipt, and next-page token state. A plain read of the counter is sufficient: item writes increment it under the account lock and commit it atomically with their `item_changes` rows, so every row with `seq <= H` is already committed. The transaction commits before the HTTP response is sent.
2. Every continuation token is bound to account, device, sync session, deployment epoch, expiry, fixed `H`, and the exact next page position. The server rejects altered, expired, out-of-order, or wrong-device tokens.
3. Pages contain `item_changes` rows in ascending `seq`, with `cursor < seq <= H`. An incremental pull returns, for each item with a change in that interval, its latest state at or before `H`, including tombstones, so a client gets the final state without downloading superseded same-item versions. If the item changed again after `H`, that newer state arrives in a later pull. A full snapshot (`cursor = 0`) returns the latest state for each item at or before `H`, omitting tombstones because the client reconciles against a complete snapshot. The change log preserves the snapshot’s view if an item is updated while pages are being read.
4. A page becomes server-issued when its page state is committed, before attempting to send the HTTP response. The response’s page checkpoint is the final row sequence; the final response explicitly marks the snapshot complete and identifies `H` as the completed checkpoint. The server cannot know whether the client received a response, so issuance never depends on transport delivery. A lost response is recovered by abandoning the session and starting from the server-acknowledged checkpoint as described below.
5. Concurrent writes after `H` are excluded from this session and belong to the next pull.
6. An incremental checkpoint below `max(tombstone_floor_seq, change_floor_seq)` returns `410 resync_required`. A checkpoint equal to the applicable floor is allowed. Full snapshots from cursor zero remain available.
7. An incremental pull must start at the device’s server-acknowledged checkpoint. If the client’s durable local checkpoint is ahead because its ack response was lost, it retries that ack before pulling again. A client that restored older local state requests a full snapshot (`cursor = 0`). Reject any response watermark below a watermark the client has already durably recorded.

Each page response contains `sync_session_id`, `items`, `high_watermark`, `page_cursor`, `done`, and a one-use `page_receipt` bound to the session, page number, and terminal checkpoint. Non-final responses also contain a continuation token for the next page. Final responses set `page_cursor = H` and have no continuation token. The page selection, receipt, and continuation-token state are committed atomically before the response is attempted. The client acknowledges the page receipt; the receipt is not itself a durable checkpoint.

**Lost response / retry rule:** clients persist a local applied checkpoint separately from the server-acknowledged device checkpoint; neither continuation tokens nor page receipts are checkpoints. If any pull-page response is lost, the client cannot rely on receiving the already-issued continuation token: it starts a new incremental session from the server-acknowledged checkpoint and idempotently reapplies any already-applied item versions. Starting the new session abandons the old one. If an ack response is lost, retry the same receipt; if its session has expired, fetch the server-acknowledged checkpoint from `/accounts/me` before resuming. If an incomplete full snapshot is lost or expires, the client discards its staging state and restarts from cursor zero. A new session captures a new high watermark. This makes page recovery safe without requiring the server to reconstruct a response from a mutable item table.

Clients must atomically apply each page and persist its checkpoint locally. They acknowledge only after that transaction commits. For a full snapshot, stage all pages; do not replace local state until the final page is applied. Reconcile at snapshot watermark `H`: take clean remote states; merge conflicting dirty states; remove a previously synced clean local item only when it is absent from the complete snapshot; preserve never-synced local items for upload; and ask the user before restoring a dirty local item absent remotely, using a new item ID if restored. Commit the staged reconciliation atomically, then acknowledge the completed snapshot at `H`. Changes after `H` arrive in the next incremental pull.

The device’s `issued_through` and sync-session page position record what the server made available; they do not prove that a client applied a page honestly. Treat acknowledgements as device assertions in the threat model.

## 8. Checkpoints and tombstone collection

An ack contains `sync_session_id`, the terminal sequence, and the server-issued page receipt. Accept it only for the device’s active session and its next unacknowledged page; a later page cannot be acknowledged first. Retrying the most recently accepted ack with the same receipt returns the original success without changing state. The client sends the ack only after that page is durably applied. For an incremental session, each page ack advances `last_seen_seq`. For a full-snapshot session, page acks advance only the session’s acknowledged page position; they do not advance the device watermark. Atomically set `last_seen_seq = H` only when the final page of the full snapshot is acknowledged. Set `first_sync_at` at that same point for the first completed full snapshot; do not infer initial-sync completion from a partial page. A device signature authenticates the client assertion but cannot prove its local disk state.

Run GC in a transaction holding the account row lock. A tombstone is eligible only when:

- it is older than the retention period (90 days);
- its sequence is no greater than the minimum checkpoint of every active device;
- the account has at least one active device watermark. If there are no active devices, delete nothing unless a separately reviewed retention policy says otherwise.

After deleting eligible tombstones, advance `tombstone_floor_seq` monotonically to the maximum purged tombstone sequence. Retain the corresponding `retired_item_ids` marker. Prune superseded `item_changes` rows only when no active device checkpoint or snapshot needs them; always retain the latest state of each live item. Advance `change_floor_seq` to the highest sequence whose history was pruned. Incremental cursors below either floor must full-resync; a full snapshot reads the latest retained state at or before H for each live item, never the mutable current row — an item rewritten after H must not change a snapshot already in flight. When rotation completes, remove superseded pre-target ciphertext history as soon as no active snapshot needs it; lagging devices receive the latest target-key state or full-resync. Missing rows with `base_version > 0` return `item_gone`; the server never recreates them implicitly.

**GC-stall observability and runbook.** A single non-acking device blocks tombstone and superseded-history collection indefinitely; device revocation is the bound. Export `gc_blocked_account_count`, `oldest_unpurgable_tombstone_age_days`, `oldest_unpurgable_change_age_days`, and per-account tombstone/change-history count and bytes (account IDs are pseudonymous metadata and allowed in telemetry). Alert on excessive age or quota use. Runbook: identify the blocking device server-side, contact the user, revoke the device if abandoned — revocation already removes it from GC watermarks (§6). Cap retained tombstones and change-history bytes per account so stalled accounts cannot grow storage without bound.

**Cap behavior.** When an account reaches either cap, the server does not reject writes. Under the account lock it prunes superseded `item_changes` rows without regard to device checkpoints (never the latest state of a live item, never rows pinned by an active session) and, if the tombstone cap is hit, purges the oldest tombstones early. It advances `change_floor_seq` and `tombstone_floor_seq` accordingly, so lagging devices full-resync instead of blocking the account; `retired_item_ids` still prevents ID reuse. Each cap-driven prune emits a metric and a `history_cap_prune` event.

Scheduled lifecycle jobs:

- revoke devices that never complete first sync after 14 days (the account’s first device is exempt: its `first_sync_at` is set at registration);
- revoke inactive devices after the defined 180-day window, but never the account’s last active device: skip it, emit an `inactive_sole_device` metric, and leave recovery to the client (§13.4);
- purge expired idempotency records, sync sessions, `account_events`, and stale `pairing_challenges`;
- collect eligible tombstones;
- enforce rotation deadlines per §11 (routine: clear the lease or auto-abort; compromise: revoke unacknowledged devices);
- hard-purge accounts whose 30-day deletion grace period has ended and write their `deleted_accounts` markers.

Every job uses the same account-row-first lock order and is safe to retry.

## 9. Mutation and idempotency protocol

While `rotation_mode = 'master_password_change'`, ordinary `/sync/batch`
requests are rejected regardless of key version. The owner uses the dedicated
`POST /rotation/rewrite` endpoint, which accepts only conditional puts at the
target version and applies the same operation-id, base-version, sequence, and
quota rules. This is a narrow maintenance path, not a user-data write path; the
server cannot determine whether an opaque target blob contains the same
plaintext as the old blob.

Mutation shape. `blob` is unpadded base64url encoding of the exact opaque ciphertext bytes; size limits apply after decoding. The body’s signature digest covers the raw JSON bytes, while the operation hash covers the decoded blob bytes as specified in §2.2.

```json
{
  "operation_id": "uuid",
  "op": "put | delete",
  "item_id": "uuid",
  "base_version": 0,
  "key_version": 1,
  "blob": "unpadded base64url ciphertext"
}
```

For a `put`, `key_version` and `blob` are both required. For a `delete`, both are omitted — the operation hash uses `key_version = 0` (§2.2), and the server never sees a key version on a delete.

The exact fixed-width hash input is defined in §2.2 and `docs/crypto-spec.md`. Hashes must not depend on JSON key order or incidental whitespace. Enforce the blob limit on decoded ciphertext bytes; enforce the request-body limit on raw received bytes.

Batch limits initially: 100 mutations, 1 MiB total body, and 64 KiB per blob. Reject a batch as a whole before mutation if it contains a duplicate `item_id` or duplicate `operation_id`. Validate all sizes and shapes before beginning the transaction.

Inside one transaction under the account lock, process mutations in request order:

1. Look up `(account_id, operation_id)`. Same hash returns the stored result; different hash returns `422 operation_id_reused`.
2. Check the current accepted key version for the rotation state.
3. Apply base-version and permanent-deletion rules.
4. A rejected mutation consumes no item version or sequence and stores no operation row.
5. An accepted mutation increments item version once and the account sequence once, writes the current item, its immutable `item_changes` row, and operation result atomically.

The batch returns one result per mutation in request order. A processed batch returns HTTP 200 even when individual mutations conflict or refer to gone/deleted items. Lost-response retries return the original result for stored operation IDs and process new IDs exactly once.

## 10. Deletion and permanent item IDs

- Delete at the current version writes a tombstone, clears the encrypted blob, increments version and sequence, and inserts the permanent `retired_item_ids` marker in the same transaction.
- Stale delete returns conflict. Delete of an already-deleted item returns `item_deleted`, except an idempotent retry returns the original result.
- Edits to a tombstone return `item_deleted`. A missing item with `base_version > 0` returns `item_gone`.
- Creating with `base_version = 0` and an existing or retired ID conflicts. Clients restore by creating a new UUID.
- Clients never reuse item UUIDs; `retired_item_ids` enforces this after physical tombstone collection.

## 11. Key rotation state machine

The `routine` and `compromise` modes below retain their existing semantics.
Cross-device master-password change is a distinct `master_password_change`
mode (§11.2), because it must freeze ordinary writes until every active device
has migrated.

Accepted write versions:

| State | Accepted versions |
|---|---|
| `idle` | Active version only |
| `routine` | Active and allocated target version |
| `compromise` | Target version only, immediately after start |
| `master_password_change` | Normal writes blocked; rotation-owner rewrite puts at target only |

Rotation target allocation uses `next_key_version`, then advances it permanently. Aborted or failed rotations do not return their version to the allocator. This prevents two different keys from ever sharing a version number.

Each transition runs under the account lock:

- **Start:** require idle state, active caller, target allocated by server, recovery wrap, and exactly one pending wrap for every active device. Store wraps as pending, set owner/lease/deadline (a compromise rotation’s deadline must be at least 24 hours after start), append a `rotation_started` event, and increment `keyring_version`.
- **Heartbeat:** only current rotation owner can renew an unexpired lease.
- **Resume:** after lease expiry, an active device claims ownership. Do not change target version or wraps. Revoking the owner device clears the lease immediately, so another active device can resume at once.
- **Ack:** active device confirms it unwrapped and durably stored target key; update `acked_key_version` monotonically.
- **Revoke/register:** revoke removes wraps, excludes the device from completion requirements, and clears the lease if it was the owner. Paired registration (§6.1) is rejected during routine/compromise rotation and permitted during `master_password_change` only with active and target wraps; the new device joins the participant set. Identity-signed recovery registration is **permitted**, so no rotation state can leave an account with no device able to finish or abort it: the registering device supplies its own wrap for the active version and for the pending target, stored with the matching `active`/`pending` status. In compromise mode it is recorded as having acknowledged the target, because it created its own target wrap; otherwise the deadline job would revoke it before it could sweep.
- **Sweep:** client re-encrypts live records as normal conditional mutations. Every accepted rewrite increments item version and sequence. On conflict, client re-reads, merges, and encrypts again. Sweep rewrites are exempt from the per-account ciphertext-byte quota up to a hard ceiling of 2× the quota, so an account near its quota can still finish. As soon as a rewrite supersedes a row under a pre-target key version and no active snapshot session pins that row, the server deletes it and advances `change_floor_seq`; lagging devices receive the latest target-key state or full-resync.
- **Complete:** require no live item under an older key version. In compromise mode, also require every remaining active device to have acknowledged the target. Activate pending wraps, delete old wraps, set active key version, clear rotation state, append a `rotation_completed` event, and increment `keyring_version`.
- **Abort:** routine rotations only. Allow abort only before any target-key item is written and before any device has acknowledged/stored the target key; remove pending wraps and clear state. The allocated version remains retired. Compromise rotation cannot abort.

For compromise mode, revoke suspected devices first. Old-key writes stop when rotation starts. At the deadline, revoke every unacknowledged device, then allow completion after the item sweep. Recovery-phrase compromise requires identity migration (§11.1); key rotation alone cannot restore secrecy.

**Deadlines.** Routine: when a routine rotation’s deadline passes and its lease has expired, the job auto-aborts if the abort preconditions hold; otherwise it clears the lease so any active device can resume. Routine rotations never revoke devices. Compromise: at the deadline, unacknowledged devices are revoked. If that leaves no active device, the rotation stays in `compromise` until a device registered through identity-signed recovery acknowledges the target and completes the sweep; it needs only the active and pending recovery wraps readable through `GET /accounts/recovery`.

**Device assertions.** The server cannot verify what ciphertext contains, so the key version on a put and the completion check "no live item under an older key version" rest on client-declared labels. The crypto spec binds the key version into each blob’s associated data so a mislabeled item fails to decrypt on read; completion remains a device assertion, like acknowledgements.

**Privilege model.** In v1 every active device is equally privileged: any can revoke others, start a rotation, or delete items. A stolen unlocked device is a full-account compromise until another device revokes it. The 24-hour compromise-deadline minimum, `account_events` visibility, and the deletion grace period are the v1 mitigations; device roles are future work.

**Best-effort client key cleanup.** After a device has committed rotation completion locally, rewritten or re-synced every live item at the target version, and acknowledged the target key, it should zeroize the old key in memory and delete old-key copies and wraps it controls. An offline device should full-resync at the target version before deleting its old local copy. These actions reduce exposure; they cannot prove erasure from copied files, flash storage, OS snapshots, backups, or a compromised device. Anyone who retained an old key can still decrypt ciphertext encrypted with it. Rotation therefore does not provide a guaranteed time bound on historical exposure. Backup restores must reapply recorded completed rotations and revocations before serving traffic.

### 11.2 Cross-device master-password change (write-frozen mode)

The mobile vault's existing master-password operation re-wraps its local DEK;
it does not rotate sync blobs or update another device. Cross-device change is a
separate client-driven `master_password_change` rotation of the shared sync key
and every device's local unlock state. The backend coordinates and enforces the
write barrier. It never receives either password, a password hash/verifier,
plaintext, or a vault key, and it never decrypts or re-encrypts a blob.

**Account/device model.** Every active device has equal account authority; there
is no permanent primary device. The rotation owner is only a temporary lease
holder for the ciphertext sweep. Any active device can start or resume the
operation. Pairing is allowed during this mode when the approver supplies wraps
for both the active and target keys; the new device joins the required
acknowledgement set. Pairing remains rejected during routine and compromise
rotation.

**Start and freeze.** In one account-locked transaction, the initiating active
device allocates a fresh target key version, stores one pending target wrap for
recovery and every active device, snapshots those devices into
`rotation_participants`, marks itself owner with a renewable lease, sets
`rotation_mode = 'master_password_change'`, and emits `rotation_started`. From
that commit onward, ordinary `/sync/batch` writes from every device are rejected
with `rotation_in_progress`, including writes encrypted with the old key and
writes from the owner. Pulls and account/device status reads remain available.
This is a strict freeze: no new user records or deletes are accepted until
completion.

**Ciphertext rewrite.** The owner obtains existing ciphertext through pulls,
decrypts and re-encrypts each live item locally under the target key, and sends
conditional puts through a dedicated `/rotation/rewrite` operation. Only the
current lease owner may use that operation; it accepts puts at the exact target
version, uses the same operation-id and base-version conflict rules as ordinary
sync, and does not accept deletes or arbitrary key versions. It is the only
write path while this mode is active. On a crash or lease expiry, any active
device that has both old and target keys available can claim the lease and
continue from persisted item versions. The new owner receives the target key
through its own pending device wrap; resuming a client-side local vault still
requires that user to unlock it with the old password and set the new password.

**Per-device migration and acknowledgements.** Each participant must retrieve
and durably apply the target-key snapshot, then locally migrate its encrypted
vault/unlock slot from the old master password to the new one. The client asks
for the old password to unlock and verify the existing local vault, then asks
for the new password and commits the local re-wrap/migration atomically. Only
after that local commit does it send `/rotation/ack` with the target version
and `local_master_password_updated = true`. This acknowledgement is a signed
client assertion: because the backend is blind to passwords and plaintext, it
cannot prove that the user entered either password or that every local copy was
migrated. The client must not send passwords, password-derived verifiers, or
master-password material to the server. A compliant client gates its own
ordinary writes until it has acknowledged the target version.

**Completion and offline devices.** Completion requires (1) every live server
item to be at the target key version and (2) every non-revoked participant to
have acknowledged both target-key availability and local master-password
migration. The server then activates target wraps, removes superseded wraps,
sets the target as active, clears rotation state, emits `rotation_completed`,
and re-enables normal writes under the target key. If a device is offline, the
barrier remains in place; an active user may wait for it or explicitly revoke
that device, which removes it from the participant set and prevents it from
writing again. No timer silently completes or aborts this mode. Recovery
registration during the rotation must be supplied with active and target wraps
and added as a participant before it may write after completion.

All devices poll `GET /accounts/me` or read the visible `account_events` feed
to see the mode, target version, owner/lease, write-freeze state, and required
versus acknowledged device counts. The state contains no passwords, keys, or
record contents. Any unsynced local edits remain local while the barrier is
active and must be preserved by the client, then merged and uploaded under the
target version after completion. The client should ask devices to finish sync
before starting, but the server cannot detect unsynced local-only edits.

**Scope boundary.** This changes the shared sync encryption key and coordinates
each device's local master-password re-wrap; it does not make the backend a
password authority. If the product requires the server to prove that all
devices know the *same* new password, that conflicts with the zero-knowledge
requirement without adding a separately reviewed password-authentication
protocol (which would create an offline-guessing verifier). In v1 the server
enforces device participation and the write barrier, while clients assert
password migration.

### 11.1 Identity migration after recovery-phrase compromise

Key rotation cannot help once the phrase is known: the phrase holder can read the recovery wraps and register devices. The server-side mechanism is **in-place identity replacement on the same account ID** (crypto-spec §17.2): items, versions, sequences, devices, and device wraps are untouched, and no ciphertext is re-encrypted, because the blob AAD binds the unchanged account ID. Only the identity keys and recovery-recipient wraps are replaced.

1. **Lock first.** From any active device, call `POST /accounts/lock` (crypto-spec §17.1). The account moves to `identity_locked`: every identity-signed request (`GET /accounts/recovery`, recovery `POST /devices`, identity-signed deletion or cancellation) is rejected with `identity_locked`. Existing devices keep working. This cuts off the attacker immediately, before migration finishes.
2. **Migrate.** The client generates a new recovery phrase and new identity keys, then calls `POST /accounts/migrate` — device-signed, with an optional `X-NexxPass-Countersign` header carrying a detached countersignature by the old identity key over `"NPSIdMig1" || account_id || HEX(SHA256(body))` (crypto-spec §17.2). In one account-locked transaction the server replaces the stored identity public keys, deletes all old recovery wraps, stores the new recovery wrap for the active key version, sets the account back to `active`, and appends an `identity_migrated` event. Migration is rejected while a rotation is in progress (`rotation_in_progress`) and during `deletion_pending`.
3. **Distribute the new kit.** The user saves the new recovery kit (crypto-spec §5). Other devices learn of the identity change from the `identity_migrated` account event or from `/accounts/me` and warn the user.
4. **No retire step.** The old account IS the new account: no `DELETE /accounts` call is needed, and the 30-day grace period in §13.2 does not apply to migration. The old phrase can no longer read recovery wraps, because the wraps are re-encrypted to the new identity key. (Deleting a *different* compromised account remains the §13.2 path and still requires a fresh recovery phrase to register again, because `deleted_accounts` forbids ID reuse.)

Limits to document: ciphertext and wraps the attacker already copied stay decryptable by anyone holding the old phrase or vault key; an attacker who still holds an unrevoked active device retains v1-equal privileges until it is revoked (§11); and a user who has lost every device cannot lock the account, so if that user’s phrase is also compromised the old vault cannot be salvaged.

## 12. Transaction and concurrency invariants

Enforce and test these invariants across API handlers and jobs:

- Every account mutation locks the account row first and holds it through commit.
- Sequence numbers are gapless and commit-ordered; rejected writes consume none.
- Item version increments exactly once for each accepted item mutation.
- A batch assigns consecutive sequences to accepted operations in request order.
- An item’s sequence represents its latest server-visible state.
- Account sequence counter, current items, immutable item changes, wraps, rotation state, device state, and operation results commit or roll back together where they form one transition.
- Rotation key-version allocations, tombstone/history floors, device checkpoints, and keyring version never decrease; allocated key versions are never reused.
- An idempotent operation ID returns its original immutable result for the retention period.
- No path can revive a deleted or physically purged item ID; the permanent retirement marker survives tombstone/history GC.
- An `identity_locked` account rejects every identity-signed request; the lock
  is cleared only by a successful in-place identity migration (§11.1,
  crypto-spec §17.2), never by any other path.
- A hard-purged account ID is permanently recorded in `deleted_accounts` and cannot be registered again.
- No rotation state can leave an account with no device able to act: identity-signed recovery registration is allowed during rotation (§11).

Use `READ COMMITTED` with the account row lock as the serialization point. Set a short lock timeout (initial target: 3 seconds); map lock timeout to a retryable service response. Never perform network calls or expensive cryptography inside the transaction.

**Capacity envelope (v1).** The account-row lock is the deliberate scaling limit: every mutation, ack, rotation transition, and GC scan serializes on one row; pull watermark capture is a plain read of the committed counter and takes no account lock (§7). The append-only `item_changes` table is a correctness requirement, not a future scaling option. Initial targets for Phase 8 load tests (adjust only with measurements): ≤ 8 active devices and ≤ 25000 items per account; batch commit p99 ≤ 300 ms with lock-wait p99 ≤ 50 ms under two concurrently writing devices; a 10000-item full snapshot completes in ≤ 90 s of paging; a 10000-item rotation sweep completes within 24 h of client activity. If measurements exceed the envelope, partition or archive `item_changes` and partition `items` by account while retaining the account-row lock as the serialization point. Do not remove that lock without replacing it with an equivalently testable mechanism.

## 13. Security, abuse, and operations

- TLS everywhere. Consider certificate pinning only as a client hardening measure; it is not a substitute for signed requests or correct server auth.
- Verify signatures and consume nonces before accepting any authenticated action. Check revocation on every request.
- Rate-limit by IP, account, device, and endpoint. Apply stricter controls to account creation, recovery, device registration, and rotation.
- Add per-account caps for devices, records, total ciphertext bytes, concurrent snapshots, active operations, and request rates. Publish limits before client integration.
- Prevent user enumeration with uniform unauthenticated response shapes and bounded timing where practical.
- Use encrypted database volumes and encrypted backups as defense in depth; server operators still see metadata and ciphertext.
- Restrict production access, rotate operational secrets, audit administrative actions, and test restore procedures.
- Monitor latency, lock waits, error rates, quota usage, nonce-store availability, GC progress, rotation duration, and job lag. Telemetry must exclude credentials, bodies, signatures, wraps, and blobs.
- Document that malicious servers can withhold, roll back, or fork history in v1. Persist client high-watermarks and detect observed rollback; do not claim fork consistency without a transparency/log protocol.
- Ratify the lifecycle policy defaults in §13.1–§13.4 before public launch; they are Phase 8 exit items, not stretch goals.

### 13.1 Retention defaults

| Data | Retention | Rationale |
|---|---|---|
| `operations` | 30 days | exceeds documented client retry period |
| `sync_sessions` | 24 hours | snapshots are short-lived; referenced change history is retained until the session completes, is abandoned, or expires |
| superseded `item_changes` | until all active device checkpoints and snapshots pass them, then eligible for pruning | current live item states remain available for full snapshots |
| `request_nonces` | 48 hours | ≥ timestamp window (±300 s, §2.2) + margin |
| tombstones | 90 days and ≥ min device checkpoint | §8 |
| inactive devices | 180 days, then revoke, except the account’s last active device | bounds GC stalls and wrap exposure; avoids stranding a sole device (§13.4) |
| never-synced devices | 14 days, then revoke; the first device is exempt | §8 |
| `pairing_challenges` | purged 1 hour after expiry | §4 |
| `account_events` | 90 days, at most 500 per account | §4 |
| `deleted_accounts` markers | permanent | account IDs are never re-issued (§13.2) |
| backups (PITR) | 35 days | point-in-time operational recovery |
| monthly full backups | 12 months | disaster recovery; extends historical ciphertext/wrap retention up to 12 months |

### 13.2 Account lifecycle and abuse defaults

- **Deletion**: an identity-signed `DELETE /accounts` (or a device-signed one while `identity_locked`, §11.1) moves the account to `deletion_pending`. Wraps and items become inaccessible immediately and sync requests are rejected with `account_deletion_pending`; only `GET /accounts/me` (which reports the state and `deletion_requested_at`) and cancellation remain available. Physical purge happens after 30 days. During the grace period an active device, or the identity key unless the account is `identity_locked`, can cancel with `POST /accounts/deletion/cancel`. Because a phrase holder can request deletion, this cancel path and prominent client display of pending deletion are the defense against a malicious wipe. At purge, the account ID is written to `deleted_accounts` in the same transaction, so it is never re-issued. Backups age out under the retention table and the deletion is recorded so restored backups re-apply it. The exposure window equals the longest backup-retention tier (12 months with the defaults in §13.1) and is documented to users.
- **Suspension**: automated limits → throttle → suspend (identity-signed restore) → terminate; every transition is audited without request content.
- **Orphan accounts**: an account whose identity key is lost (§13.4) is unrecoverable by design; after the inactivity window it follows the same deletion path (operator-initiated, with the same 30-day grace period).

### 13.3 Disaster recovery and database rollback

A backup restore can roll back acknowledged item writes, tombstones, device revocations, rotation completion, sequence counters, and idempotency rows. Restoring an older database and immediately serving it can lose acknowledged data or revive access that had been revoked. A lower server watermark is a detection signal; it is not a recovery procedure.

- Set and publish an RPO for acknowledged API success. Production should target zero loss of acknowledged writes within its declared failure domain, using synchronous durability/replication and tested WAL recovery. If the deployment cannot meet that target for a failure, the actual RPO must be disclosed.
- Maintain recoverable WAL/backups and an independently durable, append-only security event journal for revocations, completed rotations, and account deletions. Replay all required state through the last acknowledged commit frontier before serving restored data. Keep the journal outside the database restore domain and protect its integrity.
- Keep a monotonic `deployment_epoch` and a per-account `recovery_required` blocklist in a control plane that is not rolled back with the application database. Increment the epoch after every restore/failover that may invalidate sync state. Bind sync tokens and responses to this epoch; clients discard old sessions and request a full reconciliation when it changes. Check the recovery blocklist before serving any account request.
- **Control-plane failure mode: fail closed.** The epoch and blocklist are a hard dependency of every request. API nodes may cache them for at most 5 seconds; a longer-lived cache is a window in which a `recovery_required` account is served. If the control plane is unreachable and the cache has expired, nodes return a retryable `503` with `Retry-After` for all account requests and never serve from stale state, and a node cannot start without a successful epoch read. Test control-plane outage, partition, and stale-cache cases alongside the nonce-store outage.
- If operators cannot establish that acknowledged mutations and security events have been restored, keep affected accounts in `recovery_required`: reject normal pulls, writes, and rotation completion; do not advertise the restored database as current. Recover from the independent journal or use an explicit account-repair procedure based on clients’ durable local state. Never silently accept lower sequence/keyring versions or replay revoked devices/wraps.
- Test a restore that rolls back each of: a committed put, delete, device revoke, completed rotation, account deletion, and idempotency result. Verify that the service remains unavailable for affected accounts until repair completes and that the epoch invalidates old tokens.

### 13.4 Recovery bootstrap policy

The server cannot help a user who loses everything; the protocol only makes recovery possible when at least one of {an active device, the recovery phrase} still exists. Required decisions and client obligations:

- `docs/crypto-spec.md` must define recovery-phrase → identity-key derivation so `GET /accounts/recovery` and recovery-based `POST /devices` work with **zero devices present**; this is the only bootstrap path after total device loss.
- Registration UX must force an explicit choice: save the recovery kit (generated client-side, shown once) or skip with a blocking warning. Keep any reminder state on the client; the server cannot verify that a recovery kit was saved, and should not store an unverifiable recovery-readiness flag.
- Onboarding and settings must state plainly: lose the recovery phrase *and* all devices and the vault is gone — permanently, by design, including from server backups.
- Recovery-phrase compromise is identity compromise: it requires the lock-and-migrate flow (§11.1), not rotation; that UX is a Phase 8 exit item.
- Every recovery-wrap read and recovery-based device registration appears in `account_events` (§4). Clients show these events on every launch and treat an unexpected one as possible phrase compromise, prompting the §11.1 lock. Pending deletion is surfaced the same way.
- The server never auto-revokes a sole device (§8). If a user’s only device is nevertheless revoked or desynchronized and the phrase is lost, the surviving local vault is still intact: the client must offer to register it as a new account with a fresh identity rather than present the vault as lost.

## 14. Implementation phases and exit criteria

**Backend implementation decision (2026-10-23):** the service foundation is a
separate Rust/Axum project at `NexxPassSync/backend`, using PostgreSQL through
SQLx. Signed account registration and authenticated account metadata are the
first implemented protocol endpoints.
The deployment target, independent protocol review, OpenAPI ratification, and
client/server vector agreement remain open Phase 0 gates; this decision does
not mark Phase 0 complete.

### Phase 0 — Protocol freeze

- Check in `docs/crypto-spec.md` and the vector corpus per §2.1, and resolve discrepancies with the client plan, including passkey serialization and key-version allocation. This document defines the server implementation plan.
- Define OpenAPI schemas, canonical error shapes, body/query canonicalization (already locked in §2.2 — the spec confirms it), opaque continuation token format, quotas, and key-wrap recipient-set validation.
- Choose the server language/framework and deployment target here (moved from Phase 1), so the server vector agreement required by the exit criterion is testable.
- Specify the key-separation rules from §2 and the identity lock, migration, deletion, and cancellation message formats (§11.1, §13.2).
- Publish cross-language test vectors for account IDs, signatures, request hashes, and token validation.
- **Exit:** independent review of the protocol and successful Rust/Flutter/server vector agreement; §2.1 register complete; passkey support and serialization scope aligned in this plan and the schema plan.

### Phase 1 — Service foundation

- Configure TLS, secrets, migrations, health checks, structured redacted logs, rate limiting, and database pool for the stack chosen in Phase 0; implement the fail-closed control-plane client (§13.3).
- Implement schema migrations, account-scoped authorization middleware, device revocation checks, and shared atomic nonce consumption.
- **Exit:** integration tests cover signature tampering, replay across two service instances, clock skew, revoked devices, malformed requests, and uniform account-not-found behavior.

### Phase 2 — Registration and keyring

- Implement account registration (with the `deleted_accounts` check and first-device `first_sync_at`), recovery keyring read, device registration/pairing, listing, revocation, `account_events`, and the lock, delete, and cancel endpoints.
- Enforce recipient sets for wraps. The server checks presence/recipient identity and byte constraints; it does not inspect wrap contents.
- **Exit:** concurrent registration tests, revoked-device access tests, recovery restore tests (including recovery registration with zero active devices), retired-ID rejection, identity-lock enforcement, in-place migration (identity keys replaced, old identity rejected afterward, account back to `active`, items and versions untouched, `identity_migrated` visible), phrase-holder deletion cancelled by an active device, uniform pairing creation for existing and nonexistent accounts, and no plaintext/secrets in captured logs.

### Phase 3 — Pull snapshots

- Implement snapshot sessions, bound continuation tokens, the append-only `item_changes` log, fixed high watermark, page-size limits, full snapshots, tombstone rules, and stale-cursor responses. Capture `H` with a lock-free read of the committed counter, locking only the device row.
- Add ack semantics and first-sync completion behavior.
- **Exit:** mutate an item while a snapshot is paginating and prove the snapshot returns its state at `H` while the later state arrives in the next pull; tamper with tokens, replay/out-of-order pages, use another device’s token, expire sessions, crash/restart clients, and prove no change through `H` is skipped, including when `H` is captured without the account lock under concurrent writers.

### Phase 4 — Mutations and batches

- Implement account-row counter locking, conditional put/delete, atomic current-row plus `item_changes` writes, canonical idempotency hash, duplicate checks, partial batch outcomes, quotas, and retry behavior.
- **Exit:** concurrent writers yield consecutive sequences; rollback consumes no sequence; lost response retry returns identical results; operation-ID reuse with different payload rejects; mixed batch retry neither duplicates nor loses writes.

### Phase 5 — Tombstone lifecycle

- Implement acknowledgements, first-sync tracking, tombstone GC, tombstone floor, stale-device revocation, operation/session cleanup, and account quotas.
- **Exit:** GC racing with writes/revoke/acks; new and incomplete devices block GC; clients below floor full-resync; no-active-device policy tested; backup restore preserves counters and floors. The first device is never auto-revoked for lack of an initial pull, a sole device is never auto-revoked for inactivity, and hitting the history or tombstone cap forces resync rather than rejecting writes.

### Phase 6 — Routine rotation

- Implement monotonic target allocation, wrap changes, leases, resume, acks, sweep coordination, completion, and safe abort.
- **Exit:** crash/resume, stale-key writes, concurrent edits, target-key acknowledgement followed by abort attempt, and repeated rotations prove no version reuse. An account near its ciphertext quota completes a sweep; owner revocation clears the lease; routine deadline behavior (auto-abort or lease clear) is tested; recovery registration during a routine rotation succeeds.

### Phase 7 — Compromise rotation

- Implement immediate old-key write rejection, deadlines, automatic revocation of unacknowledged devices, and roll-forward-only completion.
- **Exit:** test all state transitions under concurrent writes, revocation, and service restarts; verify old-key writes fail from start and completion refuses incomplete sweeps. Verify that when the deadline job revokes every device, a recovery-registered device can acknowledge the target and complete the sweep.

### Phase 8 — Hardening and launch readiness

- Ratify the §13.1–§13.4 policy defaults with named owners; validate load tests against the §12 capacity envelope, including the GC-stall alert and runbook from §8.
- Add abuse controls, operational dashboards, backup/restore drills (including the re-applied wrap purge from §11), incident procedure, quotas, migration rollback plan, and independent security review.
- Ship and test the §11.1 lock-and-migrate flow end to end, including client UX for `account_events`, pending deletion, and the sole-device re-registration path (§13.4).
- **Exit:** documented v1 limitations and recovery/rotation/recovery-kit UX; policies ratified; capacity envelope validated or the scaling escape hatch scheduled; no unresolved critical/high findings; production restore drill succeeds.

## 15. Test matrix

At minimum, automate the following against PostgreSQL and multiple API instances:

- sequence ordering, gaplessness, transaction rollback, process crash, lock timeout, and account-row lock ordering;
- fixed-watermark pagination with concurrent item mutation and token tampering, replay, expiry, and cross-device use;
- client checkpoint/ack upper bounds, duplicate/non-monotonic acknowledgements, first-sync completion, and GC interactions;
- lost-response idempotency, same-operation different-payload rejection, duplicate operation IDs in a batch, mixed retries, and operation expiry;
- all create/update/delete/tombstone/permanent-ID cases, including attempts to reuse an ID after tombstone and change-history GC;
- full resync from zero, tombstone omission, staging restart, dirty local records, state-at-watermark during concurrent writes, change-history pruning, and `resync_required`;
- restore/failover with loss of acknowledged history, recovery-mode gating, security-event replay, and deployment-epoch invalidation;
- pairing approval with changed public keys, reused/expired challenges, mismatched verification codes, duplicate device IDs, wrong-account challenge/approval pairs, and approvals attempted during rotation;
- concurrent GC, revoke, ack, mutation, and rotation transitions;
- rotation liveness: recovery registration during routine and compromise rotations, including after every device is lost or revoked; owner revocation clears the lease; routine deadline auto-abort or lease clear;
- lifecycle traps: a first device that never pulls is not revoked at 14 days; a sole device is not revoked at 180 days; cap-driven pruning forces resync without rejecting writes; a near-quota account completes a rotation sweep;
- account lifecycle: phrase-holder deletion cancelled by an active device; `identity_locked` rejects every identity-signed request; in-place identity migration — same account ID, items/versions/sequences untouched, old identity keys rejected afterward, account returned to `active`, `identity_migrated` event emitted, rejected while a rotation runs or deletion is pending, optional old-identity countersignature honored; a hard-purged account ID cannot be registered again, including after restore; recovery reads and recovery registrations emit visible `account_events`;
- pairing creation returns identical responses for existing and nonexistent target accounts, enforces pending caps, and approval is observable by polling `GET /accounts/me`;
- lock-free watermark capture: concurrent writers never leave a `seq <= H` row uncommitted or missing from the session;
- control-plane outage, partition, and stale-cache cases fail closed;
- routine/compromise rotations, leases, restart/resume, abort, target-version retirement, and concurrent client edits;
- quotas, rate limits, request-size boundaries, nonce-store outage, database failover, backup restoration, and secret rotation;
- request-canonicalization fuzz and property tests: duplicate JSON keys, non-canonical base64url and query encodings, unicode edge cases, and oversized integers must reject with identical error codes across implementations;
- protocol-version negotiation: unknown, missing, or malformed `X-NexxPass-Protocol` returns `unsupported_protocol_version` with no side effects;
- log/trace inspection proving no request bodies or secret-bearing headers are retained.

## 16. Deployment and rollout

1. Deploy migrations and service behind a feature flag with account creation disabled.
2. Run protocol-vector and multi-instance integration tests in staging.
3. Enable internal accounts and measure locking, page sizes, quotas, and client retry behavior.
4. Enable opt-in sync for a small cohort. Keep clients local-first and make failed sync visibly retryable without losing local edits.
5. Expand after backup restoration, revocation, full resync, and routine rotation have all been exercised end to end.
6. Enable compromise rotation only after routine rotation and device recovery flows are stable.

Do not launch server sync before client local storage can persist dirty state, item versions, tombstones, key versions, and checkpoints atomically with the user’s vault data.
