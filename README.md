# NexxPassSync

[![CI](https://github.com/Genocadio/NexxPassSync/actions/workflows/ci.yml/badge.svg)](https://github.com/Genocadio/NexxPassSync/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![PostgreSQL](https://img.shields.io/badge/postgresql-17-blue.svg)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)]()

High-performance, production-grade **Zero-Knowledge Dumb Sync Server** for multi-device password managers.

The server acts as a hardened, blind cryptographic store: it stores only authenticated, encrypted ciphertext blobs, asymmetric key wraps, and monotonic revision sequences. The server has **zero access** to user passwords, master keys, or vault contents.

---

## Key Features

* **True Zero-Knowledge Blindness**: The server cannot decrypt vault records or verify password strings. All plaintexts and master keys remain strictly on client hardware.
* **Cryptographic Request Signing (`NPSSv1`)**: Every API request is signed with hardware-bound **Ed25519** keys over a canonical preimage (`METHOD`, `PATH`, `QUERY`, `TIMESTAMP`, `NONCE`, `SHA256(BODY)`), eliminating cookie and bearer token vulnerabilities.
* **Idempotent Batch Sync (`/v1/sync/batch`)**: Atomic mutations with SHA-256 operation deduplication, monotonic account revision counters, and item retirement markers.
* **Real-Time Push via Server-Sent Events (`/v1/sync/events`)**: Sub-50ms push notifications (`{"seq": N}`) without client polling loops. The stream carries **no ciphertext or metadata**, preserving complete privacy while saving mobile battery.
* **Option A Non-Blocking Master Password Changes**:
  * Device A initiates a password change, re-encrypts live items, and completes immediately.
  * Normal writes unfreeze right away under the new key version.
  * Offline devices waking up later are blocked from writing stale data (`unsupported_key_version`), prompt the user for the new password, unwrap the new key from their pre-provisioned asymmetric key wrap, and acknowledge without freezing the account.
* **QR Code Device Pairing**: Enrolling a new device uses optical camera scanning to perform an out-of-band cryptographic key exchange (X25519 + HKDF-SHA256), protected by tamper-proof `device_pub_digest` binding.
* **Hardened Background Maintenance**: Hourly automated GC sweeps with **PostgreSQL Advisory Locking** (`0x4e65787850617373`), pruning tombstones older than 90 days and revoking inactive devices (>180 days) safely across distributed multi-replica deployments.
* **Production Defenses**:
  * Per-account storage quotas (max 10 active devices, 25,000 items, 50 MB ciphertext).
  * High-throughput two-generation in-memory replay filter ($O(1)$ memory rejection).
  * Database statement timeouts (`statement_timeout = '10s'`) and pool lifecycle management.
  * Strict defensive headers (`Cache-Control: no-store`, `nosniff`, `HSTS`, `X-Frame-Options: DENY`).

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────┐
│                   NexxPass Sync Architecture           │
└────────────────────────────────────────────────────────┘

    Device 1 (MacBook)                      Device 2 (iPhone)
   [Ed25519 / X25519]                      [Ed25519 / X25519]
           │                                       │
           │ 1. Optical QR Code Handshake          │
           │ (Wraps Master Key to Dev 2 PubKey)    │
           │◄─────────────────────────────────────►│
           │                                       │
           │ 2. Signed Batch Writes                │ 3. Real-Time SSE
           │    (NPSSv1 Headers)                   │    Notifications
           ▼                                       ▼
  ┌─────────────────────────────────────────────────────────┐
  │         NexxPass Sync Server (Axum / Tokio / Rust)       │
  │                                                         │
  │  • Replay Filter (Two-Gen Cache) • Statement Timeout    │
  │  • Quota Enforcer (50MB / 10 Dev) • Advisory Locker     │
  └────────────────────────────┬────────────────────────────┘
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────┐
  │               PostgreSQL 17 (Atomic Storage)            │
  │                                                         │
  │  • accounts          • devices          • key_wraps     │
  │  • items (blobs)     • item_changes     • sync_sessions │
  │  • operations (dedup)• pairing_challenges               │
  └─────────────────────────────────────────────────────────┘
```

---

## Quickstart

### 1. Run with Docker Compose (Recommended)

Clone the repository and start the cluster:
```bash
git clone git@github.com:Genocadio/NexxPassSync.git
cd NexxPassSync

# Start PostgreSQL and Sync Server with healthchecks
docker compose up -d --build
```

Verify service readiness:
```bash
curl http://localhost:8080/health/ready
# {"status":"ready","database":"connected"}
```

---

### 2. Run Natively with Cargo

Prerequisites: Rust 1.85+ and PostgreSQL 16+.

```bash
# Set environment variables (or copy .env.example)
export DATABASE_URL="postgres://nexxpass:change-me@localhost:5432/nexxpass_sync"

# Run migrations and start the server
cargo run --manifest-path backend/Cargo.toml --bin nexxpass-sync-server
```

---

### 3. Run the Multi-Device CLI Simulator

Verify the entire protocol live across multiple simulated devices:
```bash
cargo run --manifest-path backend/Cargo.toml --bin simulator
```

The simulator automatically exercises:
1. Account enrollment and vault initialization.
2. QR Code device pairing handshake.
3. Real-time SSE notification stream push (<50ms latency).
4. Option A master password rotation with offline device wake-up and key unwrapping.
5. Device activity audits (`last_seen_at` and `first_sync_at`).

---

## API Reference Summary

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health/live` | `GET` | None | Fast process liveness probe. |
| `/health/ready` | `GET` | None | Deep PostgreSQL pool connectivity probe. |
| `/v1/accounts` | `POST` | Identity | Enrolls a new user account with initial device wrap. |
| `/v1/accounts/me` | `GET` | Device | Fetches active key versions, keyring version, and key wraps. |
| `/v1/accounts` | `DELETE` | Identity | Requests permanent account deletion (30-day grace). |
| `/v1/devices` | `GET` | Device | Lists all enrolled devices with live `last_seen_at` timestamps. |
| `/v1/devices` | `POST` | Identity | Registers a replacement device using the recovery phrase. |
| `/v1/devices/{device_id}` | `DELETE` | Device | Revokes an active device immediately. |
| `/v1/pairings` | `POST` | None | Initiates a 5-minute QR pairing challenge. |
| `/v1/pairings/{id}/approve` | `POST` | Device | Approves challenge and delivers an encrypted key wrap. |
| `/v1/sync/batch` | `POST` | Device | Pushes atomic batch mutations (`put`/`delete`) with deduplication. |
| `/v1/sync/pull` | `POST` | Device | Multi-page pull with continuation tokens and page receipts. |
| `/v1/sync/ack` | `POST` | Device | Acknowledges receipt and advances `last_seen_seq`. |
| `/v1/sync/events` | `GET` | Device | Real-time Server-Sent Events stream (`{"seq": N}`). |
| `/v1/rotation/start` | `POST` | Device | Starts key rotation or Option A password change. |
| `/v1/rotation/rewrite` | `POST` | Device | Submits re-encrypted ciphertext blobs. |
| `/v1/rotation/complete` | `POST` | Device | Option A completion: unfreezes writes immediately. |
| `/v1/rotation/ack` | `POST` | Device | Offline device acknowledges new master key version. |

See [`openapi.yaml`](openapi.yaml) for the complete OpenAPI 3.1 schema.

---

## Configuration Reference

| Environment Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | *(Required)* | PostgreSQL connection URL. |
| `SYNC_BIND_ADDR` | `0.0.0.0:8080` | TCP socket bind address. |
| `SYNC_DATABASE_MAX_CONNECTIONS` | `10` | Maximum SQLx connection pool size. |
| `SYNC_TOKEN_KEY_HEX` | *(Default test key)* | 32-byte hex secret for HMAC-signing pull tokens. |
| `SYNC_DEPLOYMENT_EPOCH` | `1` | Incrementing epoch invalidates older pull sessions. |
| `SYNC_MAINTENANCE_INTERVAL_SECONDS` | `3600` | Periodic background GC interval (seconds). |
| `RUST_LOG` | `info` | Tracing log filter (`info`, `debug`, `trace`). |

---

## Testing & Code Quality

Run the test suite:
```bash
cargo test --manifest-path backend/Cargo.toml --all-targets
```

Run static analysis and formatting checks:
```bash
cargo clippy --manifest-path backend/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path backend/Cargo.toml -- --check
```

---

## Security Invariants

* **Blindness**: Passwords, derived keys, and plaintexts never cross the network.
* **No Table Scans on Hot Path**: Partial indexes (`idx_items_rotation_rewrite`, `idx_items_tombstone_prune`) keep queries fast.
* **Lock Order**: Row-level locking follows strict hierarchical order: `accounts` first, then `devices`, preventing database deadlocks.
* **Stateless Token Verification**: Continuation tokens are signed using HMAC-SHA256, eliminating server memory leaks during large sync pulls.
