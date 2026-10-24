# NexxPass Sync backend

Rust/Axum service foundation for the NexxPass zero-knowledge sync protocol.
This is a separate server project; it does not share the mobile app's SQLite
database or vault session.

## Layout

```text
src/
  config.rs       Environment configuration and validation
  auth.rs         Raw-byte request signatures, principal lookup, replay guard
  account.rs      Authenticated account metadata response
  error.rs        One structured API error boundary
  health.rs       Liveness and database readiness probes
  http.rs         Middleware, request IDs, and versioned route composition
  pairing.rs      Anonymous challenge creation and signed device approval
  registration.rs Signed account registration and wire validation
  state.rs        Shared application state and PostgreSQL pool
  main.rs         Process startup and graceful shutdown
migrations/       Versioned PostgreSQL schema migrations
```

Handlers should stay thin: parse and validate transport input, delegate to a
domain/service function, and return a typed response. Protocol rules belong in
shared domain modules, persistence in repositories, and transaction boundaries
in services. Do not log request bodies, authorization/signature headers,
recovery material, wraps, or encrypted item blobs.

Implemented so far: protocol-v1 signed account registration, authenticated
`GET /v1/accounts/me`, and device pairing. A shared verifier checks raw-body
Ed25519 signatures, timestamps, canonical paths/encodings, account/device key binding, device
revocation, account identity-lock state, and atomically consumed nonces. Account
registration stores the account, first device, and version-1 wraps atomically;
the metadata endpoint returns only the caller device's wrap, visible account
events, checkpoint, and rotation/write-freeze status. The schema now reserves
rotation participants and acknowledgements for cross-device master-password
change, but no rotation transition endpoint is exposed yet. Pairing creates
short-lived account-bound challenges without checking account existence, then
registers the proposed device and its opaque key wraps atomically after an
existing device approves the signed request. It supports adding a device during
master-password change only when both active and target wraps are supplied.
Pairing challenge rate limits are not implemented yet. The implementation is
early and not production-ready: recovery registration/event writes, pulls,
mutations, rotation transitions, retention jobs, rate limits, and full account
lifecycle remain absent. Follow
`../../nexxpass/docs/zero-knowledge-sync-server-plan.md`; its deployment target and
remaining Phase 0 review gates are still open.

## Local development

1. Start PostgreSQL and set `DATABASE_URL` (see `.env.example`).
2. Run `cargo run` from this directory.
3. Check `GET /health/live` and `GET /health/ready`.

Migrations currently run at startup for local development. Production rollout
needs a separate migration release step and TLS at a trusted ingress; the
service must not sit behind a proxy that rewrites signed request bytes or paths.
