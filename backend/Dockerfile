# Stage 1: Build binary
FROM rust:1-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY backend/Cargo.toml backend/Cargo.lock ./backend/
COPY backend/src ./backend/src/
COPY backend/migrations ./backend/migrations/

WORKDIR /app/backend
RUN cargo build --release --locked --bin nexxpass-sync-server

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 nexxpass && \
    useradd -u 10001 -g nexxpass -m -s /bin/false nexxpass

USER nexxpass

COPY --from=builder --chown=nexxpass:nexxpass /app/backend/target/release/nexxpass-sync-server /usr/local/bin/nexxpass-sync-server

EXPOSE 8080

ENV SYNC_BIND_ADDR=0.0.0.0:8080
ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/nexxpass-sync-server"]
