# =============================================================================
# Multi-stage Dockerfile for ultra-low memory (<15MB idle) Rust SaaS backend.
#
# Build context must be the REPOSITORY ROOT (migrations/ is embedded into the
# binary by sqlx::migrate!):
#   docker build -f backend/Dockerfile -t xbase-backend .
# =============================================================================
FROM rust:1-slim-bookworm AS builder
WORKDIR /app/backend

# Cache dependency compilation separately from application code.
COPY backend/Cargo.toml backend/Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src target/release/deps/xbase_backend* target/release/xbase-backend*

COPY migrations /app/migrations
COPY backend/src ./src
RUN cargo build --release && strip target/release/xbase-backend

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/backend/target/release/xbase-backend /usr/local/bin/xbase-backend

USER 1000:1000
EXPOSE 3000
# start-period covers the few seconds the app waits on the database at boot.
HEALTHCHECK --interval=10s --timeout=4s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/xbase-backend", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/xbase-backend"]
