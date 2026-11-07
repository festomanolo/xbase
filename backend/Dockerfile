# =============================================================================
# Multi-stage Dockerfile for ultra-low memory (<15MB idle) Rust SaaS backend.
#
# Build context must be the REPOSITORY ROOT (migrations/ is embedded into the
# binary by sqlx::migrate!):
#   docker build -f backend/Dockerfile -t xbase-backend .
# =============================================================================
FROM rust:1.83-slim-bookworm AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/xbase-backend /usr/local/bin/xbase-backend

USER 1000:1000
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/xbase-backend"]
