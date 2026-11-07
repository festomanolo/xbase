# CLAUDE.md — `xbase` Project Guide & Architecture

## Overview

**`xbase`** is a self-hosted **Supabase + Rust (`Axum` + `SQLx`)** multi-SaaS platform architecture designed to run **10+ SaaS applications on a single Linux VPS** with minimal memory overhead (`<15MB` idle RAM per Rust backend binary) and shared PostgreSQL connection pooling via **Supavisor** (port `6543`).

---

## Repository Structure

```text
xbase/
├── CLAUDE.md                          # AI/Developer architecture & implementation gap guide
├── README.md                          # VPS self-hosting setup & Rust/Go integration guide
├── .env.example                       # Root environment template for Supabase + Rust backend
├── scripts/
│   └── bootstrap-supabase.sh          # Shallow-clones supabase/supabase & generates secrets
├── docker/
│   ├── docker-compose.saas.yml        # Multi-SaaS Rust containers + Caddy reverse proxy stack
│   └── Caddyfile                      # Automatic Let's Encrypt HTTPS routing for Kong & SaaS APIs
├── migrations/
│   └── 0001_init_multi_saas.sql       # Multi-SaaS schema (xbase.apps, xbase.workspaces) + RLS
└── backend/                           # Rust (Axum 0.7 + SQLx 0.8 + Tokio) backend service
    ├── Cargo.toml
    ├── Dockerfile                     # Multi-stage Debian bookworm-slim build
    ├── .env.example
    └── src/
        ├── main.rs                    # Entrypoint, tracing, CORS, graceful shutdown
        ├── config.rs                  # Environment config loader (AppConfig)
        ├── db.rs                      # Supavisor PgPool builder (statement_cache_capacity(0))
        ├── auth.rs                    # Local HS256 Supabase JWT extractor (SupabaseClaims)
        └── routes.rs                  # HTTP routes (/health, /health/db, /api/v1/me, /api/v1/tenants/:app_slug)
```

---

## Key Commands

```bash
# Bootstrap official self-hosted Supabase Docker stack & generate secrets
./scripts/bootstrap-supabase.sh

# Run Rust backend unit tests
cd backend && cargo test

# Run Rust backend locally
cd backend && cp .env.example .env && cargo run

# Build production release binary
cd backend && cargo build --release
```

---

## Architectural Invariants

1. **Always Connect via Supavisor (`6543`) in Transaction Mode**:
   When running 10+ SaaS backends against a single PostgreSQL instance, backends must connect through Supavisor (`port 6543`) and disable SQLx's prepared statement cache (`statement_cache_capacity(0)` in `backend/src/db.rs`) so multiplexed connections never collide on prepared statements.
2. **Zero-Network JWT Validation**:
   `backend/src/auth.rs` validates Supabase GoTrue HS256 JWTs locally using `SUPABASE_JWT_SECRET` rather than making an HTTP call to GoTrue on every request.
3. **Logical Multi-SaaS Isolation**:
   All 10+ SaaS applications share one Postgres cluster isolated by `app_slug` (in schema `xbase`) or per-SaaS schemas, enforced by Row-Level Security (RLS) and explicit `app_slug` + `owner_id` predicates.

---

## What Is Currently Implemented

- [x] Self-hosted Supabase bootstrap script (`scripts/bootstrap-supabase.sh`) with automated cryptographic secret generation (`POSTGRES_PASSWORD`, `JWT_SECRET`, `DASHBOARD_PASSWORD`, `SECRET_KEY_BASE`, `VAULT_ENC_KEY`).
- [x] Companion Docker Compose stack (`docker/docker-compose.saas.yml`) & `docker/Caddyfile` reverse proxy for automatic Let's Encrypt TLS.
- [x] Starter multi-SaaS SQL migration (`migrations/0001_init_multi_saas.sql`) with `xbase.apps`, `xbase.workspaces`, and RLS policies.
- [x] Rust (`Axum` + `SQLx`) backend with Supavisor-compatible connection pooling (`statement_cache_capacity(0)`).
- [x] Local Supabase JWT verification middleware/extractor (`SupabaseClaims`).
- [x] Liveness (`/health`), database readiness (`/health/db`), current user (`/api/v1/me`), and tenant workspace listing (`/api/v1/tenants/:app_slug`) endpoints with unit tests.

---

## What Is NOT Yet Implemented (Compared to Full Supabase)

### A. Missing in `xbase-backend` (Rust Service Layer)

| Feature Area | Current Status | What Needs to Be Implemented |
| :--- | :--- | :--- |
| **1. Auth (GoTrue) Operations** | Only verifies existing Bearer JWTs (`backend/src/auth.rs`). | Sign-up, sign-in (email/password, magic link, OTP), OAuth provider callbacks, token refresh rotation, password reset, and Admin User CRUD (either via GoTrue HTTP proxy client or native Rust auth endpoints). |
| **2. Database RLS Impersonation** | Queries run using the pool's connection role with manual `WHERE owner_id = $2` filters. | A transaction wrapper (`with_rls_claims(pool, claims, ...)`) that executes `SET LOCAL role = 'authenticated'; SET LOCAL request.jwt.claims = '...';` so PostgreSQL natively enforces Supabase RLS policies on all queries. |
| **3. Automated Migrations on Boot** | SQL migration file sits in `migrations/0001_init_multi_saas.sql`. | Wire `sqlx::migrate!("../migrations")` into `backend/src/main.rs` (using a direct port `5432` session connection at startup) to apply schema migrations automatically. |
| **4. Storage (Buckets & Objects)** | Not implemented in Rust backend. | Rust client/endpoints for creating buckets, generating presigned upload/download URLs, multipart uploads, and image transformations against Supabase Storage API or S3/MinIO. |
| **5. Realtime (WebSockets / Presence / CDC)** | Handled externally by the Supabase Realtime container. | Native Axum WebSocket endpoints (`/ws`), room broadcast channels, presence tracking, and Postgres `LISTEN/NOTIFY` or logical replication (`pgoutput`) change streams. |
| **6. Dynamic REST / GraphQL CRUD** | Only explicit typed routes exist in `backend/src/routes.rs`. | CRUD endpoints for creating/updating/deleting workspaces, memberships, invitations, and per-SaaS domain entities (or dynamic PostgREST-style query builders). |
| **7. Billing & Webhooks (Edge Functions)** | Not implemented. | Stripe / LemonSqueezy webhook signature verification (`/webhooks/stripe`), subscription state syncing into `xbase.workspaces.plan`, and background job workers. |
| **8. Vector / AI (`pgvector`)** | Not included in `backend/Cargo.toml`. | `pgvector` crate integration for storing and querying OpenAI/local embeddings per SaaS tenant. |
| **9. Rate Limiting & API Keys** | Only JWT Bearer auth is supported. | Per-tenant/per-IP token-bucket rate limiting (`tower-governor`) and hashed API key authentication (`x-api-key`) for server-to-server SaaS integrations. |

---

### B. Missing in Self-Hosted Supabase (Docker) vs. Supabase Cloud

When running the official self-hosted Supabase Docker stack (`scripts/bootstrap-supabase.sh`), the following **Supabase Cloud** control-plane features are not included out of the box and must be added if needed:

1. **Multi-Project Studio UI**: Self-hosted Supabase Studio manages a single PostgreSQL cluster. Hosting 10 SaaS apps requires logical separation (`app_slug` column or separate PostgreSQL schemas like `saas_1`, `saas_2`) rather than separate projects in Studio.
2. **Production SMTP Delivery**: Self-hosted GoTrue uses a local fake/Inbucket mail catcher by default. Production requires configuring `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_ADMIN_EMAIL` (e.g., Resend, AWS SES, Postmark) in `supabase-project/.env`.
3. **Automated Backups & Point-in-Time Recovery (PITR)**: No built-in cloud backup scheduler. Requires a cron/systemd timer running `pg_dump` or `WAL-G` / `pgBackRest` shipping encrypted backups to S3 / Cloudflare R2 / Backblaze B2.
4. **Database Branching**: Ephemeral preview branches per Git pull request are not built into the self-hosted stack.
5. **Log Drains & Metrics Alerting**: Vector/Logflare is included for basic Studio logs, but Prometheus/Grafana alerting for VPS disk, RAM, and container health must be configured separately.
6. **Custom OAuth & SAML Configuration UI**: OAuth providers (Google, GitHub, Apple, etc.) must be enabled via environment variables (`GOTRUE_EXTERNAL_<PROVIDER>_ENABLED=true`) in `supabase-project/.env` rather than toggled in the Studio UI.
