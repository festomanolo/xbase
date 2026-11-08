# CLAUDE.md — `xbase` Project Guide & Architecture

## Overview

**`xbase`** is a self-hosted **Supabase + Rust (`Axum` + `SQLx`)** multi-SaaS platform architecture designed to run **10+ SaaS applications on a single Linux VPS** with minimal memory overhead (`<15MB` idle RAM per Rust backend binary) and shared PostgreSQL connection pooling via **Supavisor** (port `6543`).

---

## Repository Structure

```text
xbase/
├── CLAUDE.md / README.md
├── .env.example                       # Root env template (Supabase + SMTP + OAuth + backends)
├── migrations/                        # Embedded via sqlx::migrate!, applied on boot over port 5432
│   ├── 0001_init_multi_saas.sql       # xbase.apps, xbase.workspaces
│   ├── 0002_platform_core.sql         # members, invitations, api_keys, jobs, webhook_events, CDC triggers, RLS + grants
│   └── 0003_vector_embeddings.sql     # pgvector xbase.embeddings (vector(1536), HNSW)
├── backend/src/                       # Rust (Axum 0.7 + SQLx 0.8 + Tokio)
│   ├── main.rs       # boot: migrations → pool → register app → job workers → CDC listener → serve
│   ├── config.rs     # AppConfig (all env vars; AppConfig::for_tests())
│   ├── state.rs      # AppState { pool, config, http, realtime, limiter, jobs_notify, metrics }
│   ├── error.rs      # ApiError (sqlx/reqwest mapping: 23505→409, 42501→403, P0001→400 ...)
│   ├── db.rs         # Supavisor pool (statement_cache_capacity(0)), run_migrations, register_app
│   ├── rls.rs        # begin_rls / with_rls_claims (set_config role + request.jwt.claims, tx-local)
│   ├── auth.rs       # SupabaseClaims, UserToken, AdminClaims, Principal (JWT | ApiKey)
│   ├── gotrue.rs     # GoTrue proxy: signup/token/refresh/otp/magiclink/verify/recover/authorize/exchange/user/logout + admin users
│   ├── workspaces.rs # workspace/member/invitation CRUD (all via begin_rls)
│   ├── api_keys.rs   # xb_<prefix>_<secret>, SHA-256 hashed, scopes, management endpoints
│   ├── storage.rs    # Supabase Storage proxy: buckets (admin), signed URLs, streaming objects, TUS, transforms
│   ├── realtime.rs   # /ws hub: rooms, broadcast, presence, NOTIFY xbase_changes → subscribers
│   ├── vector.rs     # pgvector upsert/search, OpenAI-compatible embeddings, reindex job
│   ├── billing.rs    # Stripe + LemonSqueezy signature verification → webhook_events → job → plan sync
│   ├── jobs.rs       # SKIP LOCKED queue, backoff, reaper; add kinds in jobs::dispatch
│   ├── rate_limit.rs # sharded token bucket keyed api-key > user > IP
│   ├── metrics.rs    # Prometheus text /metrics
│   └── routes.rs     # build_router + HTTP tests
├── go-backend/                        # Go template: net/http + pgx (QueryExecModeExec), WithRLS, API keys, rate limit
├── docker/
│   ├── docker-compose.saas.yml        # Rust saas-api-1 + Go saas-api-2 + Caddy (build context = repo root)
│   ├── docker-compose.monitoring.yml  # Prometheus, Alertmanager, Grafana, node-exporter, cAdvisor
│   ├── supabase-auth.override.yml     # GoTrue OAuth/SAML/SMTP env layer
│   ├── monitoring/                    # prometheus.yml, alerts.yml, alertmanager.yml, grafana datasource
│   └── Caddyfile
└── scripts/
    ├── bootstrap-supabase.sh          # clone + upstream generate-keys.sh (ANON/SERVICE keys match JWT_SECRET)
    ├── backup-postgres.sh / restore-postgres.sh / install-backups.sh
    └── db-branch.sh                   # branch_<name> databases for previews
```

---

## Key Commands

```bash
./scripts/bootstrap-supabase.sh                       # Supabase docker + secrets
cd backend && cargo test                              # Rust unit + HTTP tests (no DB needed)
cd backend && cp .env.example .env && cargo run       # needs DATABASE_URL + DIRECT_DATABASE_URL
cd go-backend && go test ./...                        # Go tests
docker build -f backend/Dockerfile .                  # Rust image: build context MUST be repo root
cd docker && docker compose --env-file ../supabase-project/.env -f docker-compose.saas.yml up -d --build
```

---

## Architectural Invariants

1. **Supavisor (`6543`) transaction mode for request traffic**, `statement_cache_capacity(0)` in `db.rs` (Go: `QueryExecModeExec`). Anything needing a session — migrations (advisory lock) and `LISTEN` — uses `DIRECT_DATABASE_URL` (`5432`).
2. **Zero-network JWT validation** with `SUPABASE_JWT_SECRET`. `sub` is optional in `SupabaseClaims` because Supabase `anon`/`service_role` keys have none; the extractor rejects sub-less tokens unless role is `service_role`.
3. **Postgres is the authorization layer.** User-facing queries go through `rls::begin_rls`, never the bare pool. Policies live in migrations; billing/secret columns are protected by column-level grants. Internal tables (`jobs`, `webhook_events`) have RLS on and no policies.
4. **Everything is scoped by `APP_ID`**: workspaces (`app_slug`), API keys, jobs, webhook events, embeddings, storage buckets (`<APP_ID>-<name>`). Never query those tables without the app predicate.
5. **API-key principals** bypass RLS (service connection), so handlers must call `Principal::require_workspace_scope` and keep explicit `workspace_id`/`app_slug` predicates.
6. **Migrations are append-only** (sqlx checksums). Add `000N_*.sql`; never edit applied files. `set_ignore_missing(true)` lets older binaries boot against newer schemas.

---

## What Is Implemented

- [x] Auth: GoTrue proxy for sign-up, password sign-in, OTP, magic link, verify, recovery, OAuth redirect + PKCE exchange, refresh rotation, user update, logout; admin user CRUD (service_role or `ADMIN_USER_IDS`).
- [x] RLS impersonation (`begin_rls`, `with_rls_claims`) used by every user-facing query.
- [x] Automated migrations on boot over the direct connection.
- [x] Storage: per-app buckets, signed upload/download URLs, image transforms, streaming upload/download proxy, batch delete, list, TUS resumable upload details.
- [x] Realtime: `/ws` rooms, broadcast, presence, private `workspace:<id>` rooms, Postgres CDC via `NOTIFY xbase_changes`, token refresh, heartbeats.
- [x] CRUD: workspaces, memberships (roles owner/admin/member/viewer), invitations (hashed single-use tokens, `xbase.accept_invitation`).
- [x] Billing: Stripe + LemonSqueezy webhook verification, idempotent event log, plan/status/period sync; durable background job queue.
- [x] pgvector embeddings with server-side embedding (OpenAI-compatible), metadata filters, reindex job.
- [x] Per-key/user/IP token-bucket rate limiting; hashed scoped API keys (`x-api-key`).
- [x] Prometheus `/metrics`; Go backend template; ops: secrets bootstrap (fixed ANON/SERVICE key mismatch), SMTP/OAuth/SAML override, encrypted backups + restore + systemd timer, DB branching, monitoring + alerts.

Verified end-to-end against `supabase/postgres:17.6.1.136` (RLS isolation, invitations, API keys, vector search, Stripe→plan sync, realtime presence/broadcast/CDC, backup→restore round-trip, branching).

---

## Known Gaps / Next Steps

| Area | Gap |
| :--- | :--- |
| Horizontal scaling | Realtime hub and rate limiter are in-memory per process. Running >1 replica of the same SaaS needs room fan-out over `NOTIFY` (or Redis) and a shared limiter. |
| Storage via API keys | Storage endpoints accept user JWTs only (Storage RLS needs a user identity). |
| Dynamic REST | No PostgREST-style query builder in Rust; the Supabase PostgREST container already serves `/rest/v1` for generic CRUD. |
| PITR | Nightly logical dumps only (24h RPO). Add WAL-G/pgBackRest WAL archiving for point-in-time recovery. |
| Go template parity | Go service covers health, me, workspaces, API-key auth and rate limiting — not storage/realtime/billing/vector. |
| Storage policies | Create `storage.objects` RLS policies per bucket (e.g. `(storage.foldername(name))[1] = auth.uid()::text`) — not shipped as migrations because buckets are app-specific. |
| Multi-project Studio | Self-hosted Studio manages one cluster; isolation is logical (`app_slug` / per-SaaS schemas). |
