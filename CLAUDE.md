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
│   ├── 0003_vector_embeddings.sql     # pgvector xbase.embeddings (vector(1536), HNSW)
│   ├── 0004_shared_rate_limit.sql     # UNLOGGED xbase.rate_limits + xbase.rate_limit_check() (shared token bucket)
│   └── 0005_storage_policies.sql      # xbase.can_access_storage_object() + storage.objects policies (skips if not owner)
├── backend/src/                       # Rust (Axum 0.7 + SQLx 0.8 + Tokio)
│   ├── main.rs       # boot: migrations → pool → register app → job workers → CDC listener → serve
│   ├── config.rs     # AppConfig (all env vars; AppConfig::for_tests())
│   ├── state.rs      # AppState { pool, config, http, realtime, limiter, jobs_notify, metrics, rest_cache }
│   ├── error.rs      # ApiError (sqlx/reqwest mapping: 23505→409, 42501→403, P0001→400 ...)
│   ├── db.rs         # Supavisor pool (statement_cache_capacity(0)), run_migrations, register_app
│   ├── rls.rs        # begin_rls / with_rls_claims (set_config role + request.jwt.claims, tx-local)
│   ├── auth.rs       # SupabaseClaims, UserToken, AdminClaims, Principal (JWT | ApiKey)
│   ├── gotrue.rs     # GoTrue proxy: signup/token/refresh/otp/magiclink/verify/recover/authorize/exchange/user/logout + admin users
│   ├── workspaces.rs # workspace/member/invitation CRUD (all via begin_rls)
│   ├── api_keys.rs   # xb_<prefix>_<secret>, SHA-256 hashed, scopes, management endpoints
│   ├── storage.rs    # Supabase Storage proxy: buckets (admin), signed URLs, streaming objects, TUS, transforms; user JWT or API key (confined to <workspace_id>/)
│   ├── realtime.rs   # /ws hub: rooms, broadcast, presence, NOTIFY xbase_changes → subscribers; REALTIME_CLUSTER fan-out over NOTIFY xbase_rt_<app>
│   ├── rest.rs       # PostgREST-style CRUD /api/v1/rest/:table (catalog-validated identifiers, bound values, RLS)
│   ├── vector.rs     # pgvector upsert/search, OpenAI-compatible embeddings, reindex job
│   ├── billing.rs    # Stripe + LemonSqueezy signature verification → webhook_events → job → plan sync
│   ├── jobs.rs       # SKIP LOCKED queue, backoff, reaper; add kinds in jobs::dispatch
│   ├── rate_limit.rs # token bucket keyed api-key > user > IP; backend memory | postgres (shared across replicas)
│   ├── metrics.rs    # Prometheus text /metrics
│   └── routes.rs     # build_router + HTTP tests
├── go-backend/                        # Go template: net/http + pgx (QueryExecModeExec), WithRLS, API keys, shared rate limit,
│   └── internal/httpapi/              #   storage, vector, billing, realtime (+cluster), /metrics (same wire protocols as Rust)
├── docker/
│   ├── docker-compose.saas.yml        # Rust saas-api-1 + Go saas-api-2 + Caddy (build context = repo root)
│   ├── docker-compose.monitoring.yml  # Prometheus, Alertmanager, Grafana, node-exporter, cAdvisor
│   ├── supabase-auth.override.yml     # GoTrue OAuth/SAML/SMTP env layer
│   ├── supabase-pitr.override.yml     # enables WAL archiving (archive_mode/archive_command) on the Supabase db service
│   ├── storage-policies.sql           # same policy SQL as migration 0005, for running as the DB superuser
│   ├── monitoring/                    # prometheus.yml, alerts.yml, alertmanager.yml, grafana datasource
│   └── Caddyfile
└── scripts/
    ├── bootstrap-supabase.sh          # clone + upstream generate-keys.sh (ANON/SERVICE keys match JWT_SECRET)
    ├── backup-postgres.sh / restore-postgres.sh / install-backups.sh   # nightly logical dumps
    ├── pitr.sh / install-pitr.sh      # WAL shipping + base backups + point-in-time restore rehearsal (RPO ≈ 1-2 min)
    ├── apply-storage-policies.sh      # install storage.objects policies as supabase_admin
    └── db-branch.sh                   # branch_<name> databases for previews
```

---

## Key Commands

```bash
./scripts/bootstrap-supabase.sh                       # Supabase docker + secrets
cd backend && cargo test                              # Rust unit + HTTP tests (no DB needed)
cd backend && cp .env.example .env && cargo run       # needs DATABASE_URL + DIRECT_DATABASE_URL
cd go-backend && go test -race ./...                  # Go tests (WebSocket + storage proxy use in-process fakes)
sudo ./scripts/install-pitr.sh && sudo xbase-pitr status   # point-in-time recovery (see README → Operations)
./scripts/apply-storage-policies.sh                   # only if migration 0005 printed "skipped storage.objects policies"
docker build -f backend/Dockerfile .                  # Rust image: build context MUST be repo root
cd docker && docker compose --env-file ../supabase-project/.env -f docker-compose.saas.yml up -d --build
```

---

## Architectural Invariants

1. **Supavisor (`6543`) transaction mode for request traffic**, `statement_cache_capacity(0)` in `db.rs` (Go: `QueryExecModeExec`). Anything needing a session — migrations (advisory lock) and `LISTEN` — uses `DIRECT_DATABASE_URL` (`5432`).
2. **Zero-network JWT validation** with `SUPABASE_JWT_SECRET`. `sub` is optional in `SupabaseClaims` because Supabase `anon`/`service_role` keys have none; the extractor rejects sub-less tokens unless role is `service_role`.
3. **Postgres is the authorization layer.** User-facing queries go through `rls::begin_rls`, never the bare pool. Policies live in migrations; billing/secret columns are protected by column-level grants. Internal tables (`jobs`, `webhook_events`) have RLS on and no policies.
4. **Everything is scoped by `APP_ID`**: workspaces (`app_slug`), API keys, jobs, webhook events, embeddings, storage buckets (`<APP_ID>-<name>`). Never query those tables without the app predicate.
5. **API-key principals** bypass RLS (service connection), so handlers must call `Principal::require_workspace_scope` and keep explicit `workspace_id`/`app_slug` predicates. Storage is the same rule on the file side: a key runs with the service role, so `storage.rs` confines it to `<its workspace_id>/…` and to the `storage:read` / `storage:write` scopes. The generic REST API never accepts keys.
6. **Object naming convention:** storage objects live at `<workspace_uuid>/<path>` in bucket `<APP_ID>-<name>`. The `storage.objects` policies (migration 0005), the API-key confinement in `storage.rs` and the Go proxy all depend on it.
7. **Multi-replica rules.** More than one replica of an `APP_ID` requires `RATE_LIMIT_BACKEND=postgres` and `REALTIME_CLUSTER=true` on every replica. Cluster messages must stay under the NOTIFY limit (~7 KB). Jobs, migrations and CDC are already replica-safe (`SKIP LOCKED`, advisory lock, per-replica `LISTEN`).
8. **REST API safety:** identifiers only ever come from the catalog and are quoted; values are always bound (`($n::text)::<column type>`). `xbase`, `auth`, `storage` and other internals are refused regardless of `REST_SCHEMAS`; PATCH/DELETE require a filter.
9. **Migrations are append-only** (sqlx checksums). Add `000N_*.sql`; never edit applied files. `set_ignore_missing(true)` lets older binaries boot against newer schemas.

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
- [x] **Horizontal scaling:** `RATE_LIMIT_BACKEND=postgres` shares one token bucket per key across replicas (atomic upsert in `xbase.rate_limit_check`, 250 ms budget, falls back to the local bucket); `REALTIME_CLUSTER=true` replays broadcast + presence to other replicas over `NOTIFY xbase_rt_<app>` (presence diffs + 30 s sync + 90 s expiry). Metrics: `xbase_rate_limit_fallbacks_total`, `xbase_realtime_cluster_messages_total`.
- [x] **Storage via API keys** (`storage:read` / `storage:write`, confined to `<workspace_id>/`) and **storage policies** (migration 0005 + `scripts/apply-storage-policies.sh`): workspace members read, owner/admin/member write.
- [x] **REST:** `/api/v1/rest/:table` with select/filters (`eq neq gt gte lt lte like ilike is in not.`)/order/limit/offset, insert (batch + upsert), PATCH, DELETE, `Prefer: count=exact`. Opt-in with `REST_ENABLED=true`.
- [x] **PITR:** WAL archiving override + `pitr.sh` (ship-wal, base-backup, prune, status, restore into a throwaway container); everything encrypted before upload.
- [x] **Go parity:** storage, vector (no reindex job), billing (plan sync inline in the webhook transaction), realtime incl. cluster mode, shared rate limiter, `/metrics`, service-role admin gate.
- [x] Prometheus `/metrics`; Go backend template; ops: secrets bootstrap (fixed ANON/SERVICE key mismatch), SMTP/OAuth/SAML override, encrypted backups + restore + systemd timer, DB branching, monitoring + alerts.

Verified end-to-end against `supabase/postgres:17.6.1.136` (RLS isolation, invitations, API keys, vector search, Stripe→plan sync, realtime presence/broadcast/CDC, backup→restore round-trip, branching) — **that run predates the items marked "Needs live verification" below.**

### Live verification (2026-11-08)

Run against `supabase/postgres:17.6.1.136`, the real `supabase/storage-api:v1.25.7`, two replicas of each backend, and (for PITR) a Linux container with `rclone` + `age`. All passed after the fixes below:

| Area | What was exercised |
| :--- | :--- |
| Migrations `0001`–`0005` | Applied in order as `postgres`. `0005` installs the policies on the real `supabase_storage_admin`-owned `storage.objects`; the unprivileged-role skip path and `apply-storage-policies.sh` also work. |
| Shared limiter | `rate_limit_check`: sequential refill, key isolation, grants; 200 concurrent calls on a burst of 50 allowed exactly 50. Through two real replicas (Rust and Go) the global limit held. |
| REST (Rust) | 27 HTTP checks: CRUD, filters/order/paging/count, upsert, bad casts → 400, SQL-looking values stored literally, RLS isolation between users, internal schemas refused. |
| Realtime cluster (Rust + Go) | Real WebSockets on two replicas: cross-replica broadcast and presence, late-joiner sync, leave diffs, oversize rejection, DB change feed on both replicas, and recovery after every `LISTEN` backend was terminated. |
| Storage (Rust + Go) | 25 checks each through the proxy to the real Storage API: owner/viewer/outsider RLS, signed URLs (and fetching them), API key confined to `<workspace_id>/`, traversal, user-only TUS. |
| Go vector / billing | pgvector search (`::extensions.vector`), metadata filter, upsert, key scope + workspace binding, Stripe and LemonSqueezy plan sync, idempotent replay, bad/stale signatures. |
| PITR | WAL archiving from `supabase-pitr.override.yml`, base backup → age → rclone, WAL shipping, then `DROP TABLE` and a restore to a point just before it (150 rows back, 0 rows from after the target). `archive_command` verified for new / identical / different files. |

Bugs found and fixed by this run: (1) REST batch insert forced omitted columns to `NULL` instead of their `DEFAULT` (now one `INSERT` per distinct key set); (2) `pg_basebackup` was refused because the Supabase image's `pg_hba.conf` has no `replication` rule (`pitr.sh` now adds `local replication <admin> trust` idempotently before each base backup); plus a noisy first-run prune error.

Still not covered: GoTrue/auth flows, the Rust job worker path for billing, image transforms, TUS uploads, and a real S3/R2 remote for `rclone` (a local-directory remote was used). The shared limiter fails open to the per-replica bucket when its query exceeds 250 ms; with a tiny pool (`DB_MAX_CONNECTIONS=5`) a burst of ~150 concurrent requests per replica caused that fallback and let ~5% more than the global limit through — size the pool for your concurrency or accept that degradation.

---

## Known Gaps / Next Steps

| Area | Gap |
| :--- | :--- |
| Cluster limits | Clustered realtime messages are capped at ~7 KB (NOTIFY payload limit) and presence converges within ≤30 s after a replica crash. For larger payloads or very high fan-out, move to Redis pub/sub. The shared limiter adds one DB round-trip per request and serialises on one row per key. |
| REST scope | No resource embedding (joins), `or=`/`and=` groups, RPC or API-key access. Use views for joins. |
| Storage resumable (TUS) | Still user-JWT only: the response embeds the caller's token, which an API key does not have. |
| Storage policy owner | If `postgres` does not own `storage.objects`, run `scripts/apply-storage-policies.sh` once as `supabase_admin`. A workspace of app `x` could in theory address bucket `x-1-…` by prefix; object paths are workspace-UUID-scoped so no data crosses, but prefer app slugs that are not prefixes of each other. |
| PITR | RPO ≈ `archive_timeout` (60 s) + 1 min shipping; the restore is a rehearsal into a scratch container — promoting it to production is a deliberate manual step. Uses plain `cp`/`pg_basebackup`, not WAL-G/pgBackRest (no dependency on tools bundled in the Supabase image); switch to pgBackRest for incremental backups on multi-hundred-GB databases. |
| Go template parity | Go still lacks the GoTrue proxy, workspace members/invitations, API-key management endpoints, the generic REST API and the durable job queue (so no `embeddings/reindex`). |
| Multi-project Studio | Self-hosted Studio manages one cluster; isolation is logical (`app_slug` / per-SaaS schemas). |
