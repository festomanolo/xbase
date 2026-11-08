# xbase

A self-hosted, **Supabase-compatible backend platform** for running **10+ SaaS applications on a single Linux VPS**. It pairs the official self-hosted Supabase stack (Postgres, GoTrue, Storage, Supavisor) with:

* **`backend/`**: a **Rust (Axum + SQLx)** platform API. It covers auth, RLS-enforced CRUD, storage, realtime WebSockets with Postgres CDC, pgvector search, billing webhooks, background jobs, API keys, rate limiting and Prometheus metrics. It idles at roughly 10–15 MB of RAM.
* **`go-backend/`**: a lean **Go (net/http + pgx)** service template. It uses the same conventions (Supavisor pooling, local JWT verification, RLS impersonation, API keys, rate limiting) for SaaS backends you'd rather write in Go.
* Ops tooling for the parts Supabase Cloud provides and self-hosting doesn't: encrypted off-site backups, database branching, monitoring/alerting, SMTP and OAuth configuration.

```text
                       ┌──────────── Caddy (Let's Encrypt TLS) ────────────┐
                       │                                                   │
          api.domain ──┤──► Kong ──► GoTrue · Storage · PostgREST · Studio │
     app1-api.domain ──┤──► saas-api-1 (Rust)  ─┐                          │
     app2-api.domain ──┤──► saas-api-2 (Go)    ─┼─► Supavisor :6543 ──► Postgres (+pgvector)
                ...  ──┤──► saas-api-N         ─┘        ▲                 │
                       └──────────────────────── LISTEN/NOTIFY :5432 ──────┘
```

---

## Repository Structure

```text
xbase/
├── migrations/                        # Embedded into the Rust binary, applied on boot
│   ├── 0001_init_multi_saas.sql       # xbase.apps, xbase.workspaces
│   ├── 0002_platform_core.sql         # members, invitations, API keys, jobs, webhooks, CDC triggers, RLS
│   ├── 0003_vector_embeddings.sql     # pgvector embeddings + HNSW index
│   ├── 0004_shared_rate_limit.sql     # shared token bucket for multi-replica rate limiting
│   └── 0005_storage_policies.sql      # workspace-scoped storage.objects policies
├── backend/                           # Rust platform API (Axum 0.7, SQLx 0.8, Tokio)
│   └── src/
│       ├── main.rs        # boot: migrations, pool, workers, CDC listener, graceful shutdown
│       ├── config.rs      # every environment variable
│       ├── db.rs          # Supavisor pool (statement_cache_capacity(0)), migrator
│       ├── rls.rs         # begin_rls / with_rls_claims — native Postgres RLS impersonation
│       ├── auth.rs        # local HS256 JWT verification, Principal (JWT | API key), admin gate
│       ├── gotrue.rs      # sign-up/in, OTP, magic link, OAuth+PKCE, refresh, recovery, admin users
│       ├── workspaces.rs  # workspace / member / invitation CRUD
│       ├── api_keys.rs    # hashed x-api-key management + authentication
│       ├── storage.rs     # buckets, signed URLs, streaming upload/download, TUS, transforms; JWT or API key
│       ├── realtime.rs    # /ws rooms, broadcast, presence, change streams, multi-replica fan-out
│       ├── rest.rs        # PostgREST-style CRUD under RLS (opt-in)
│       ├── vector.rs      # pgvector upsert/search, server-side embeddings, reindex job
│       ├── billing.rs     # Stripe + LemonSqueezy webhooks → workspace plan sync
│       ├── jobs.rs        # durable SKIP LOCKED job queue with retries/backoff
│       ├── rate_limit.rs  # token bucket per API key / user / IP (memory or shared via Postgres)
│       ├── metrics.rs     # Prometheus /metrics
│       └── routes.rs      # router assembly + HTTP tests
├── go-backend/                        # Go service: storage, vector, billing, realtime, shared limiter (pgx)
├── docker/
│   ├── docker-compose.saas.yml        # Rust + Go SaaS backends + Caddy
│   ├── docker-compose.monitoring.yml  # Prometheus, Alertmanager, Grafana, node-exporter, cAdvisor
│   ├── supabase-auth.override.yml     # OAuth providers, SAML, SMTP tuning for GoTrue
│   ├── supabase-pitr.override.yml     # WAL archiving for point-in-time recovery
│   ├── storage-policies.sql           # storage.objects policies (superuser variant of migration 0005)
│   ├── monitoring/                    # scrape config, alert rules, receivers
│   └── Caddyfile
└── scripts/
    ├── bootstrap-supabase.sh          # clone Supabase docker + generate ALL secrets consistently
    ├── backup-postgres.sh             # encrypted pg_dump → S3 / R2 / B2 (age or openssl + rclone)
    ├── restore-postgres.sh            # verified restore into a fresh database
    ├── install-backups.sh             # nightly systemd timer
    ├── pitr.sh / install-pitr.sh      # WAL shipping, base backups, point-in-time restore
    ├── apply-storage-policies.sh      # install storage.objects policies as the DB superuser
    └── db-branch.sh                   # ephemeral per-PR database branches
```

---

## Part 1: Deploy on a VPS

**Prerequisites:** Ubuntu 22.04/24.04 or Debian, **4 GB RAM / 2 vCPU** minimum, a domain pointing at the server.

```bash
# 1. Docker + tools
sudo apt update && sudo apt install -y git curl openssl age rclone
curl -fsSL https://get.docker.com | sudo sh

# 2. Supabase with freshly generated, mutually consistent secrets
#    (JWT_SECRET, ANON_KEY and SERVICE_ROLE_KEY are signed together)
DOMAIN=api.yourdomain.com SITE_URL=https://app1.yourdomain.com \
SMTP_HOST=smtp.resend.com SMTP_PORT=587 SMTP_USER=resend SMTP_PASS=re_xxx \
SMTP_ADMIN_EMAIL=no-reply@yourdomain.com \
  ./scripts/bootstrap-supabase.sh

cd supabase-project && sudo docker compose pull && sudo docker compose up -d && cd ..

# 3. SaaS backends + Caddy (edit docker/Caddyfile domains first)
cd docker
sudo docker compose --env-file ../supabase-project/.env -f docker-compose.saas.yml up -d --build

# 4. Backups (edit /etc/xbase/backup.env afterwards) and monitoring
cd .. && sudo ./scripts/install-backups.sh
cd docker && GRAFANA_ADMIN_PASSWORD=... sudo docker compose -f docker-compose.monitoring.yml up -d
```

The Rust backend applies `migrations/` automatically on boot over the direct `5432` connection. sqlx's advisory lock makes it safe for several backends to boot at once.

### Adding SaaS #3 … #10

Each SaaS is one container with its own `APP_ID`:

1. Copy the `saas-api-1` block in `docker/docker-compose.saas.yml` and change `container_name`, `APP_ID`, `CORS_ALLOWED_ORIGINS` and the Stripe secrets.
2. Add a site block to `docker/Caddyfile`.
3. Add the target to `docker/monitoring/prometheus.yml`.

Data isolation between apps comes from `app_slug` predicates and RLS. Storage isolation comes from per-app bucket prefixes (`<APP_ID>-<bucket>`). Jobs, webhook events and API keys are all scoped by `APP_ID`.

### OAuth, SAML and SMTP

Self-hosted Studio has no provider UI. Set the credentials in `supabase-project/.env` and layer the override file:

```bash
cd supabase-project
docker compose -f docker-compose.yml -f ../docker/supabase-auth.override.yml up -d auth
```

The callback URL for every provider is `https://api.yourdomain.com/auth/v1/callback`. Without `SMTP_*`, GoTrue cannot send confirmation, magic-link or password-reset emails.

---

## Part 2: The Rust Platform API

### Architectural invariants

1. **Supavisor transaction mode (`6543`)** for every request, with SQLx's prepared-statement cache disabled (`statement_cache_capacity(0)`). Migrations and `LISTEN` use the direct `5432` connection (`DIRECT_DATABASE_URL`).
2. **Zero-network auth:** Supabase JWTs are verified locally with `SUPABASE_JWT_SECRET`, in about a microsecond with no round-trip to GoTrue.
3. **Postgres is the authorization layer.** `rls::begin_rls` opens a transaction and sets `role = authenticated` and `request.jwt.claims` as transaction-local settings, exactly as PostgREST does. `auth.uid()` and every RLS policy then apply natively. Billing columns are protected by column-level grants, so users cannot change their own `plan`.

### Endpoints

| Area | Method & Path | Auth |
|---|---|---|
| Health | `GET /health`, `GET /health/db`, `GET /metrics` | public / `METRICS_TOKEN` |
| Me | `GET /api/v1/me` | JWT |
| **Auth** | `POST /api/v1/auth/signup` · `token` (password) · `refresh` · `otp` · `magiclink` · `verify` · `recover` · `exchange` (PKCE) · `logout` | public / JWT |
| | `GET /api/v1/auth/authorize?provider=github&redirect_to=…` (OAuth redirect) | public |
| | `GET/PUT /api/v1/auth/user` | JWT |
| | `GET/POST /api/v1/admin/users`, `GET/PUT/DELETE /api/v1/admin/users/:id` | service_role or `ADMIN_USER_IDS` |
| **Workspaces** | `GET/POST /api/v1/workspaces`, `GET/PATCH/DELETE /api/v1/workspaces/:id` | JWT (GET also API key) |
| | `GET /api/v1/workspaces/:id/members`, `PATCH/DELETE …/members/:user_id` | JWT |
| | `GET/POST /api/v1/workspaces/:id/invitations`, `DELETE …/invitations/:id`, `POST /api/v1/invitations/accept` | JWT |
| | `GET /api/v1/tenants/:app_slug` (legacy) | JWT |
| **API keys** | `GET/POST /api/v1/workspaces/:id/api-keys`, `DELETE …/api-keys/:key_id` | JWT (owner/admin) |
| | `GET /api/v1/server/whoami` | `x-api-key` |
| **Storage** | `GET/POST /api/v1/storage/buckets`, `DELETE …/buckets/:bucket?force=true` | admin |
| | `POST /api/v1/storage/objects/:bucket/list` · `sign-upload` · `sign-download` (with `transform`) | JWT or API key |
| | `GET/PUT/POST /api/v1/storage/objects/:bucket/*path` (streaming), `DELETE /api/v1/storage/objects/:bucket` | JWT or API key |
| | `POST /api/v1/storage/uploads/resumable` (TUS / multipart details) | JWT |
| **REST** (opt-in) | `GET/POST/PATCH/DELETE /api/v1/rest/:table` | JWT |
| **Realtime** | `GET /ws?access_token=<jwt>` | JWT |
| **Vector** | `POST /api/v1/workspaces/:id/embeddings` · `…/embeddings/search` · `…/embeddings/reindex`, `DELETE …/embeddings/:id` | JWT or API key |
| **Billing** | `POST /webhooks/stripe`, `POST /webhooks/lemonsqueezy` | provider signature |

Workspace roles are `owner > admin > member > viewer`. Owners delete the workspace. Owners and admins rename it, manage members, invite people and create API keys. Members write embeddings. Every member can read.

### Storage with API keys and policies

Name objects `<workspace_id>/<path>` inside bucket `<APP_ID>-<name>`. Migration `0005` installs `storage.objects` policies on that convention: workspace members read, owners/admins/members write. If it prints `skipped storage.objects policies` (the migration user does not own the table), run `./scripts/apply-storage-policies.sh` once.

Server-to-server callers use an API key with scope `storage:read` and/or `storage:write` (or `*`). The key runs with the service role, so the backend pins it to its own workspace: any path outside `<its workspace_id>/` is refused, and listings are forced to that folder. Resumable (TUS) uploads stay user-only.

```bash
curl -X PUT "$API/api/v1/storage/objects/docs/$WORKSPACE_ID/reports/q3.pdf" \
     -H "x-api-key: $XB_KEY" -H "content-type: application/pdf" --data-binary @q3.pdf
```

### Generic REST API

Set `REST_ENABLED=true` (and `REST_SCHEMAS`, default `public`) to get PostgREST-style CRUD from the Rust backend. Every request runs under the caller's RLS role, so grants and policies are the authorization layer; `xbase`, `auth`, `storage` and other internal schemas are never reachable.

```bash
GET    /api/v1/rest/todos?select=id,title&done=eq.false&title=ilike.*milk*&order=created_at.desc&limit=20
GET    /api/v1/rest/todos?id=in.(1,2,3)&deleted_at=is.null        # Prefer: count=exact → Content-Range
POST   /api/v1/rest/todos        {"title":"x"}  |  [{"title":"a"},{"title":"b"}]
POST   /api/v1/rest/todos?on_conflict=id   (Prefer: resolution=merge-duplicates)   # upsert
PATCH  /api/v1/rest/todos?id=eq.7   {"done":true}            # a filter is mandatory
DELETE /api/v1/rest/todos?id=eq.7                            # a filter is mandatory
```

Operators: `eq neq gt gte lt lte like ilike is in`, each negatable with `not.`. Use `Accept-Profile` / `Content-Profile` to pick another allowed schema. Joins, `or=`/`and=` and RPC are not supported (use a view). Table and column names are validated against the catalog and values are always bound parameters.

### Running more than one replica

Both in-memory pieces have a shared mode. Turn them on for **every** replica of the app:

| Setting | What it does |
|---|---|
| `RATE_LIMIT_BACKEND=postgres` | One token bucket per key for all replicas (`xbase.rate_limit_check`, migration `0004`). If the database is slow (>250 ms) or down, that request uses the local bucket, so a DB blip never becomes an API outage (`xbase_rate_limit_fallbacks_total`). |
| `REALTIME_CLUSTER=true` | Broadcast and presence are replayed to the other replicas over `NOTIFY xbase_rt_<app>`. Presence uses diffs plus a 30 s sync, and entries of a silent replica expire after 90 s. Messages are limited to about 7 KB in this mode. Needs `DIRECT_DATABASE_URL`. |

Database change events (`subscribe_changes`) and background jobs already work across replicas. Add the replica to `docker-compose.saas.yml` (commented example) and to the Caddy `reverse_proxy` list. No sticky sessions are needed.

### Realtime protocol

```js
const ws = new WebSocket(`wss://app1-api.yourdomain.com/ws?access_token=${session.access_token}`);
ws.send(JSON.stringify({ type: "join", room: `workspace:${workspaceId}` }));   // private, members only
ws.send(JSON.stringify({ type: "track", room: `workspace:${workspaceId}`, state: { status: "online" } }));
ws.send(JSON.stringify({ type: "broadcast", room: `workspace:${workspaceId}`, event: "cursor", payload: { x, y } }));
ws.send(JSON.stringify({ type: "subscribe_changes", workspace_id: workspaceId })); // Postgres CDC
// ← joined · presence_state · presence_diff · broadcast · change · error
```

To add CDC to your own tables, attach the trigger. Any table with a `workspace_id` column works:

```sql
create trigger trg_projects_notify after insert or update or delete on saas1.projects
  for each row execute function xbase.notify_change();
```

### Billing

Pass the workspace id at checkout: Stripe `client_reference_id` / `subscription_data.metadata.workspace_id`, or LemonSqueezy `checkout_data.custom.workspace_id`. Map prices to plans with `STRIPE_PRICE_PLANS=price_123:pro`. The webhook verifies the signature, stores the event idempotently and returns immediately. A background job then updates `plan`, `subscription_status` and `current_period_end`. Cancelled or expired subscriptions fall back to `free`.

### Background jobs

```rust
jobs::enqueue(&state.pool, &state.config.app_id, "emails.welcome", &json!({ "user_id": id })).await?;
```

Add the handler in `jobs::dispatch`. Jobs retry with exponential backoff (up to 8 attempts). Stuck jobs are re-queued after 10 minutes, and completed jobs are pruned after 7 days.

### Vector search

Set `EMBEDDING_API_URL`. Any OpenAI-compatible endpoint works, including Ollama at `http://ollama:11434/v1`. Then send `{"items":[{"external_id":"doc1","content":"…"}]}` to `…/embeddings` and `{"query":"…","filter":{"lang":"en"}}` to `…/embeddings/search`. The vector dimension is `1536`; change `vector(1536)` in `0003` and `EMBEDDING_DIMS` together before first deploy.

### Develop & test

```bash
cd backend && cp .env.example .env && cargo run
cargo test                      # unit + HTTP tests (no database needed)
cd ../go-backend && go test -race ./...
```

---

## Part 3: The Go Template

`go-backend/` provides `/health`, `/health/db`, `/metrics`, `/api/v1/me`, workspace list/create/get (RLS-enforced through `db.WithRLS`), and `/api/v1/server/whoami` (API keys). It also implements, with the same routes, scopes and wire formats as the Rust backend:

- **Storage:** buckets (admin), signed URLs with transforms, streaming upload/download, batch delete, TUS details; user JWT or API key confined to `<workspace_id>/`.
- **Vector:** `…/embeddings`, `…/embeddings/search`, `DELETE …/embeddings/:id` (no `reindex`, since the Go template has no job queue).
- **Billing:** Stripe and LemonSqueezy webhooks. The plan sync runs inside the webhook's own transaction, so the event is recorded and applied together or not at all.
- **Realtime:** `/ws` rooms, broadcast, presence, change feed, and `REALTIME_CLUSTER` using the same envelope as Rust.
- **Rate limiting:** memory or shared (`RATE_LIMIT_BACKEND=postgres`) with the same fail-over.

Not ported: the GoTrue proxy, workspace members/invitations, API-key management, the generic REST API and the job queue. It shares the same `.env` names as the Rust backend. pgx runs in `QueryExecModeExec`, so no prepared statement outlives a transaction behind Supavisor. Run the Rust backend once first, because it owns the shared migrations.

```go
err := db.WithRLS(ctx, pool, claims, func(tx pgx.Tx) error {
    _, err := tx.Exec(ctx, "insert into saas2.todos (workspace_id, title) values ($1, $2)", wsID, title)
    return err
})
```

---

## Part 4: Operations

| Concern | Tool |
|---|---|
| Backups | `scripts/backup-postgres.sh`: per-database `pg_dump -Fc` + globals, encrypted with `age` (or AES-256 via OpenSSL), uploaded with `rclone`, with retention pruning, checksums and an optional healthchecks.io ping. Nightly via `install-backups.sh`. |
| Restore | `scripts/restore-postgres.sh backup.tar.age [db] [target]` restores into a new database by default so you can verify before swapping. |
| Branching | `scripts/db-branch.sh create pr-42 [--with-data]` / `delete pr-42`. Point a preview backend at `branch_pr_42`. |
| Monitoring | `docker-compose.monitoring.yml` alerts on disk > 85%, RAM > 90%, CPU, down targets, container restart loops, 5xx > 5% and failing jobs. |
| PITR | Continuous WAL archiving plus nightly base backups: restore to any second in the retention window (RPO about 1–2 minutes). Setup below. |

### Point-in-time recovery

```bash
sudo ./scripts/install-pitr.sh                  # installs xbase-pitr + systemd timers, creates the WAL spool
sudoedit /etc/xbase/pitr.env                    # RCLONE_REMOTE + AGE_RECIPIENT at minimum
cd supabase-project && docker compose -f docker-compose.yml -f ../docker/supabase-pitr.override.yml up -d db   # one restart
sudo systemctl enable --now xbase-pitr-ship.timer xbase-pitr-base.timer
sudo xbase-pitr base-backup && sudo xbase-pitr status
```

Postgres copies each finished WAL segment (and one every 60 s at most) to a host directory. A timer encrypts each file, uploads it with `rclone`, verifies the upload and only then deletes the local copy. A nightly `pg_basebackup` is streamed straight to the bucket, so the VPS needs no scratch disk. `xbase-pitr status --check` exits non-zero if archiving is off, WAL is piling up locally or the newest base is older than 36 h (wire it to `HEALTHCHECK_URL`).

**Rehearse a restore now, not during an incident:**

```bash
sudo xbase-pitr restore "2026-11-08 14:30:00+00"    # or: latest
```

It rebuilds a data directory from the right base plus WAL up to that time and boots it as a throwaway container on `127.0.0.1:54329` (archiving off, so it never writes to your real archive). It prints the commands to make it production, which stays a deliberate manual step. Keep the age private key offline. Without it neither backups nor WAL can be decrypted.

If local WAL grows past `MAX_LOCAL_WAL_MB` (uploads failing), fix the remote before the disk fills: a full disk makes `archive_command` fail and Postgres eventually stops.
