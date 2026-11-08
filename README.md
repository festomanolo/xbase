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
│   └── 0003_vector_embeddings.sql     # pgvector embeddings + HNSW index
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
│       ├── storage.rs     # buckets, signed URLs, streaming upload/download, TUS, image transforms
│       ├── realtime.rs    # /ws rooms, broadcast, presence, Postgres change streams
│       ├── vector.rs      # pgvector upsert/search, server-side embeddings, reindex job
│       ├── billing.rs     # Stripe + LemonSqueezy webhooks → workspace plan sync
│       ├── jobs.rs        # durable SKIP LOCKED job queue with retries/backoff
│       ├── rate_limit.rs  # sharded token bucket per API key / user / IP
│       ├── metrics.rs     # Prometheus /metrics
│       └── routes.rs      # router assembly + HTTP tests
├── go-backend/                        # Go service template (pgx, golang-jwt)
├── docker/
│   ├── docker-compose.saas.yml        # Rust + Go SaaS backends + Caddy
│   ├── docker-compose.monitoring.yml  # Prometheus, Alertmanager, Grafana, node-exporter, cAdvisor
│   ├── supabase-auth.override.yml     # OAuth providers, SAML, SMTP tuning for GoTrue
│   ├── monitoring/                    # scrape config, alert rules, receivers
│   └── Caddyfile
└── scripts/
    ├── bootstrap-supabase.sh          # clone Supabase docker + generate ALL secrets consistently
    ├── backup-postgres.sh             # encrypted pg_dump → S3 / R2 / B2 (age or openssl + rclone)
    ├── restore-postgres.sh            # verified restore into a fresh database
    ├── install-backups.sh             # nightly systemd timer
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
| | `POST /api/v1/storage/objects/:bucket/list` · `sign-upload` · `sign-download` (with `transform`) | JWT |
| | `GET/PUT/POST /api/v1/storage/objects/:bucket/*path` (streaming), `DELETE /api/v1/storage/objects/:bucket` | JWT |
| | `POST /api/v1/storage/uploads/resumable` (TUS / multipart details) | JWT |
| **Realtime** | `GET /ws?access_token=<jwt>` | JWT |
| **Vector** | `POST /api/v1/workspaces/:id/embeddings` · `…/embeddings/search` · `…/embeddings/reindex`, `DELETE …/embeddings/:id` | JWT or API key |
| **Billing** | `POST /webhooks/stripe`, `POST /webhooks/lemonsqueezy` | provider signature |

Workspace roles are `owner > admin > member > viewer`. Owners delete the workspace. Owners and admins rename it, manage members, invite people and create API keys. Members write embeddings. Every member can read.

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
cd ../go-backend && go test ./...
```

---

## Part 2: High-Performance Rust/Go Integration for 10+ SaaS Apps

Using Rust or Go alongside your self-hosted Supabase is an excellent strategy for maximizing performance and minimizing server costs, especially if you plan to run 10 different SaaS applications on a single VPS.

In fact, Supabase itself is built for extreme performance using these exact languages: its authentication server (GoTrue) is written in Go, and its Edge Functions runtime (Deno) is built on Rust.

### 1. The Direct Database Approach (Maximum Speed)

Because Supabase is ultimately just a standard PostgreSQL database under the hood, your custom backend does not have to communicate through Supabase's REST API. You can connect your Rust or Go server directly to the Postgres instance for raw, unthrottled performance.

* **In Rust:** Use **`sqlx`** for highly performant, fully asynchronous, compile-time or runtime checked SQL queries (implemented in [`backend/`](backend)), or **`diesel`** if you prefer a traditional ORM.
* **In Go:** Use **`pgx`**, which is widely considered the fastest PostgreSQL driver for Go. It supports advanced Postgres features and connection pooling natively.

**How it works:** Your Rust/Go backend handles the heavy business logic, background jobs, and payment processing (like Stripe webhooks) by talking directly to Postgres on the server. You then leave the Supabase client SDKs on the frontend to handle authentication, file storage, and real-time sockets.

### 2. Using Supabase SDKs for Go and Rust

If your custom backend needs to interact with Supabase's specific features (like creating users in Auth or uploading files to Storage), you can use the community-maintained SDKs:

* **Go:** The `supabase-community/supabase-go` library allows you to interact with Auth, Storage, and the PostgREST API.
* **Rust:** The `supabase-rs` crate provides similar functionality for interacting with the Supabase ecosystem from your Rust server.

### 3. Rust via WebAssembly in Edge Functions

If you want to write Rust but don't want to manage a separate backend server process at all, Supabase Edge Functions run on Deno (a modern JavaScript/TypeScript runtime). Deno natively supports WebAssembly (Wasm). You can write your high-performance algorithms in Rust, compile them to Wasm, and execute them directly inside Supabase's serverless Edge Functions.

---

## Why This Is Ideal for Hosting 10 SaaS Apps on One VPS

* **Minimal RAM Footprint:** Node.js or Python backends can consume 100MB+ of RAM just idling. A compiled Go or Rust binary can idle at under 15MB. When running 10 distinct SaaS backends on a single VPS, this difference prevents your server from crashing due to out-of-memory errors.
* **Concurrency:** Go's goroutines and Rust's asynchronous runtime (`tokio`) can handle tens of thousands of concurrent requests with minimal CPU overhead, ensuring that a traffic spike on SaaS #1 doesn't slow down SaaS #2.

> **Crucial Setup Requirement (Supavisor Port `6543`):**
> Because you are running 10 SaaS apps, you must utilize **Supavisor** (Supabase's built-in connection pooler). Postgres limits the number of direct, simultaneous connections it can handle. Point your Rust/Go backends to the Supavisor transaction pooler port (`6543`) rather than the direct Postgres port (`5432`) so the pooler can efficiently share connections across all 10 of your applications.
>
> In [`backend/src/db.rs`](backend/src/db.rs), `statement_cache_capacity(0)` is explicitly configured on `PgConnectOptions` so `sqlx` works seamlessly with Supavisor's transaction pooling mode on port `6543`.

---

## Running the Included Rust (Axum + SQLx) Backend

### Local Development

```bash
cd backend
cp .env.example .env
# Edit .env with your DATABASE_URL (port 6543) and SUPABASE_JWT_SECRET

cargo run
```

### Run Unit Tests

```bash
cd backend
cargo test
```

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | Public | Liveness & process metrics check |
| `GET` | `/health/db` | Public | Verifies Supavisor (`6543`) PostgreSQL connectivity |
| `GET` | `/api/v1/me` | Bearer JWT | Verifies Supabase JWT & returns authenticated user claims |
| `GET` | `/api/v1/tenants/:app_slug` | Bearer JWT | Queries multi-SaaS tenant workspace data directly from Postgres |
