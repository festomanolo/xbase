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

You can use our automated helper script to clone the official Supabase Docker configuration and generate secure secrets automatically:

```bash
chmod +x scripts/bootstrap-supabase.sh
./scripts/bootstrap-supabase.sh
```

Or perform the steps manually:

```bash
# Clone the repository (shallow clone to save space)
git clone --depth 1 https://github.com/supabase/supabase

# Create your project directory
mkdir supabase-project

# Copy the docker files (including hidden files) to your project
cp -rf supabase/docker/. supabase-project

cd supabase-project

# Create the environment file
cp .env.example .env
```

### 3. Configure Environment Variables (Crucial for Security)

You must update the default passwords and secrets before starting the server. Open the `.env` file using a terminal text editor like `nano`:

```bash
nano .env
```

Update the following core variables:

* `POSTGRES_PASSWORD`: Create a strong database password (alphanumeric recommended to avoid URL encoding issues).
* `JWT_SECRET`: Generate a secure, 32+ character random string (`openssl rand -base64 32`).
* `DASHBOARD_USERNAME` & `DASHBOARD_PASSWORD`: Set your login credentials for the Supabase Studio web interface.
* `SITE_URL` & `API_EXTERNAL_URL`: Set these to your VPS's public IP address (e.g., `http://YOUR_VPS_IP:8000`) or your domain name (e.g., `https://api.yourdomain.com`).

### 4. Start the Supabase Stack

Pull the latest Docker images and start all the backend services in the background.

```bash
sudo docker compose pull
sudo docker compose up -d
```

This process will take a few minutes as it downloads and initializes the containers for PostgreSQL, Auth (GoTrue), Realtime, Storage, Supavisor, and the Studio dashboard.

### 5. Access Supabase Studio

Once the containers are running, you can access your self-hosted dashboard.

Open your web browser and navigate to:
`http://YOUR_VPS_IP:8000`

Log in using the `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD` you configured in Step 3.

---

### Production Readiness

By default, this exposes Supabase over plain HTTP. Before deploying a live application, you should:

1. Point a custom domain name (or a subdomain like `api.yourdomain.com`) to your VPS's IP address.
2. Set up a reverse proxy (like **Nginx** or **Caddy** — see [`docker/Caddyfile`](docker/Caddyfile)) to handle traffic.
3. Secure the connection with a free SSL certificate from Let's Encrypt.

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
