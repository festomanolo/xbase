# xbase

High-performance, self-hosted **Supabase + Rust (Axum & SQLx)** multi-SaaS platform architecture designed to run **10+ SaaS applications on a single VPS** with minimal RAM footprint (<15MB per backend service) and Supavisor connection pooling.

---

## Repository Structure

```text
xbase/
├── README.md                          # Complete VPS setup & architecture guide
├── .env.example                       # Environment template for Supabase + Rust backend
├── scripts/
│   └── bootstrap-supabase.sh          # Automated official Supabase Docker setup + secret generator
├── docker/
│   ├── docker-compose.saas.yml        # Multi-SaaS Rust backend + Caddy reverse proxy stack
│   └── Caddyfile                      # Automatic HTTPS reverse proxy for Supabase & SaaS apps
├── migrations/
│   └── 0001_init_multi_saas.sql       # Multi-SaaS schema & Row-Level Security (RLS) starter
└── backend/                           # Rust (Axum + SQLx) backend optimized for Supavisor (port 6543)
    ├── Cargo.toml
    ├── Dockerfile
    ├── .env.example
    └── src/
        ├── main.rs                    # Entrypoint & graceful shutdown
        ├── config.rs                  # Environment & pool configuration
        ├── db.rs                      # Supavisor-compatible PgPool (statement cache disabled)
        ├── auth.rs                    # Local Supabase JWT verification middleware
        └── routes.rs                  # Health, DB diagnostics, and multi-SaaS tenant endpoints
```

---

## Part 1: Self-Host Supabase on Your VPS (Official Docker Compose)

### Prerequisites

* A Linux VPS (Ubuntu 22.04/24.04 or Debian recommended) with at least **4GB of RAM** and **2 vCPUs**.
* Root or `sudo` access to your server.

### 1. Install Docker and Git

Update your package manager and install the necessary dependencies, including Docker, which runs the Supabase services.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl openssl

# Install Docker Engine
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

### 2. Clone the Supabase Repository (or Run the Bootstrap Script)

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
