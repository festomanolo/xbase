use std::collections::HashMap;
use std::env;

use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct AppConfig {
    /// Slug of the SaaS app this binary serves. Every workspace, API key, job and
    /// webhook event is scoped by it, so 10+ backends can share one database.
    pub app_id: String,
    pub host: String,
    pub port: u16,

    /// Supavisor transaction pooler (port 6543). Used for all request traffic.
    pub database_url: String,
    /// Direct Postgres session connection (port 5432). Used for migrations and
    /// LISTEN/NOTIFY, which do not work through a transaction-mode pooler.
    pub direct_database_url: Option<String>,
    pub run_migrations: bool,
    pub db_max_connections: u32,

    pub supabase_jwt_secret: String,
    /// Internal Supabase gateway URL (Kong), e.g. http://kong:8000.
    pub supabase_url: String,
    /// Public Supabase URL handed to browsers (signed URLs, OAuth redirects).
    pub supabase_public_url: String,
    pub supabase_anon_key: Option<String>,
    pub supabase_service_role_key: Option<String>,
    /// GoTrue base URL. Defaults to `{supabase_url}/auth/v1`.
    pub gotrue_url: String,
    /// Storage API base URL. Defaults to `{supabase_url}/storage/v1`.
    pub storage_url: String,
    /// Users allowed to call the admin endpoints in addition to service_role tokens.
    pub admin_user_ids: Vec<Uuid>,

    pub cors_allowed_origins: Vec<String>,
    pub trust_proxy_headers: bool,
    pub rate_limit_per_second: f64,
    pub rate_limit_burst: f64,
    pub metrics_token: Option<String>,

    pub stripe_webhook_secret: Option<String>,
    pub stripe_price_plans: HashMap<String, String>,
    pub lemonsqueezy_webhook_secret: Option<String>,
    pub lemonsqueezy_variant_plans: HashMap<String, String>,

    pub jobs_enabled: bool,
    pub jobs_concurrency: usize,

    pub realtime_enabled: bool,

    /// OpenAI-compatible embeddings endpoint (OpenAI, Ollama, vLLM, LocalAI...).
    pub embedding_api_url: Option<String>,
    pub embedding_api_key: Option<String>,
    pub embedding_model: String,
    pub embedding_dims: usize,
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn parse<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    match var(name) {
        Some(v) => v.parse::<T>().map_err(|e| format!("Invalid {name}: {e}")),
        None => Ok(default),
    }
}

fn parse_bool(name: &str, default: bool) -> Result<bool, String> {
    match var(name).as_deref().map(str::to_ascii_lowercase).as_deref() {
        None => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(other) => Err(format!("Invalid {name}: expected true/false, got '{other}'")),
    }
}

/// Parses `key:value,key2:value2` maps such as `STRIPE_PRICE_PLANS=price_123:pro,price_456:team`.
pub fn parse_pairs(raw: &str) -> HashMap<String, String> {
    raw.split(',')
        .filter_map(|pair| {
            let (k, v) = pair.split_once(':')?;
            let (k, v) = (k.trim(), v.trim());
            (!k.is_empty() && !v.is_empty()).then(|| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

impl AppConfig {
    pub fn from_env() -> Result<Self, String> {
        let app_id = env::var("APP_ID").unwrap_or_else(|_| "xbase-saas".to_string());
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()
            .map_err(|e| format!("Invalid PORT: {e}"))?;

        let database_url = env::var("DATABASE_URL")
            .map_err(|_| "Missing required environment variable: DATABASE_URL".to_string())?;

        let db_max_connections = env::var("DB_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u32>()
            .map_err(|e| format!("Invalid DB_MAX_CONNECTIONS: {e}"))?;

        let supabase_jwt_secret = env::var("SUPABASE_JWT_SECRET").map_err(|_| {
            "Missing required environment variable: SUPABASE_JWT_SECRET".to_string()
        })?;

        let supabase_url =
            env::var("SUPABASE_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

        Ok(Self {
            app_id,
            host,
            port,
            database_url,
            db_max_connections,
            supabase_jwt_secret,
            supabase_url,
        })
    }
}
