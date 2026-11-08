use std::collections::HashMap;
use std::env;

use uuid::Uuid;

/// Where token-bucket state lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitBackend {
    /// Per-process buckets: zero latency, but each replica enforces its own limit.
    Memory,
    /// One shared bucket per key in Postgres (`xbase.rate_limit_check`): the limit
    /// holds across any number of replicas, at the cost of one DB round-trip.
    Postgres,
}

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
    pub rate_limit_backend: RateLimitBackend,
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
        let app_id = var("APP_ID").unwrap_or_else(|| "xbase-saas".to_string());
        if !app_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err("APP_ID must contain only lowercase letters, digits and '-'".into());
        }

        let database_url =
            var("DATABASE_URL").ok_or("Missing required environment variable: DATABASE_URL")?;
        let supabase_jwt_secret = var("SUPABASE_JWT_SECRET")
            .ok_or("Missing required environment variable: SUPABASE_JWT_SECRET")?;
        if supabase_jwt_secret.len() < 32 {
            return Err("SUPABASE_JWT_SECRET must be at least 32 characters".into());
        }

        let supabase_url = var("SUPABASE_URL")
            .unwrap_or_else(|| "http://localhost:8000".to_string())
            .trim_end_matches('/')
            .to_string();
        let supabase_public_url = var("SUPABASE_PUBLIC_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or_else(|| supabase_url.clone());

        let admin_user_ids = match var("ADMIN_USER_IDS") {
            Some(raw) => parse_list(&raw)
                .iter()
                .map(|s| Uuid::parse_str(s).map_err(|e| format!("Invalid ADMIN_USER_IDS entry '{s}': {e}")))
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };

        Ok(Self {
            host: var("HOST").unwrap_or_else(|| "0.0.0.0".to_string()),
            port: parse("PORT", 3000u16)?,
            database_url,
            direct_database_url: var("DIRECT_DATABASE_URL"),
            run_migrations: parse_bool("RUN_MIGRATIONS", true)?,
            db_max_connections: parse("DB_MAX_CONNECTIONS", 5u32)?,
            supabase_jwt_secret,
            gotrue_url: var("GOTRUE_URL").unwrap_or_else(|| format!("{supabase_url}/auth/v1")),
            storage_url: var("STORAGE_URL").unwrap_or_else(|| format!("{supabase_url}/storage/v1")),
            supabase_url,
            supabase_public_url,
            supabase_anon_key: var("SUPABASE_ANON_KEY"),
            supabase_service_role_key: var("SUPABASE_SERVICE_ROLE_KEY"),
            admin_user_ids,
            cors_allowed_origins: var("CORS_ALLOWED_ORIGINS")
                .map(|r| parse_list(&r))
                .unwrap_or_default(),
            trust_proxy_headers: parse_bool("TRUST_PROXY_HEADERS", true)?,
            rate_limit_per_second: parse("RATE_LIMIT_PER_SECOND", 20.0f64)?,
            rate_limit_burst: parse("RATE_LIMIT_BURST", 60.0f64)?,
            metrics_token: var("METRICS_TOKEN"),
            stripe_webhook_secret: var("STRIPE_WEBHOOK_SECRET"),
            stripe_price_plans: var("STRIPE_PRICE_PLANS")
                .map(|r| parse_pairs(&r))
                .unwrap_or_default(),
            lemonsqueezy_webhook_secret: var("LEMONSQUEEZY_WEBHOOK_SECRET"),
            lemonsqueezy_variant_plans: var("LEMONSQUEEZY_VARIANT_PLANS")
                .map(|r| parse_pairs(&r))
                .unwrap_or_default(),
            jobs_enabled: parse_bool("JOBS_ENABLED", true)?,
            jobs_concurrency: parse("JOBS_CONCURRENCY", 2usize)?.max(1),
            realtime_enabled: parse_bool("REALTIME_ENABLED", true)?,
            embedding_api_url: var("EMBEDDING_API_URL").map(|u| u.trim_end_matches('/').to_string()),
            embedding_api_key: var("EMBEDDING_API_KEY"),
            embedding_model: var("EMBEDDING_MODEL")
                .unwrap_or_else(|| "text-embedding-3-small".to_string()),
            embedding_dims: parse("EMBEDDING_DIMS", 1536usize)?,
            app_id,
        })
    }

    /// Minimal configuration for unit tests (no network or database needed).
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            app_id: "saas-test-1".to_string(),
            host: "127.0.0.1".to_string(),
            port: 3000,
            database_url: "postgres://postgres.tenant:pass@localhost:6543/postgres".to_string(),
            direct_database_url: None,
            run_migrations: false,
            db_max_connections: 2,
            supabase_jwt_secret: "test-secret-at-least-32-characters-long!".to_string(),
            supabase_url: "http://localhost:8000".to_string(),
            supabase_public_url: "https://api.example.com".to_string(),
            supabase_anon_key: Some("anon".to_string()),
            supabase_service_role_key: Some("service".to_string()),
            gotrue_url: "http://localhost:8000/auth/v1".to_string(),
            storage_url: "http://localhost:8000/storage/v1".to_string(),
            admin_user_ids: Vec::new(),
            cors_allowed_origins: Vec::new(),
            trust_proxy_headers: true,
            rate_limit_per_second: 20.0,
            rate_limit_burst: 60.0,
            metrics_token: None,
            stripe_webhook_secret: Some("whsec_test".to_string()),
            stripe_price_plans: parse_pairs("price_pro:pro"),
            lemonsqueezy_webhook_secret: Some("ls_test".to_string()),
            lemonsqueezy_variant_plans: HashMap::new(),
            jobs_enabled: false,
            jobs_concurrency: 1,
            realtime_enabled: true,
            embedding_api_url: None,
            embedding_api_key: None,
            embedding_model: "text-embedding-3-small".to_string(),
            embedding_dims: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plan_maps() {
        let map = parse_pairs("price_1:pro, price_2 : team,broken,:x");
        assert_eq!(map.get("price_1").map(String::as_str), Some("pro"));
        assert_eq!(map.get("price_2").map(String::as_str), Some("team"));
        assert_eq!(map.len(), 2);
    }
}
