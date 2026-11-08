use std::sync::Arc;

use sqlx::PgPool;
use tokio::sync::Notify;

use crate::{
    config::AppConfig, metrics::Metrics, rate_limit::RateLimiter, realtime::RealtimeHub, rest::SchemaCache,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<AppConfig>,
    pub http: reqwest::Client,
    pub realtime: Arc<RealtimeHub>,
    pub limiter: Arc<RateLimiter>,
    /// Wakes background job workers immediately after a job is enqueued.
    pub jobs_notify: Arc<Notify>,
    pub metrics: Arc<Metrics>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Arc<AppConfig>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .pool_idle_timeout(std::time::Duration::from_secs(60))
            .user_agent(concat!("xbase-backend/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client builds");
        Self {
            limiter: Arc::new(RateLimiter::new(
                config.rate_limit_per_second,
                config.rate_limit_burst,
            )),
            pool,
            config,
            http,
            realtime: Arc::new(RealtimeHub::new()),
            jobs_notify: Arc::new(Notify::new()),
            metrics: Arc::new(Metrics::default()),
        }
    }
}
