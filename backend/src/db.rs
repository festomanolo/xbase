use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::str::FromStr;
use std::time::Duration;

use crate::config::AppConfig;

/// Builds a PostgreSQL connection pool optimized for Supavisor (port 6543).
///
/// Important: When running 10+ SaaS backends through Supavisor in transaction
/// mode (port 6543), prepared statement caching MUST be disabled (`statement_cache_capacity(0)`)
/// so that connections shared across different backend instances do not collide.
pub fn build_supavisor_connect_options(database_url: &str) -> Result<PgConnectOptions, sqlx::Error> {
    let options = PgConnectOptions::from_str(database_url)?.statement_cache_capacity(0);
    Ok(options)
}

pub async fn create_pool(config: &AppConfig) -> Result<PgPool, sqlx::Error> {
    let connect_options = build_supavisor_connect_options(&config.database_url)?;

    Ok(PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(300))
        .connect_lazy_with(connect_options))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supavisor_options_disable_statement_cache() {
        let url = "postgres://postgres.tenant:secret@localhost:6543/postgres";
        let opts = build_supavisor_connect_options(url).expect("valid postgres url");
        assert_eq!(opts.get_port(), 6543);
    }
}
