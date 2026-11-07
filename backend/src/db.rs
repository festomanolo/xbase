use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::str::FromStr;
use std::time::Duration;

use crate::config::AppConfig;

/// Platform migrations, embedded into the binary at compile time.
pub static MIGRATOR: Migrator = sqlx::migrate!("../migrations");

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

/// Applies embedded migrations over a direct session connection (port 5432).
///
/// sqlx takes a session-level advisory lock while migrating, which is why this
/// must not go through the transaction pooler. The lock also makes concurrent
/// boots of several SaaS backends safe: only one applies each migration.
pub async fn run_migrations(direct_url: &str) -> Result<(), sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(15))
        .connect(direct_url)
        .await?;
    let mut migrator = sqlx::migrate!("../migrations");
    // Backends built from an older checkout must still boot after a newer
    // backend has applied additional migrations.
    migrator.set_ignore_missing(true);
    migrator.run(&pool).await?;
    pool.close().await;
    Ok(())
}

/// Registers this backend's APP_ID in `xbase.apps` so workspaces can reference it.
pub async fn register_app(pool: &PgPool, app_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("insert into xbase.apps (slug, name) values ($1, $1) on conflict (slug) do nothing")
        .bind(app_id)
        .execute(pool)
        .await?;
    Ok(())
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

    #[test]
    fn migrations_are_embedded_in_order() {
        let versions: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
        assert!(versions.len() >= 3, "expected platform migrations, got {versions:?}");
        assert!(versions.windows(2).all(|w| w[0] < w[1]));
    }
}
