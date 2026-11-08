pub mod api_keys;
pub mod auth;
pub mod billing;
pub mod config;
pub mod db;
pub mod error;
pub mod gotrue;
pub mod jobs;
pub mod metrics;
pub mod rate_limit;
pub mod realtime;
pub mod rest;
pub mod rls;
pub mod routes;
pub mod state;
pub mod storage;
pub mod vector;
pub mod workspaces;

use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{config::AppConfig, db::create_pool, state::AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Operator subcommands, handled before any configuration is loaded (so they never
    // need DATABASE_URL). The slim runtime image has no curl, so the binary probes itself:
    //   xbase-backend healthcheck        exit 0 iff GET /health is 200 (Docker HEALTHCHECK)
    //   xbase-backend probe [/path]      print the response body (default /metrics), exit 0 iff 200
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("healthcheck") => std::process::exit(if local_get("/health").await.is_some_and(|(c, _)| c == 200) { 0 } else { 1 }),
        Some("probe") => {
            let path = args.next().unwrap_or_else(|| "/metrics".to_string());
            match local_get(&path).await {
                Some((code, body)) => {
                    print!("{body}");
                    std::process::exit(if code == 200 { 0 } else { 1 });
                }
                None => std::process::exit(2),
            }
        }
        _ => {}
    }

    let _ = dotenvy::dotenv();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "xbase_backend=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Arc::new(AppConfig::from_env()?);

    // 1. Schema migrations over a direct (session) connection.
    match (&config.direct_database_url, config.run_migrations) {
        (Some(url), true) => {
            db::run_migrations(url).await?;
            tracing::info!("database migrations applied");
        }
        (None, true) => tracing::warn!(
            "RUN_MIGRATIONS=true but DIRECT_DATABASE_URL (port 5432) is not set; skipping migrations"
        ),
        _ => {}
    }

    // 2. Request pool through Supavisor (transaction mode).
    let pool = create_pool(&config).await?;
    if let Err(e) = db::register_app(&pool, &config.app_id).await {
        tracing::warn!(error = %e, "could not register app in xbase.apps (migrations applied?)");
    }

    let state = AppState::new(pool, Arc::clone(&config));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // 3. Background tasks.
    let mut tasks = Vec::new();
    if config.jobs_enabled {
        tasks.extend(jobs::spawn_workers(&state, shutdown_rx.clone()));
    }
    if config.realtime_cluster && !config.realtime_enabled {
        tracing::warn!("REALTIME_CLUSTER=true has no effect while REALTIME_ENABLED=false");
    }
    if config.realtime_enabled {
        match &config.direct_database_url {
            Some(url) => {
                tokio::spawn(realtime::run_change_listener(state.realtime.clone(), url.clone()));
                if config.realtime_cluster {
                    realtime::spawn_cluster(&state, url.clone());
                    tracing::info!("realtime cluster fan-out enabled");
                }
            }
            None => tracing::warn!("DIRECT_DATABASE_URL not set; realtime database changes disabled"),
        }
    }
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                state.limiter.sweep();
                if state.config.rate_limit_backend == config::RateLimitBackend::Postgres {
                    rate_limit::sweep_shared(&state).await;
                }
            }
        });
    }

    let app = routes::build_router(state.clone());

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    tracing::info!(
        app_id = %config.app_id,
        listen_addr = %addr,
        "Starting xbase Rust backend (Supavisor pooled mode)"
    );

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    let _ = shutdown_tx.send(true);
    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(10), t).await;
    }
    state.pool.close().await;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Shutdown signal received, draining connections...");
}
