//! Lock-free Prometheus metrics (`GET /metrics`) for Grafana/Alertmanager.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{auth::bearer_token, state::AppState};

#[derive(Default)]
pub struct Metrics {
    pub requests_2xx: AtomicU64,
    pub requests_3xx: AtomicU64,
    pub requests_4xx: AtomicU64,
    pub requests_5xx: AtomicU64,
    pub in_flight: AtomicU64,
    pub latency_micros_sum: AtomicU64,
    pub rate_limited: AtomicU64,
    pub jobs_succeeded: AtomicU64,
    pub jobs_failed: AtomicU64,
}

pub async fn track(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let m = &state.metrics;
    m.in_flight.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let resp = next.run(req).await;
    m.in_flight.fetch_sub(1, Ordering::Relaxed);
    m.latency_micros_sum
        .fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
    let counter = match resp.status().as_u16() {
        200..=299 => &m.requests_2xx,
        300..=399 => &m.requests_3xx,
        400..=499 => &m.requests_4xx,
        _ => &m.requests_5xx,
    };
    counter.fetch_add(1, Ordering::Relaxed);
    resp
}

pub async fn render(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    if let Some(expected) = &state.config.metrics_token {
        if bearer_token(&headers) != Some(expected.as_str()) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    let m = &state.metrics;
    let app = &state.config.app_id;
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let total = g(&m.requests_2xx) + g(&m.requests_3xx) + g(&m.requests_4xx) + g(&m.requests_5xx);
    let pool = &state.pool;

    let body = format!(
        "# TYPE xbase_http_requests_total counter\n\
xbase_http_requests_total{{app=\"{app}\",class=\"2xx\"}} {}\n\
xbase_http_requests_total{{app=\"{app}\",class=\"3xx\"}} {}\n\
xbase_http_requests_total{{app=\"{app}\",class=\"4xx\"}} {}\n\
xbase_http_requests_total{{app=\"{app}\",class=\"5xx\"}} {}\n\
# TYPE xbase_http_request_duration_seconds summary\n\
xbase_http_request_duration_seconds_sum{{app=\"{app}\"}} {}\n\
xbase_http_request_duration_seconds_count{{app=\"{app}\"}} {total}\n\
# TYPE xbase_http_in_flight gauge\n\
xbase_http_in_flight{{app=\"{app}\"}} {}\n\
# TYPE xbase_rate_limited_total counter\n\
xbase_rate_limited_total{{app=\"{app}\"}} {}\n\
# TYPE xbase_jobs_total counter\n\
xbase_jobs_total{{app=\"{app}\",result=\"success\"}} {}\n\
xbase_jobs_total{{app=\"{app}\",result=\"failure\"}} {}\n\
# TYPE xbase_ws_connections gauge\n\
xbase_ws_connections{{app=\"{app}\"}} {}\n\
# TYPE xbase_ws_rooms gauge\n\
xbase_ws_rooms{{app=\"{app}\"}} {}\n\
# TYPE xbase_db_pool_connections gauge\n\
xbase_db_pool_connections{{app=\"{app}\",state=\"total\"}} {}\n\
xbase_db_pool_connections{{app=\"{app}\",state=\"idle\"}} {}\n",
        g(&m.requests_2xx),
        g(&m.requests_3xx),
        g(&m.requests_4xx),
        g(&m.requests_5xx),
        g(&m.latency_micros_sum) as f64 / 1_000_000.0,
        g(&m.in_flight),
        g(&m.rate_limited),
        g(&m.jobs_succeeded),
        g(&m.jobs_failed),
        state.realtime.connections.load(Ordering::Relaxed),
        state.realtime.room_count(),
        pool.size(),
        pool.num_idle(),
    );
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}
