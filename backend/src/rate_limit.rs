//! Sharded in-memory token-bucket rate limiter, keyed per API key, per user
//! (JWT `sub`) or per client IP — in that order of precedence.

use std::{
    collections::hash_map::DefaultHasher,
    collections::HashMap,
    hash::{Hash, Hasher},
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{api_keys, auth, state::AppState};

const SHARDS: usize = 16;

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    rate: f64,
    burst: f64,
    shards: Vec<Mutex<HashMap<String, Bucket>>>,
}

pub enum Decision {
    Allow { remaining: u64 },
    Deny { retry_after: Duration },
}

impl RateLimiter {
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            rate: rate_per_sec.max(0.001),
            burst: burst.max(1.0),
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    pub fn burst(&self) -> u64 {
        self.burst as u64
    }

    fn shard(&self, key: &str) -> &Mutex<HashMap<String, Bucket>> {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        &self.shards[(h.finish() as usize) % SHARDS]
    }

    pub fn check_at(&self, key: &str, now: Instant) -> Decision {
        let mut map = self.shard(key).lock().unwrap();
        let bucket = map
            .entry(key.to_string())
            .or_insert(Bucket { tokens: self.burst, last: now });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Decision::Allow { remaining: bucket.tokens as u64 }
        } else {
            let wait = (1.0 - bucket.tokens) / self.rate;
            Decision::Deny { retry_after: Duration::from_secs_f64(wait) }
        }
    }

    pub fn check(&self, key: &str) -> Decision {
        self.check_at(key, Instant::now())
    }

    /// Drops buckets that have been idle long enough to be full again.
    pub fn sweep(&self) {
        let now = Instant::now();
        let refill = Duration::from_secs_f64(self.burst / self.rate) + Duration::from_secs(60);
        for shard in &self.shards {
            shard
                .lock()
                .unwrap()
                .retain(|_, b| now.saturating_duration_since(b.last) < refill);
        }
    }
}

fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trust_proxy: bool) -> String {
    if trust_proxy {
        let forwarded = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .or_else(|| {
                headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.split(',').next())
            })
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(ip) = forwarded {
            return ip.to_string();
        }
    }
    peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unknown".into())
}

/// Derives the bucket key. JWTs are verified (HS256 is ~1µs) so a forged token
/// cannot borrow another user's bucket; invalid tokens fall back to the IP.
pub fn rate_key(state: &AppState, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if let Some(prefix) = headers
        .get(api_keys::API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(api_keys::key_prefix)
    {
        return format!("key:{prefix}");
    }
    if let Some(token) = auth::bearer_token(headers) {
        if let Ok(c) = auth::verify_supabase_jwt(token, &state.config.supabase_jwt_secret) {
            return format!("user:{}", c.sub);
        }
    }
    format!("ip:{}", client_ip(headers, peer, state.config.trust_proxy_headers))
}

pub async fn middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path.starts_with("/health") || path == "/metrics" || path.starts_with("/webhooks/") {
        return next.run(req).await;
    }
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    let key = rate_key(&state, req.headers(), peer);
    let limit = HeaderValue::from(state.limiter.burst());

    match state.limiter.check(&key) {
        Decision::Allow { remaining } => {
            let mut resp = next.run(req).await;
            let h = resp.headers_mut();
            h.insert("x-ratelimit-limit", limit);
            h.insert("x-ratelimit-remaining", HeaderValue::from(remaining));
            resp
        }
        Decision::Deny { retry_after } => {
            state.metrics.rate_limited.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let secs = retry_after.as_secs().max(1);
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "rate_limited", "message": "Too many requests", "retry_after": secs })),
            )
                .into_response();
            let h = resp.headers_mut();
            h.insert("retry-after", HeaderValue::from(secs));
            h.insert("x-ratelimit-limit", limit);
            h.insert("x-ratelimit-remaining", HeaderValue::from(0u64));
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_burst_then_refills() {
        let rl = RateLimiter::new(1.0, 3.0);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(matches!(rl.check_at("k", t0), Decision::Allow { .. }));
        }
        assert!(matches!(rl.check_at("k", t0), Decision::Deny { .. }));
        assert!(matches!(rl.check_at("other", t0), Decision::Allow { .. }), "keys are independent");
        assert!(matches!(rl.check_at("k", t0 + Duration::from_millis(1100)), Decision::Allow { .. }));
    }

    #[test]
    fn ip_extraction_prefers_proxy_headers_when_trusted() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4, 10.0.0.1".parse().unwrap());
        let peer: SocketAddr = "10.0.0.9:1234".parse().unwrap();
        assert_eq!(client_ip(&h, Some(peer), true), "1.2.3.4");
        assert_eq!(client_ip(&h, Some(peer), false), "10.0.0.9");
    }
}
