//! Billing webhooks (Stripe + LemonSqueezy).
//!
//! The HTTP handler only verifies the signature, stores the event idempotently
//! in `xbase.webhook_events` and enqueues a job — so it answers in milliseconds
//! and provider retries are harmless. A background worker then syncs the
//! subscription into `xbase.workspaces` (plan, status, period end).
//!
//! Link a checkout to a workspace by setting `client_reference_id` (Stripe
//! Checkout) or `metadata.workspace_id` (Stripe subscriptions) /
//! `checkout_data.custom.workspace_id` (LemonSqueezy).

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    error::{ApiError, ApiResult},
    jobs,
    state::AppState,
};

type HmacSha256 = Hmac<Sha256>;

const STRIPE_TOLERANCE_SECS: i64 = 300;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/webhooks/stripe", post(stripe_webhook))
        .route("/webhooks/lemonsqueezy", post(lemonsqueezy_webhook))
}

// --- Signature verification -----------------------------------------------

/// Verifies a `Stripe-Signature` header (`t=...,v1=...[,v1=...]`).
pub fn verify_stripe_signature(payload: &[u8], header: &str, secret: &str, now: i64) -> Result<(), &'static str> {
    let mut timestamp: Option<i64> = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => timestamp = v.parse().ok(),
            Some(("v1", v)) => signatures.push(v),
            _ => {}
        }
    }
    let ts = timestamp.ok_or("missing timestamp")?;
    if (now - ts).abs() > STRIPE_TOLERANCE_SECS {
        return Err("timestamp outside tolerance");
    }
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| "bad secret")?;
    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let expected = mac.finalize().into_bytes();

    let ok = signatures.iter().any(|sig| {
        hex::decode(sig)
            .map(|bytes| constant_time_eq(&bytes, &expected))
            .unwrap_or(false)
    });
    if ok { Ok(()) } else { Err("signature mismatch") }
}

/// Verifies LemonSqueezy's `X-Signature` (hex HMAC-SHA256 of the raw body).
pub fn verify_lemonsqueezy_signature(payload: &[u8], signature: &str, secret: &str) -> Result<(), &'static str> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| "bad secret")?;
    mac.update(payload);
    let sig = hex::decode(signature.trim()).map_err(|_| "malformed signature")?;
    mac.verify_slice(&sig).map_err(|_| "signature mismatch")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// --- HTTP handlers --------------------------------------------------------

async fn record_and_enqueue(
    state: &AppState,
    provider: &str,
    event_id: &str,
    event_type: &str,
    payload: Value,
) -> ApiResult<Json<Value>> {
    let mut tx = state.pool.begin().await?;
    let inserted: Option<String> = sqlx::query_scalar(
        "insert into xbase.webhook_events (app_id, provider, event_id, event_type, payload) \
         values ($1, $2, $3, $4, $5) on conflict do nothing returning event_id",
    )
    .bind(&state.config.app_id)
    .bind(provider)
    .bind(event_id)
    .bind(event_type)
    .bind(&payload)
    .fetch_optional(&mut *tx)
    .await?;

    if inserted.is_none() {
        tx.rollback().await?;
        return Ok(Json(json!({ "received": true, "duplicate": true })));
    }
    jobs::enqueue(
        &mut *tx,
        &state.config.app_id,
        "billing.webhook",
        &json!({ "provider": provider, "event_id": event_id }),
    )
    .await?;
    tx.commit().await?;
    state.jobs_notify.notify_one();
    Ok(Json(json!({ "received": true })))
}

async fn stripe_webhook(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> ApiResult<(StatusCode, Json<Value>)> {
    let secret = state
        .config
        .stripe_webhook_secret
        .as_deref()
        .ok_or_else(|| ApiError::ServiceUnavailable("STRIPE_WEBHOOK_SECRET is not configured".into()))?;
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("Missing Stripe-Signature header"))?;
    verify_stripe_signature(&body, sig, secret, Utc::now().timestamp())
        .map_err(|e| ApiError::bad_request(format!("Invalid Stripe signature: {e}")))?;

    let event: Value = serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("Invalid JSON"))?;
    let id = event["id"].as_str().ok_or_else(|| ApiError::bad_request("Missing event id"))?.to_string();
    let ty = event["type"].as_str().unwrap_or_default().to_string();
    Ok((StatusCode::OK, record_and_enqueue(&state, "stripe", &id, &ty, event).await?))
}

async fn lemonsqueezy_webhook(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> ApiResult<(StatusCode, Json<Value>)> {
    let secret = state
        .config
        .lemonsqueezy_webhook_secret
        .as_deref()
        .ok_or_else(|| ApiError::ServiceUnavailable("LEMONSQUEEZY_WEBHOOK_SECRET is not configured".into()))?;
    let sig = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("Missing X-Signature header"))?;
    verify_lemonsqueezy_signature(&body, sig, secret)
        .map_err(|e| ApiError::bad_request(format!("Invalid LemonSqueezy signature: {e}")))?;

    let event: Value = serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("Invalid JSON"))?;
    // LemonSqueezy has no event id; the body hash makes retries idempotent.
    let id = hex::encode(Sha256::digest(&body));
    let ty = event["meta"]["event_name"].as_str().unwrap_or_default().to_string();
    Ok((StatusCode::OK, record_and_enqueue(&state, "lemonsqueezy", &id, &ty, event).await?))
}

// --- Subscription sync (runs in the job worker) --------------------------

#[derive(Debug, Default, PartialEq)]
pub struct SubscriptionUpdate {
    pub provider: &'static str,
    pub workspace_id: Option<Uuid>,
    pub customer_id: Option<String>,
    pub subscription_id: Option<String>,
    pub status: Option<String>,
    pub plan: Option<String>,
    pub period_end: Option<DateTime<Utc>>,
}

fn str_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn uuid_of(v: &Value) -> Option<Uuid> {
    v.as_str().and_then(|s| Uuid::parse_str(s).ok())
}

fn ts_of(v: &Value) -> Option<DateTime<Utc>> {
    if let Some(secs) = v.as_i64() {
        return Utc.timestamp_opt(secs, 0).single();
    }
    v.as_str().and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&Utc))
}

/// Statuses after which the workspace falls back to the free plan.
fn is_terminal(status: &str) -> bool {
    matches!(status, "canceled" | "cancelled" | "unpaid" | "incomplete_expired" | "expired")
}

pub fn parse_stripe_event(event: &Value, price_plans: &std::collections::HashMap<String, String>) -> Option<SubscriptionUpdate> {
    let ty = event["type"].as_str()?;
    let obj = &event["data"]["object"];
    match ty {
        "checkout.session.completed" => Some(SubscriptionUpdate {
            provider: "stripe",
            workspace_id: uuid_of(&obj["client_reference_id"]).or_else(|| uuid_of(&obj["metadata"]["workspace_id"])),
            customer_id: str_of(&obj["customer"]),
            subscription_id: str_of(&obj["subscription"]),
            plan: str_of(&obj["metadata"]["plan"]),
            ..Default::default()
        }),
        "customer.subscription.created" | "customer.subscription.updated" | "customer.subscription.deleted" => {
            let item = &obj["items"]["data"][0];
            let price_id = str_of(&item["price"]["id"]);
            let mut status = str_of(&obj["status"]);
            if ty == "customer.subscription.deleted" {
                status = Some("canceled".into());
            }
            Some(SubscriptionUpdate {
                provider: "stripe",
                workspace_id: uuid_of(&obj["metadata"]["workspace_id"]),
                customer_id: str_of(&obj["customer"]),
                subscription_id: str_of(&obj["id"]),
                plan: price_id
                    .and_then(|p| price_plans.get(&p).cloned())
                    .or_else(|| str_of(&obj["metadata"]["plan"])),
                // Newer API versions moved current_period_end onto the item.
                period_end: ts_of(&obj["current_period_end"]).or_else(|| ts_of(&item["current_period_end"])),
                status,
            })
        }
        _ => None,
    }
}

pub fn parse_lemonsqueezy_event(event: &Value, variant_plans: &std::collections::HashMap<String, String>) -> Option<SubscriptionUpdate> {
    let name = event["meta"]["event_name"].as_str()?;
    if !name.starts_with("subscription_") || name.starts_with("subscription_payment") {
        return None;
    }
    let attrs = &event["data"]["attributes"];
    let mut status = str_of(&attrs["status"]);
    if name == "subscription_expired" {
        status = Some("expired".into());
    }
    Some(SubscriptionUpdate {
        provider: "lemonsqueezy",
        workspace_id: uuid_of(&event["meta"]["custom_data"]["workspace_id"]),
        customer_id: str_of(&attrs["customer_id"]),
        subscription_id: str_of(&event["data"]["id"]),
        plan: str_of(&attrs["variant_id"]).and_then(|v| variant_plans.get(&v).cloned()),
        period_end: ts_of(&attrs["renews_at"]).or_else(|| ts_of(&attrs["ends_at"])),
        status,
    })
}

pub async fn apply_subscription(state: &AppState, u: &SubscriptionUpdate) -> Result<u64, sqlx::Error> {
    let plan = match u.status.as_deref() {
        Some(s) if is_terminal(s) => Some("free".to_string()),
        _ => u.plan.clone(),
    };
    let res = sqlx::query(
        r#"
        update xbase.workspaces set
            billing_provider        = $5,
            billing_customer_id     = coalesce($3, billing_customer_id),
            billing_subscription_id = coalesce($4, billing_subscription_id),
            subscription_status     = coalesce($6, subscription_status),
            plan                    = coalesce($7, plan),
            current_period_end      = coalesce($8, current_period_end)
        where app_slug = $1 and (
              ($2::uuid is not null and id = $2)
           or ($4::text is not null and billing_subscription_id = $4)
           or ($2::uuid is null and $4::text is null and $3::text is not null and billing_customer_id = $3))
        "#,
    )
    .bind(&state.config.app_id)
    .bind(u.workspace_id)
    .bind(&u.customer_id)
    .bind(&u.subscription_id)
    .bind(u.provider)
    .bind(&u.status)
    .bind(plan)
    .bind(u.period_end)
    .execute(&state.pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn process_webhook_job(state: &AppState, payload: &Value) -> Result<(), ApiError> {
    let provider = payload["provider"].as_str().unwrap_or_default();
    let event_id = payload["event_id"].as_str().unwrap_or_default();
    let event: Value = sqlx::query_scalar(
        "select payload from xbase.webhook_events where app_id = $1 and provider = $2 and event_id = $3",
    )
    .bind(&state.config.app_id)
    .bind(provider)
    .bind(event_id)
    .fetch_one(&state.pool)
    .await?;

    let update = match provider {
        "stripe" => parse_stripe_event(&event, &state.config.stripe_price_plans),
        "lemonsqueezy" => parse_lemonsqueezy_event(&event, &state.config.lemonsqueezy_variant_plans),
        _ => None,
    };
    if let Some(update) = update {
        let rows = apply_subscription(state, &update).await?;
        if rows == 0 {
            tracing::warn!(provider, event_id, ?update, "webhook matched no workspace");
        }
    }

    sqlx::query(
        "update xbase.webhook_events set processed_at = now() where app_id = $1 and provider = $2 and event_id = $3",
    )
    .bind(&state.config.app_id)
    .bind(provider)
    .bind(event_id)
    .execute(&state.pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn stripe_header(payload: &[u8], secret: &str, ts: i64) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{ts}.").as_bytes());
        mac.update(payload);
        format!("t={ts},v1={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn stripe_signature_verification() {
        let body = br#"{"id":"evt_1"}"#;
        let now = 1_700_000_000;
        let header = stripe_header(body, "whsec_x", now);
        assert!(verify_stripe_signature(body, &header, "whsec_x", now + 10).is_ok());
        assert_eq!(verify_stripe_signature(body, &header, "whsec_y", now), Err("signature mismatch"));
        assert_eq!(verify_stripe_signature(body, &header, "whsec_x", now + 301), Err("timestamp outside tolerance"));
        assert!(verify_stripe_signature(b"tampered", &header, "whsec_x", now).is_err());
    }

    #[test]
    fn lemonsqueezy_signature_verification() {
        let body = br#"{"meta":{}}"#;
        let mut mac = HmacSha256::new_from_slice(b"ls").unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        assert!(verify_lemonsqueezy_signature(body, &sig, "ls").is_ok());
        assert!(verify_lemonsqueezy_signature(body, &sig, "other").is_err());
    }

    #[test]
    fn parses_stripe_subscription_events() {
        let ws = Uuid::new_v4();
        let plans: HashMap<_, _> = [("price_pro".to_string(), "pro".to_string())].into();
        let ev = json!({
            "type": "customer.subscription.updated",
            "data": {"object": {
                "id": "sub_1", "customer": "cus_1", "status": "active",
                "metadata": {"workspace_id": ws.to_string()},
                "items": {"data": [{"price": {"id": "price_pro"}, "current_period_end": 1_800_000_000}]}
            }}
        });
        let u = parse_stripe_event(&ev, &plans).unwrap();
        assert_eq!(u.workspace_id, Some(ws));
        assert_eq!(u.plan.as_deref(), Some("pro"));
        assert_eq!(u.status.as_deref(), Some("active"));
        assert!(u.period_end.is_some());

        let deleted = json!({"type":"customer.subscription.deleted","data":{"object":{"id":"sub_1","status":"active"}}});
        assert_eq!(parse_stripe_event(&deleted, &plans).unwrap().status.as_deref(), Some("canceled"));
        assert!(parse_stripe_event(&json!({"type":"invoice.paid","data":{"object":{}}}), &plans).is_none());
    }

    #[test]
    fn parses_lemonsqueezy_events() {
        let plans: HashMap<_, _> = [("42".to_string(), "team".to_string())].into();
        let ev = json!({
            "meta": {"event_name": "subscription_created", "custom_data": {"workspace_id": Uuid::nil().to_string()}},
            "data": {"id": "99", "attributes": {"status": "active", "variant_id": 42, "customer_id": 7, "renews_at": "2030-01-01T00:00:00.000000Z"}}
        });
        let u = parse_lemonsqueezy_event(&ev, &plans).unwrap();
        assert_eq!(u.plan.as_deref(), Some("team"));
        assert_eq!(u.subscription_id.as_deref(), Some("99"));
        assert_eq!(u.customer_id.as_deref(), Some("7"));
        assert!(u.period_end.is_some());
    }
}
