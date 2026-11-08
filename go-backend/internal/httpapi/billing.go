package httpapi

// Billing webhooks (Stripe + LemonSqueezy) — same verification, idempotency and
// plan-sync rules as backend/src/billing.rs.
//
// Difference: the Rust backend enqueues a job and a worker syncs the plan. This
// template has no job queue, so the sync runs in the webhook's own transaction:
// either the event is recorded AND applied, or neither (the provider retries).
//
// Link a checkout to a workspace with `client_reference_id` (Stripe Checkout) or
// `metadata.workspace_id` (Stripe subscriptions) /
// `checkout_data.custom.workspace_id` (LemonSqueezy).

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const stripeTolerance = 5 * time.Minute

func (s *Server) billingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /webhooks/stripe", s.stripeWebhook)
	mux.HandleFunc("POST /webhooks/lemonsqueezy", s.lemonSqueezyWebhook)
}

// verifyStripeSignature checks a `Stripe-Signature` header (t=...,v1=...[,v1=...]).
func verifyStripeSignature(payload []byte, header, secret string, now time.Time) error {
	var ts int64
	var haveTS bool
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				ts, haveTS = n, true
			}
		case "v1":
			sigs = append(sigs, v)
		}
	}
	if !haveTS {
		return errors.New("missing timestamp")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > stripeTolerance || d < -stripeTolerance {
		return errors.New("timestamp outside tolerance")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	mac.Write(payload)
	want := mac.Sum(nil)
	for _, sig := range sigs {
		if got, err := hex.DecodeString(sig); err == nil && hmac.Equal(got, want) {
			return nil
		}
	}
	return errors.New("signature mismatch")
}

// verifyLemonSqueezySignature checks `X-Signature` (hex HMAC-SHA256 of the body).
func verifyLemonSqueezySignature(payload []byte, signature, secret string) error {
	got, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return errors.New("malformed signature")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("signature mismatch")
	}
	return nil
}

func (s *Server) stripeWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StripeWebhookSecret == "" {
		writeAPIError(w, errUnavailable("STRIPE_WEBHOOK_SECRET is not configured"))
		return
	}
	body, ok := readWebhookBody(w, r)
	if !ok {
		return
	}
	sig := r.Header.Get("Stripe-Signature")
	if sig == "" {
		writeAPIError(w, errBadRequest("Missing Stripe-Signature header"))
		return
	}
	if err := verifyStripeSignature(body, sig, s.cfg.StripeWebhookSecret, time.Now()); err != nil {
		writeAPIError(w, errBadRequest("Invalid Stripe signature: %s", err))
		return
	}
	event, err := decodeEvent(body)
	if err != nil {
		writeAPIError(w, errBadRequest("Invalid JSON"))
		return
	}
	id := str(event["id"])
	if id == "" {
		writeAPIError(w, errBadRequest("Missing event id"))
		return
	}
	s.recordAndApply(w, r, "stripe", id, str(event["type"]), body, parseStripeEvent(event, s.cfg.StripePricePlans))
}

func (s *Server) lemonSqueezyWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.LemonSqueezyWebhookSecret == "" {
		writeAPIError(w, errUnavailable("LEMONSQUEEZY_WEBHOOK_SECRET is not configured"))
		return
	}
	body, ok := readWebhookBody(w, r)
	if !ok {
		return
	}
	sig := r.Header.Get("X-Signature")
	if sig == "" {
		writeAPIError(w, errBadRequest("Missing X-Signature header"))
		return
	}
	if err := verifyLemonSqueezySignature(body, sig, s.cfg.LemonSqueezyWebhookSecret); err != nil {
		writeAPIError(w, errBadRequest("Invalid LemonSqueezy signature: %s", err))
		return
	}
	event, err := decodeEvent(body)
	if err != nil {
		writeAPIError(w, errBadRequest("Invalid JSON"))
		return
	}
	// LemonSqueezy has no event id; the body hash makes retries idempotent.
	sum := sha256.Sum256(body)
	meta, _ := event["meta"].(map[string]any)
	s.recordAndApply(w, r, "lemonsqueezy", hex.EncodeToString(sum[:]), str(meta["event_name"]), body,
		parseLemonSqueezyEvent(event, s.cfg.LemonSqueezyVariantPlans))
}

func readWebhookBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeAPIError(w, errBadRequest("Request body too large or unreadable"))
		return nil, false
	}
	return body, true
}

// decodeEvent keeps numbers exact (json.Number), so ids like 42 never become 42.0.
func decodeEvent(body []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var ev map[string]any
	if err := dec.Decode(&ev); err != nil {
		return nil, err
	}
	return ev, nil
}

// recordAndApply stores the event once and applies its subscription update, atomically.
func (s *Server) recordAndApply(w http.ResponseWriter, r *http.Request, provider, eventID, eventType string, raw []byte, upd *subscriptionUpdate) {
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		dbError(w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	var inserted string
	err = tx.QueryRow(ctx, `
		insert into xbase.webhook_events (app_id, provider, event_id, event_type, payload)
		values ($1, $2, $3, $4, $5::jsonb) on conflict do nothing returning event_id`,
		s.cfg.AppID, provider, eventID, eventType, string(raw)).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, map[string]any{"received": true, "duplicate": true})
		return
	}
	if err != nil {
		dbError(w, err)
		return
	}
	if upd != nil {
		rows, err := s.applySubscription(ctx, tx, upd)
		if err != nil {
			dbError(w, err)
			return
		}
		if rows == 0 {
			slog.Warn("webhook matched no workspace", "provider", provider, "event_id", eventID)
		}
	}
	if _, err := tx.Exec(ctx,
		"update xbase.webhook_events set processed_at = now() where app_id = $1 and provider = $2 and event_id = $3",
		s.cfg.AppID, provider, eventID); err != nil {
		dbError(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": true})
}

// --- subscription mapping ------------------------------------------------------

type subscriptionUpdate struct {
	Provider       string
	WorkspaceID    string
	CustomerID     string
	SubscriptionID string
	Status         string
	Plan           string
	PeriodEnd      *time.Time
}

// str renders strings and numbers as a string ("" for anything else).
func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	}
	return ""
}

func dig(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			a, ok := v.([]any)
			if !ok || k >= len(a) {
				return nil
			}
			v = a[k]
		}
	}
	return v
}

func uuidOf(v any) string {
	if s, ok := v.(string); ok && isUUID(s) {
		return strings.ToLower(s)
	}
	return ""
}

func tsOf(v any) *time.Time {
	switch t := v.(type) {
	case json.Number:
		if n, err := t.Int64(); err == nil {
			ts := time.Unix(n, 0).UTC()
			return &ts
		}
	case string:
		if ts, err := time.Parse(time.RFC3339, t); err == nil {
			ts = ts.UTC()
			return &ts
		}
	}
	return nil
}

func isTerminalStatus(s string) bool {
	switch s {
	case "canceled", "cancelled", "unpaid", "incomplete_expired", "expired":
		return true
	}
	return false
}

func parseStripeEvent(ev map[string]any, pricePlans map[string]string) *subscriptionUpdate {
	ty := str(ev["type"])
	obj := dig(ev, "data", "object")
	switch ty {
	case "checkout.session.completed":
		ws := uuidOf(dig(obj, "client_reference_id"))
		if ws == "" {
			ws = uuidOf(dig(obj, "metadata", "workspace_id"))
		}
		return &subscriptionUpdate{
			Provider: "stripe", WorkspaceID: ws, CustomerID: str(dig(obj, "customer")),
			SubscriptionID: str(dig(obj, "subscription")), Plan: str(dig(obj, "metadata", "plan")),
		}
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
		item := dig(obj, "items", "data", 0)
		plan := pricePlans[str(dig(item, "price", "id"))]
		if plan == "" {
			plan = str(dig(obj, "metadata", "plan"))
		}
		status := str(dig(obj, "status"))
		if ty == "customer.subscription.deleted" {
			status = "canceled"
		}
		end := tsOf(dig(obj, "current_period_end"))
		if end == nil { // newer API versions moved it onto the item
			end = tsOf(dig(item, "current_period_end"))
		}
		return &subscriptionUpdate{
			Provider: "stripe", WorkspaceID: uuidOf(dig(obj, "metadata", "workspace_id")),
			CustomerID: str(dig(obj, "customer")), SubscriptionID: str(dig(obj, "id")),
			Plan: plan, PeriodEnd: end, Status: status,
		}
	}
	return nil
}

func parseLemonSqueezyEvent(ev map[string]any, variantPlans map[string]string) *subscriptionUpdate {
	name := str(dig(ev, "meta", "event_name"))
	if !strings.HasPrefix(name, "subscription_") || strings.HasPrefix(name, "subscription_payment") {
		return nil
	}
	attrs := dig(ev, "data", "attributes")
	status := str(dig(attrs, "status"))
	if name == "subscription_expired" {
		status = "expired"
	}
	end := tsOf(dig(attrs, "renews_at"))
	if end == nil {
		end = tsOf(dig(attrs, "ends_at"))
	}
	return &subscriptionUpdate{
		Provider: "lemonsqueezy", WorkspaceID: uuidOf(dig(ev, "meta", "custom_data", "workspace_id")),
		CustomerID: str(dig(attrs, "customer_id")), SubscriptionID: str(dig(ev, "data", "id")),
		Plan: variantPlans[str(dig(attrs, "variant_id"))], PeriodEnd: end, Status: status,
	}
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Server) applySubscription(ctx context.Context, tx pgx.Tx, u *subscriptionUpdate) (int64, error) {
	plan := u.Plan
	if isTerminalStatus(u.Status) {
		plan = "free"
	}
	tag, err := tx.Exec(ctx, `
		update xbase.workspaces set
		    billing_provider        = $5,
		    billing_customer_id     = coalesce($3::text, billing_customer_id),
		    billing_subscription_id = coalesce($4::text, billing_subscription_id),
		    subscription_status     = coalesce($6::text, subscription_status),
		    plan                    = coalesce($7::text, plan),
		    current_period_end      = coalesce($8::timestamptz, current_period_end)
		where app_slug = $1 and (
		      ($2::uuid is not null and id = $2::uuid)
		   or ($4::text is not null and billing_subscription_id = $4::text)
		   or ($2::uuid is null and $4::text is null and $3::text is not null and billing_customer_id = $3::text))`,
		s.cfg.AppID, nullable(u.WorkspaceID), nullable(u.CustomerID), nullable(u.SubscriptionID),
		u.Provider, nullable(u.Status), nullable(plan), u.PeriodEnd)
	return tag.RowsAffected(), err
}
