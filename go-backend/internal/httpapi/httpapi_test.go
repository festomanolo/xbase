package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/festomanolo/xbase/go-backend/internal/auth"
	"github.com/festomanolo/xbase/go-backend/internal/config"
	"github.com/festomanolo/xbase/go-backend/internal/ratelimit"
)

const secret = "test-secret-at-least-32-characters-long!"

func newServer(t *testing.T, burst float64) http.Handler {
	t.Helper()
	cfg := &config.Config{AppID: "saas-test", JWTSecret: secret, TrustProxyHeaders: true}
	// Lazily-connecting pool: these tests never touch the database.
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return New(cfg, pool, ratelimit.New(0.01, burst)).Handler()
}

func sign(t *testing.T, sub, role string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub, "role": role, "email": "a@b.c", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	rec := do(newServer(t, 10), httptest.NewRequest("GET", "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestMeRequiresToken(t *testing.T) {
	h := newServer(t, 10)
	if rec := do(h, httptest.NewRequest("GET", "/api/v1/me", nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, "11111111-1111-1111-1111-111111111111", "authenticated"))
	if rec := do(h, req); rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
}

func TestRejectsForgedToken(t *testing.T) {
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "x", "role": "authenticated", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("some-other-secret-that-is-32-chars-long"))
	if _, err := auth.Verify(tok, secret); err == nil {
		t.Fatal("expected forged token to be rejected")
	}
}

func TestRateLimit(t *testing.T) {
	h := newServer(t, 2)
	req := func() *http.Request {
		r := httptest.NewRequest("GET", "/api/v1/me", nil)
		r.Header.Set("X-Real-Ip", "9.9.9.9")
		return r
	}
	do(h, req())
	do(h, req())
	rec := do(h, req())
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAPIKeyPrefix(t *testing.T) {
	if auth.APIKeyPrefix("xb_abcdefabcdef_secret") != "abcdefabcdef" {
		t.Fatal("expected prefix")
	}
	if auth.APIKeyPrefix("xb_short_secret") != "" || auth.APIKeyPrefix("sk_live") != "" {
		t.Fatal("expected malformed keys to be rejected")
	}
	if len(auth.HashAPIKey("x")) != 64 {
		t.Fatal("expected sha256 hex")
	}
}
