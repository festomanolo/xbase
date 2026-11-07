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
