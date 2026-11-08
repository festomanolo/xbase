// Package auth verifies Supabase GoTrue JWTs locally (no network round-trip)
// and authenticates hashed xbase API keys.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Claims holds the standard Supabase claims plus the full raw claim set,
// which is forwarded to Postgres as request.jwt.claims for RLS.
type Claims struct {
	Subject string
	Email   string
	Role    string
	Raw     map[string]any
}

var ErrInvalidToken = errors.New("invalid or expired Supabase JWT")

// Verify validates an HS256 Supabase JWT with the shared JWT secret.
func Verify(token, secret string) (*Claims, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithLeeway(5_000_000_000))
	if err != nil || !parsed.Valid {
		return nil, ErrInvalidToken
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	c := &Claims{Raw: mc}
	c.Subject, _ = mc["sub"].(string)
	c.Email, _ = mc["email"].(string)
	c.Role, _ = mc["role"].(string)
	// Supabase's anon / service_role API keys carry no `sub`. Only service_role
	// is accepted without one (anon has no user identity).
	if c.Role == "" || (c.Subject == "" && c.Role != "service_role") {
		return nil, ErrInvalidToken
	}
	return c, nil
}

// IsServiceRole reports whether the token is a Supabase service_role key.
func (c *Claims) IsServiceRole() bool { return c.Role == "service_role" }

// BearerToken extracts the token from `Authorization: Bearer <token>`.
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(t)
	}
	return ""
}

// APIKeyHeader carries server-to-server keys (`xb_<prefix>_<secret>`).
const APIKeyHeader = "X-Api-Key"

// HashAPIKey returns the SHA-256 hex digest stored in xbase.api_keys.key_hash.
func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// APIKeyPrefix returns the public prefix of a well-formed key, or "".
func APIKeyPrefix(raw string) string {
	rest, ok := strings.CutPrefix(raw, "xb_")
	if !ok {
		return ""
	}
	prefix, secret, ok := strings.Cut(rest, "_")
	if !ok || len(prefix) != 12 || secret == "" {
		return ""
	}
	return prefix
}
