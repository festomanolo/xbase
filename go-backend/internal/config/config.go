// Package config loads the Go backend's environment configuration. Variable
// names match the Rust backend so both can share one .env template.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Config struct {
	AppID            string
	Host             string
	Port             int
	DatabaseURL      string
	DBMaxConnections int32
	// DirectDatabaseURL is the session connection (port 5432) needed for
	// LISTEN/NOTIFY (realtime). Empty disables realtime database features.
	DirectDatabaseURL  string
	JWTSecret          string
	TrustProxyHeaders  bool
	RateLimitPerSecond float64
	RateLimitBurst     float64
	// RateLimitBackend is "memory" (per replica) or "postgres" (shared by all replicas).
	RateLimitBackend   string
	CORSAllowedOrigins []string
	MetricsToken       string
	AdminUserIDs       []string

	// Supabase services (storage proxy)
	SupabaseURL        string
	SupabasePublicURL  string
	StorageURL         string
	SupabaseAnonKey    string
	SupabaseServiceKey string

	// Realtime
	RealtimeEnabled bool
	// RealtimeCluster fans rooms/presence out to other replicas via NOTIFY.
	RealtimeCluster bool

	// Billing
	StripeWebhookSecret       string
	StripePricePlans          map[string]string
	LemonSqueezyWebhookSecret string
	LemonSqueezyVariantPlans  map[string]string

	// Vector / embeddings
	EmbeddingAPIURL string
	EmbeddingAPIKey string
	EmbeddingModel  string
	EmbeddingDims   int
}

var appIDPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func Load() (*Config, error) {
	c := &Config{
		AppID:       env("APP_ID", "xbase-saas"),
		Host:        env("HOST", "0.0.0.0"),
		DatabaseURL: env("DATABASE_URL", ""),
		JWTSecret:   env("SUPABASE_JWT_SECRET", ""),
	}
	if !appIDPattern.MatchString(c.AppID) {
		return nil, fmt.Errorf("APP_ID must contain only lowercase letters, digits and '-'")
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("missing required environment variable: DATABASE_URL")
	}
	if len(c.JWTSecret) < 32 {
		return nil, fmt.Errorf("SUPABASE_JWT_SECRET must be set and at least 32 characters")
	}

	var err error
	if c.Port, err = strconv.Atoi(env("PORT", "3000")); err != nil {
		return nil, fmt.Errorf("invalid PORT: %w", err)
	}
	maxConns, err := strconv.Atoi(env("DB_MAX_CONNECTIONS", "5"))
	if err != nil {
		return nil, fmt.Errorf("invalid DB_MAX_CONNECTIONS: %w", err)
	}
	c.DBMaxConnections = int32(maxConns)
	c.DirectDatabaseURL = env("DIRECT_DATABASE_URL", "")
	c.MetricsToken = env("METRICS_TOKEN", "")
	c.AdminUserIDs = splitList(env("ADMIN_USER_IDS", ""))

	switch strings.ToLower(env("RATE_LIMIT_BACKEND", "memory")) {
	case "memory":
		c.RateLimitBackend = "memory"
	case "postgres", "shared":
		c.RateLimitBackend = "postgres"
	default:
		return nil, fmt.Errorf("invalid RATE_LIMIT_BACKEND: expected memory|postgres")
	}

	c.SupabaseURL = strings.TrimRight(env("SUPABASE_URL", "http://localhost:8000"), "/")
	c.SupabasePublicURL = strings.TrimRight(env("SUPABASE_PUBLIC_URL", c.SupabaseURL), "/")
	c.StorageURL = strings.TrimRight(env("STORAGE_URL", c.SupabaseURL+"/storage/v1"), "/")
	c.SupabaseAnonKey = env("SUPABASE_ANON_KEY", "")
	c.SupabaseServiceKey = env("SUPABASE_SERVICE_ROLE_KEY", "")

	if c.RealtimeEnabled, err = strconv.ParseBool(env("REALTIME_ENABLED", "true")); err != nil {
		return nil, fmt.Errorf("invalid REALTIME_ENABLED: %w", err)
	}
	if c.RealtimeCluster, err = strconv.ParseBool(env("REALTIME_CLUSTER", "false")); err != nil {
		return nil, fmt.Errorf("invalid REALTIME_CLUSTER: %w", err)
	}

	c.StripeWebhookSecret = env("STRIPE_WEBHOOK_SECRET", "")
	c.StripePricePlans = ParsePairs(env("STRIPE_PRICE_PLANS", ""))
	c.LemonSqueezyWebhookSecret = env("LEMONSQUEEZY_WEBHOOK_SECRET", "")
	c.LemonSqueezyVariantPlans = ParsePairs(env("LEMONSQUEEZY_VARIANT_PLANS", ""))

	c.EmbeddingAPIURL = strings.TrimRight(env("EMBEDDING_API_URL", ""), "/")
	c.EmbeddingAPIKey = env("EMBEDDING_API_KEY", "")
	c.EmbeddingModel = env("EMBEDDING_MODEL", "text-embedding-3-small")
	if c.EmbeddingDims, err = strconv.Atoi(env("EMBEDDING_DIMS", "1536")); err != nil || c.EmbeddingDims < 1 {
		return nil, fmt.Errorf("invalid EMBEDDING_DIMS")
	}
	if c.TrustProxyHeaders, err = strconv.ParseBool(env("TRUST_PROXY_HEADERS", "true")); err != nil {
		return nil, fmt.Errorf("invalid TRUST_PROXY_HEADERS: %w", err)
	}
	if c.RateLimitPerSecond, err = strconv.ParseFloat(env("RATE_LIMIT_PER_SECOND", "20"), 64); err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_PER_SECOND: %w", err)
	}
	if c.RateLimitBurst, err = strconv.ParseFloat(env("RATE_LIMIT_BURST", "60"), 64); err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_BURST: %w", err)
	}
	for _, o := range strings.Split(env("CORS_ALLOWED_ORIGINS", ""), ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.CORSAllowedOrigins = append(c.CORSAllowedOrigins, o)
		}
	}
	return c, nil
}
