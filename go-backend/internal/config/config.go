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
	AppID              string
	Host               string
	Port               int
	DatabaseURL        string
	DBMaxConnections   int32
	JWTSecret          string
	TrustProxyHeaders  bool
	RateLimitPerSecond float64
	RateLimitBurst     float64
	CORSAllowedOrigins []string
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
