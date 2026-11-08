package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Giving every app its own Supavisor tenant (external_id = APP_ID) gives each one its
// own server-side pool, so one busy app cannot starve the others of Postgres
// connections. The app then connects as `postgres.<APP_ID>` on port 6543.
//
// The management API (PUT /api/tenants/:id) is authenticated with an HS256 JWT signed
// by Supavisor's API_JWT_SECRET.

type supavisorUser struct {
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
	PoolSize   int    `json:"pool_size"`
	MaxClients int    `json:"max_clients,omitempty"`
	ModeType   string `json:"mode_type"`
	IsManager  bool   `json:"is_manager"`
}

type supavisorTenant struct {
	ExternalID        string          `json:"external_id"`
	DBHost            string          `json:"db_host"`
	DBPort            int             `json:"db_port"`
	DBDatabase        string          `json:"db_database"`
	IPVersion         string          `json:"ip_version"`
	RequireUser       bool            `json:"require_user"`
	AuthQuery         string          `json:"auth_query"`
	DefaultPoolSize   int             `json:"default_pool_size"`
	DefaultMaxClients int             `json:"default_max_clients,omitempty"`
	Users             []supavisorUser `json:"users"`
}

func tenantFor(cfg *Config, a CapacityApp, password string) supavisorTenant {
	s := cfg.Supavisor
	return supavisorTenant{
		ExternalID: a.AppID, DBHost: s.DBHost, DBPort: s.DBPort, DBDatabase: s.DBName,
		IPVersion: "auto", RequireUser: false, AuthQuery: s.AuthQuery,
		DefaultPoolSize: a.PoolSize, DefaultMaxClients: a.MaxClients,
		Users: []supavisorUser{{
			DBUser: s.DBUser, DBPassword: password, PoolSize: a.PoolSize, MaxClients: a.MaxClients,
			ModeType: "transaction", IsManager: true,
		}},
	}
}

// hs256 signs a minimal JWT; Supavisor only checks the signature and expiry.
func hs256(secret string, now time.Time) string {
	enc := base64.RawURLEncoding
	head := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"role": "service", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	body := head + "." + enc.EncodeToString(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return body + "." + enc.EncodeToString(mac.Sum(nil))
}

// syncSupavisor refuses to push pool sizes that do not fit Postgres (run `plan` first).
func syncSupavisor(ctx context.Context, cfg *Config, out io.Writer, dry bool, client *http.Client) error {
	p := Plan(cfg.Capacity)
	if !p.OK() {
		p.Print(out, cfg.Capacity)
		return fmt.Errorf("capacity plan does not fit; not pushing pool sizes")
	}
	if len(cfg.Capacity.Apps) == 0 {
		return fmt.Errorf("no capacity.apps configured")
	}
	secret := os.Getenv(cfg.Supavisor.APISecretEnv)
	password := os.Getenv(cfg.Supavisor.DBPasswordEnv)
	if !dry && (secret == "" || password == "") {
		return fmt.Errorf("set %s and %s in the environment", cfg.Supavisor.APISecretEnv, cfg.Supavisor.DBPasswordEnv)
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	base := strings.TrimRight(cfg.Supavisor.APIURL, "/")
	for _, a := range cfg.Capacity.Apps {
		t := tenantFor(cfg, a, password)
		if dry {
			fmt.Fprintf(out, "would PUT %s/api/tenants/%s pool_size=%d max_clients=%d\n", base, a.AppID, a.PoolSize, a.MaxClients)
			continue
		}
		body, _ := json.Marshal(map[string]any{"tenant": t})
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/api/tenants/"+a.AppID, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+hs256(secret, time.Now()))
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("%s: %w", a.AppID, err)
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("%s: supavisor answered %d: %s", a.AppID, resp.StatusCode, strings.TrimSpace(string(msg)))
		}
		fmt.Fprintf(out, "tenant %s: pool_size=%d max_clients=%d (connect as %s.%s on :6543)\n", a.AppID, a.PoolSize, a.MaxClients, cfg.Supavisor.DBUser, a.AppID)
	}
	return nil
}
