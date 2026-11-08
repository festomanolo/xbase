package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Duration is a JSON string such as "45s" or "10m".
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

// ServiceConfig is one autoscaled compose service (one SaaS app's backend).
type ServiceConfig struct {
	Service string `json:"service"` // compose service name, e.g. saas-api-1
	Binary  string `json:"binary"`  // binary inside the image that supports `probe` (xbase-backend | xbase-go-backend)
	Min     int    `json:"min"`
	Max     int    `json:"max"`

	// CPU is docker's per-core percentage divided by CoresPerReplica, so 70 means
	// "70% of this replica's CPU allowance". Set `cpus` in compose to match.
	CoresPerReplica float64 `json:"cores_per_replica"`
	CPUUp           float64 `json:"cpu_up"`   // scale up while avg CPU stays >= this
	CPUDown         float64 `json:"cpu_down"` // scale down while avg CPU stays <= this
	// SaturationUp: scale up while at least this fraction of healthy replicas have
	// every database pool connection busy (idle == 0) while serving requests.
	SaturationUp float64 `json:"saturation_up"`

	UpAfter   Duration `json:"up_after"`   // condition must hold this long before scaling up
	DownAfter Duration `json:"down_after"` // ...and this long before scaling down
	Cooldown  Duration `json:"cooldown"`   // minimum time between two scaling actions
	StepUp    int      `json:"step_up"`
}

type CapacityApp struct {
	AppID string `json:"app_id"`
	// Rust opens two direct LISTEN connections per replica when realtime is on; Go opens one.
	Backend         string `json:"backend"` // rust | go
	PoolSize        int    `json:"pool_size"`
	MaxClients      int    `json:"max_clients"`
	MaxReplicas     int    `json:"max_replicas"`
	DBMaxConns      int    `json:"db_max_connections"` // per replica, sqlx/pgx pool towards Supavisor
	DirectListeners int    `json:"-"`
}

type Capacity struct {
	PostgresMaxConnections int           `json:"postgres_max_connections"`
	// Connections used by Supabase's own services (GoTrue, Storage, Realtime, PostgREST,
	// Studio, Analytics...) plus superuser_reserved_connections and a safety margin.
	ReservedConnections int           `json:"reserved_connections"`
	Apps                []CapacityApp `json:"apps"`
}

type SupavisorConfig struct {
	APIURL         string `json:"api_url"`          // http://127.0.0.1:4000
	APISecretEnv   string `json:"api_secret_env"`   // env var holding API_JWT_SECRET
	DBHost         string `json:"db_host"`          // as seen from Supavisor (db)
	DBPort         int    `json:"db_port"`          // 5432
	DBName         string `json:"db_name"`          // postgres
	DBUser         string `json:"db_user"`          // postgres
	DBPasswordEnv  string `json:"db_password_env"`  // env var holding POSTGRES_PASSWORD
	AuthQuery      string `json:"auth_query"`
}

type Config struct {
	Project      string          `json:"project"`
	ComposeFiles []string        `json:"compose_files"`
	EnvFile      string          `json:"env_file"`
	ComposeCmd   []string        `json:"compose_cmd"` // default ["docker","compose"]
	DockerBin    string          `json:"docker_bin"`  // default "docker"
	WorkDir      string          `json:"work_dir"`
	Interval     Duration        `json:"interval"`
	StateDir     string          `json:"state_dir"`
	Services     []ServiceConfig `json:"services"`
	Capacity     Capacity        `json:"capacity"`
	Supavisor    SupavisorConfig `json:"supavisor"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // a typo in a threshold must not silently fall back to a default
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.applyDefaults()
	return &c, c.Validate()
}

func (c *Config) applyDefaults() {
	if c.Project == "" {
		c.Project = "xbase"
	}
	if len(c.ComposeCmd) == 0 {
		c.ComposeCmd = []string{"docker", "compose"}
	}
	if c.DockerBin == "" {
		c.DockerBin = "docker"
	}
	if c.Interval == 0 {
		c.Interval = Duration(15 * time.Second)
	}
	if c.StateDir == "" {
		c.StateDir = os.TempDir()
	}
	for i := range c.Services {
		s := &c.Services[i]
		if s.Binary == "" {
			s.Binary = "xbase-backend"
		}
		if s.Min == 0 {
			s.Min = 1
		}
		if s.CoresPerReplica == 0 {
			s.CoresPerReplica = 1
		}
		if s.CPUUp == 0 {
			s.CPUUp = 70
		}
		if s.CPUDown == 0 {
			s.CPUDown = 25
		}
		if s.SaturationUp == 0 {
			s.SaturationUp = 0.5
		}
		if s.UpAfter == 0 {
			s.UpAfter = Duration(45 * time.Second)
		}
		if s.DownAfter == 0 {
			s.DownAfter = Duration(10 * time.Minute)
		}
		if s.Cooldown == 0 {
			s.Cooldown = Duration(2 * time.Minute)
		}
		if s.StepUp == 0 {
			s.StepUp = 1
		}
	}
	for i := range c.Capacity.Apps {
		a := &c.Capacity.Apps[i]
		if a.Backend == "" {
			a.Backend = "rust"
		}
		if a.MaxReplicas == 0 {
			a.MaxReplicas = 1
		}
		if a.DBMaxConns == 0 {
			a.DBMaxConns = 5
		}
	}
	if c.Supavisor.DBHost == "" {
		c.Supavisor.DBHost = "db"
	}
	if c.Supavisor.DBPort == 0 {
		c.Supavisor.DBPort = 5432
	}
	if c.Supavisor.DBName == "" {
		c.Supavisor.DBName = "postgres"
	}
	if c.Supavisor.DBUser == "" {
		c.Supavisor.DBUser = "postgres"
	}
	if c.Supavisor.APISecretEnv == "" {
		c.Supavisor.APISecretEnv = "API_JWT_SECRET"
	}
	if c.Supavisor.DBPasswordEnv == "" {
		c.Supavisor.DBPasswordEnv = "POSTGRES_PASSWORD"
	}
	if c.Supavisor.AuthQuery == "" {
		c.Supavisor.AuthQuery = "SELECT * FROM pgbouncer.get_auth($1)"
	}
	if c.Supavisor.APIURL == "" {
		c.Supavisor.APIURL = "http://127.0.0.1:4000"
	}
}

func (c *Config) Validate() error {
	seen := map[string]bool{}
	for _, s := range c.Services {
		switch {
		case s.Service == "":
			return fmt.Errorf("a service entry has no `service` name")
		case seen[s.Service]:
			return fmt.Errorf("service %q listed twice", s.Service)
		case s.Max < s.Min:
			return fmt.Errorf("service %q: max (%d) < min (%d)", s.Service, s.Max, s.Min)
		case s.Min < 1:
			return fmt.Errorf("service %q: min must be >= 1", s.Service)
		case s.CPUDown >= s.CPUUp:
			return fmt.Errorf("service %q: cpu_down (%.0f) must be below cpu_up (%.0f), or it would flap", s.Service, s.CPUDown, s.CPUUp)
		case s.SaturationUp <= 0 || s.SaturationUp > 1:
			return fmt.Errorf("service %q: saturation_up must be in (0,1]", s.Service)
		}
		seen[s.Service] = true
	}
	return nil
}
