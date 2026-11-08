package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func svcCfg() ServiceConfig {
	c := &Config{Services: []ServiceConfig{{Service: "api", Max: 4}}}
	c.applyDefaults()
	return c.Services[0]
}

// ---------------------------------------------------------------- Decide

func TestDecideScalesUpOnlyAfterSustainedLoad(t *testing.T) {
	cfg, st := svcCfg(), &State{}
	t0 := time.Unix(1_000_000, 0)
	hot := Aggregate{Healthy: 1, AvgCPU: 90}
	if d := Decide(cfg, st, t0, 1, hot); d.Target != 1 {
		t.Fatalf("scaled immediately: %+v", d)
	}
	if d := Decide(cfg, st, t0.Add(30*time.Second), 1, hot); d.Target != 1 {
		t.Fatalf("scaled before up_after: %+v", d)
	}
	if d := Decide(cfg, st, t0.Add(45*time.Second), 1, hot); d.Target != 2 {
		t.Fatalf("did not scale after up_after: %+v", d)
	}
	// cooldown: still hot, but within 2m of the last action
	Decide(cfg, st, t0.Add(60*time.Second), 2, hot)
	if d := Decide(cfg, st, t0.Add(110*time.Second), 2, hot); d.Target != 2 || !strings.Contains(d.Reason, "cooling") {
		t.Fatalf("cooldown ignored: %+v", d)
	}
	if d := Decide(cfg, st, t0.Add(170*time.Second), 2, hot); d.Target != 3 {
		t.Fatalf("expected scale to 3 after cooldown: %+v", d)
	}
}

func TestDecideBlipResetsTimer(t *testing.T) {
	cfg, st := svcCfg(), &State{}
	t0 := time.Unix(0, 0)
	Decide(cfg, st, t0, 1, Aggregate{Healthy: 1, AvgCPU: 90})
	Decide(cfg, st, t0.Add(20*time.Second), 1, Aggregate{Healthy: 1, AvgCPU: 40}) // dips
	if d := Decide(cfg, st, t0.Add(50*time.Second), 1, Aggregate{Healthy: 1, AvgCPU: 90}); d.Target != 1 {
		t.Fatalf("timer was not reset by the dip: %+v", d)
	}
}

func TestDecidePoolSaturationScalesUp(t *testing.T) {
	cfg, st := svcCfg(), &State{}
	a := Aggregate{Healthy: 2, AvgCPU: 20, SatFrac: 0.5}
	Decide(cfg, st, time.Unix(0, 0), 2, a)
	if d := Decide(cfg, st, time.Unix(60, 0), 2, a); d.Target != 3 {
		t.Fatalf("saturation did not scale up: %+v", d)
	}
}

func TestDecideScaleDown(t *testing.T) {
	cfg, st := svcCfg(), &State{}
	idle := Aggregate{Healthy: 3, AvgCPU: 10}
	t0 := time.Unix(0, 0)
	Decide(cfg, st, t0, 3, idle)
	if d := Decide(cfg, st, t0.Add(9*time.Minute), 3, idle); d.Target != 3 {
		t.Fatalf("scaled down early: %+v", d)
	}
	if d := Decide(cfg, st, t0.Add(10*time.Minute), 3, idle); d.Target != 2 {
		t.Fatalf("did not scale down: %+v", d)
	}
}

func TestDecideNoScaleDownIfSurvivorsWouldBeHot(t *testing.T) {
	cfg, st := svcCfg(), &State{}
	cfg.CPUDown = 40
	// 2 replicas at 35% -> 1 replica at 70% (>= cpu_up-10): must not shrink
	a := Aggregate{Healthy: 2, AvgCPU: 35}
	Decide(cfg, st, time.Unix(0, 0), 2, a)
	if d := Decide(cfg, st, time.Unix(3600, 0), 2, a); d.Target != 2 {
		t.Fatalf("scaled into overload: %+v", d)
	}
}

func TestDecideBoundsAndMissingData(t *testing.T) {
	cfg := svcCfg()
	if d := Decide(cfg, &State{}, time.Unix(0, 0), 0, Aggregate{}); d.Target != 1 {
		t.Fatalf("below min not corrected: %+v", d)
	}
	if d := Decide(cfg, &State{}, time.Unix(0, 0), 7, Aggregate{Healthy: 7}); d.Target != 4 {
		t.Fatalf("above max not corrected: %+v", d)
	}
	if d := Decide(cfg, &State{}, time.Unix(0, 0), 2, Aggregate{Unhealthy: 2}); d.Target != 2 {
		t.Fatalf("acted with no healthy replicas: %+v", d)
	}
	st := &State{}
	hot := Aggregate{Healthy: 4, AvgCPU: 99}
	Decide(cfg, st, time.Unix(0, 0), 4, hot)
	if d := Decide(cfg, st, time.Unix(600, 0), 4, hot); d.Target != 4 || !strings.Contains(d.Reason, "at max") {
		t.Fatalf("exceeded max: %+v", d)
	}
	// an unhealthy replica blocks scale-down
	st = &State{}
	a := Aggregate{Healthy: 2, Unhealthy: 1, AvgCPU: 5}
	Decide(cfg, st, time.Unix(0, 0), 3, a)
	if d := Decide(cfg, st, time.Unix(3600, 0), 3, a); d.Target != 3 {
		t.Fatalf("scaled down with an unhealthy replica: %+v", d)
	}
}

// ---------------------------------------------------------------- config

func TestConfigValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.json")
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	if _, err := LoadConfig(write(`{"services":[{"service":"a","max":2,"cpu_upp":80}]}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := LoadConfig(write(`{"services":[{"service":"a","max":2,"cpu_up":30,"cpu_down":30}]}`)); err == nil {
		t.Fatal("flapping thresholds accepted")
	}
	if _, err := LoadConfig(write(`{"services":[{"service":"a","min":3,"max":2}]}`)); err == nil {
		t.Fatal("max < min accepted")
	}
	c, err := LoadConfig(write(`{"interval":"5s","services":[{"service":"a","max":3,"up_after":"1m"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval.D() != 5*time.Second || c.Services[0].UpAfter.D() != time.Minute || c.Services[0].Cooldown.D() != 2*time.Minute {
		t.Fatalf("durations/defaults wrong: %+v", c.Services[0])
	}
}

// ---------------------------------------------------------------- capacity

func TestPlan(t *testing.T) {
	c := Capacity{PostgresMaxConnections: 100, ReservedConnections: 40, Apps: []CapacityApp{
		{AppID: "a", Backend: "rust", PoolSize: 20, MaxClients: 100, MaxReplicas: 3, DBMaxConns: 10},
		{AppID: "b", Backend: "go", PoolSize: 15, MaxClients: 100, MaxReplicas: 2, DBMaxConns: 5},
	}}
	p := Plan(c)
	// pools 35 + direct (rust 2*3 + go 2 + migrations 1 = 9) = 44 <= 60
	if !p.OK() || p.Used != 44 || p.Budget != 60 {
		t.Fatalf("unexpected plan: %+v", p)
	}
	c.Apps[0].PoolSize = 40
	p = Plan(c)
	if p.OK() {
		t.Fatal("over budget accepted")
	}
	s := Suggest(c, p)
	if s["a"]+s["b"]+p.Direct > p.Budget {
		t.Fatalf("suggestion does not fit: %v", s)
	}
	c.Apps[0].PoolSize, c.Apps[0].MaxClients = 20, 25 // 3x10 = 30 client conns > 25
	if Plan(c).OK() {
		t.Fatal("max_clients overflow accepted")
	}
	var buf bytes.Buffer
	Plan(c).Print(&buf, c)
	if !strings.Contains(buf.String(), "max_clients is 25") {
		t.Fatalf("print: %s", buf.String())
	}
}

// ---------------------------------------------------------------- metrics

const sampleMetrics = `# TYPE xbase_http_in_flight gauge
xbase_http_in_flight{app="a"} 3
xbase_http_in_flight_extra{app="a"} 99
# TYPE xbase_db_pool_connections gauge
xbase_db_pool_connections{app="a",state="total"} 5
xbase_db_pool_connections{app="a",state="idle"} 0
`

func TestMetricValueAndAggregate(t *testing.T) {
	if v, ok := metricValue(sampleMetrics, "xbase_http_in_flight", ""); !ok || v != 3 {
		t.Fatalf("in_flight = %v %v", v, ok)
	}
	if v, _ := metricValue(sampleMetrics, "xbase_db_pool_connections", `state="idle"`); v != 0 {
		t.Fatalf("idle = %v", v)
	}
	if v, _ := metricValue(sampleMetrics, "xbase_db_pool_connections", `state="total"`); v != 5 {
		t.Fatalf("total = %v", v)
	}
	if _, ok := metricValue(sampleMetrics, "missing", ""); ok {
		t.Fatal("found a missing metric")
	}
	if v, ok := parseCPU(" 143.50% "); !ok || v != 143.5 {
		t.Fatalf("parseCPU = %v", v)
	}
	a := aggregate([]Sample{
		{Healthy: true, CPU: 150, PoolTotal: 5, PoolIdle: 0, InFlight: 2},
		{Healthy: true, CPU: 50, PoolTotal: 5, PoolIdle: 3, InFlight: 1},
		{Healthy: false, CPU: 0},
	}, 2)
	if a.Healthy != 2 || a.Unhealthy != 1 || a.AvgCPU != 50 || a.SatFrac != 0.5 {
		t.Fatalf("aggregate = %+v", a)
	}
}

// ---------------------------------------------------------------- fake docker

type fakeContainer struct {
	id, name string
	running  bool
	health   string
	created  time.Time
	cpu      string
	metrics  string
	version  int
}

// fakeDocker simulates the subset of the docker / docker compose CLI the scaler uses.
type fakeDocker struct {
	mu        sync.Mutex
	seq       int
	version   int // image version a newly created container gets
	byID      map[string]*fakeContainer
	newHealth string // health status new containers report
	calls     []string
	scaleCall []int
}

func newFake(n int) *fakeDocker {
	f := &fakeDocker{byID: map[string]*fakeContainer{}, newHealth: "healthy", version: 1}
	for i := 0; i < n; i++ {
		f.add()
	}
	return f
}

func (f *fakeDocker) add() *fakeContainer {
	f.seq++
	id := fmt.Sprintf("%012d", f.seq)
	c := &fakeContainer{id: id, name: fmt.Sprintf("xbase-api-%d", f.seq), running: true, health: f.newHealth,
		created: time.Unix(int64(f.seq), 0), cpu: "10.00%", metrics: sampleMetrics, version: f.version}
	f.byID[id] = c
	return c
}

func (f *fakeDocker) ids() []string {
	var ids []string
	for id := range f.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (f *fakeDocker) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name == "docker" && len(args) > 0 {
		switch args[0] {
		case "ps":
			return strings.Join(f.ids(), "\n") + "\n", nil
		case "inspect":
			var b strings.Builder
			for _, id := range args[3:] {
				c := f.byID[id]
				state := "exited"
				if c.running {
					state = "running"
				}
				fmt.Fprintf(&b, "%s0000|/%s|%s|%s|%s\n", c.id, c.name, state, c.health, c.created.UTC().Format(time.RFC3339Nano))
			}
			return b.String(), nil
		case "stats":
			var b strings.Builder
			for _, id := range args[4:] {
				fmt.Fprintf(&b, "%s|%s\n", id, f.byID[id].cpu)
			}
			return b.String(), nil
		case "exec":
			c := f.byID[args[1]]
			if c == nil || !c.running {
				return "", fmt.Errorf("not running")
			}
			return c.metrics, nil
		case "stop":
			f.byID[args[3]].running = false
			return "", nil
		case "rm":
			delete(f.byID, args[2])
			return "", nil
		}
	}
	// docker compose ... up -d --no-deps [--no-recreate] --scale svc=N svc
	for i, a := range args {
		if a == "--scale" {
			n, _ := strconv.Atoi(strings.SplitN(args[i+1], "=", 2)[1])
			f.scaleCall = append(f.scaleCall, n)
			running := 0
			for _, c := range f.byID {
				if c.running {
					running++
				}
			}
			for ; running < n; running++ {
				f.add()
			}
			ids := f.ids()
			for j := len(ids) - 1; j >= 0 && running > n; j-- { // compose removes the newest
				if f.byID[ids[j]].running {
					delete(f.byID, ids[j])
					running--
				}
			}
			return "", nil
		}
		if a == "build" {
			f.version++
			return "", nil
		}
	}
	return "", nil
}

func testConfig(t *testing.T) *Config {
	c := &Config{StateDir: t.TempDir(), Services: []ServiceConfig{{Service: "api", Max: 4}}}
	c.applyDefaults()
	return c
}

func TestCollect(t *testing.T) {
	f := newFake(2)
	f.byID["000000000002"].health = "starting"
	d := &Docker{r: f, cfg: testConfig(t)}
	n, samples, err := d.Collect(context.Background(), d.cfg.Services[0])
	if err != nil || n != 2 || len(samples) != 1 {
		t.Fatalf("n=%d samples=%+v err=%v", n, samples, err)
	}
	if s := samples[0]; !s.Healthy || s.CPU != 10 || s.PoolTotal != 5 || s.InFlight != 3 {
		t.Fatalf("sample = %+v", s)
	}
}

func TestDeployReplacesAllReplicas(t *testing.T) {
	f := newFake(2)
	d := &Docker{r: f, cfg: testConfig(t)}
	err := Deploy(context.Background(), d, d.cfg.Services[0], DeployOptions{Build: true}, func(time.Duration) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.byID) != 2 {
		t.Fatalf("want 2 replicas after deploy, have %d", len(f.byID))
	}
	for _, c := range f.byID {
		if c.version != 2 {
			t.Fatalf("old replica survived: %+v", c)
		}
	}
	if f.scaleCall[0] != 4 {
		t.Fatalf("did not surge to 2N: %v", f.scaleCall)
	}
}

func TestDeployRollsBackUnhealthy(t *testing.T) {
	f := newFake(2)
	f.newHealth = "unhealthy"
	d := &Docker{r: f, cfg: testConfig(t)}
	err := Deploy(context.Background(), d, d.cfg.Services[0], DeployOptions{}, func(time.Duration) {})
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("expected rollback, got %v", err)
	}
	if len(f.byID) != 2 || f.byID["000000000001"] == nil || f.byID["000000000002"] == nil {
		t.Fatalf("old replicas not preserved: %v", f.ids())
	}
}

func TestDeployTimesOut(t *testing.T) {
	f := newFake(1)
	f.newHealth = "starting"
	d := &Docker{r: f, cfg: testConfig(t)}
	err := Deploy(context.Background(), d, d.cfg.Services[0], DeployOptions{HealthTimeout: time.Millisecond}, func(time.Duration) { time.Sleep(2 * time.Millisecond) })
	if err == nil || !strings.Contains(err.Error(), "became healthy") {
		t.Fatalf("expected timeout, got %v", err)
	}
	if len(f.byID) != 1 {
		t.Fatalf("new replica not removed: %v", f.ids())
	}
}

func TestTickScalesAndRespectsLock(t *testing.T) {
	f := newFake(1)
	for _, c := range f.byID {
		c.cpu = "95%"
	}
	cfg := testConfig(t)
	cfg.Services[0].UpAfter = 0
	d := &Docker{r: f, cfg: cfg}
	states := map[string]*State{"api": {}}
	now := time.Unix(0, 0)
	opt := loopOptions{Now: func() time.Time { return now }}

	held, _ := TryLock(cfg.StateDir)
	tick(context.Background(), d, cfg, states, opt)
	if len(f.scaleCall) != 0 {
		t.Fatal("scaled while a deploy held the lock")
	}
	held.Unlock()

	tick(context.Background(), d, cfg, states, opt)
	if len(f.scaleCall) != 1 || f.scaleCall[0] != 2 {
		t.Fatalf("expected scale to 2, got %v", f.scaleCall)
	}
	dry := loopOptions{Now: func() time.Time { return now.Add(time.Hour) }, DryRun: true}
	tick(context.Background(), d, cfg, states, dry)
	if len(f.scaleCall) != 1 {
		t.Fatal("dry-run changed replicas")
	}
}

func TestLockExclusive(t *testing.T) {
	dir := t.TempDir()
	a, err := TryLock(dir)
	if err != nil || a == nil {
		t.Fatal("first lock failed", err)
	}
	if b, _ := TryLock(dir); b != nil {
		t.Fatal("second lock succeeded")
	}
	a.Unlock()
	if b, _ := TryLock(dir); b == nil {
		t.Fatal("lock not released")
	} else {
		b.Unlock()
	}
}

// ---------------------------------------------------------------- supavisor + CLI

func TestSupavisorSync(t *testing.T) {
	var got []map[string]any
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/api/tenants/") {
			w.WriteHeader(404)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		json.Unmarshal(b, &m)
		got = append(got, m)
		auth = append(auth, r.Header.Get("Authorization"))
		w.WriteHeader(201)
	}))
	defer srv.Close()
	cfg := testConfig(t)
	cfg.Supavisor.APIURL = srv.URL
	cfg.Capacity = Capacity{PostgresMaxConnections: 100, ReservedConnections: 20, Apps: []CapacityApp{{AppID: "app-1", PoolSize: 10, MaxClients: 50, MaxReplicas: 2, Backend: "go", DBMaxConns: 5}}}
	t.Setenv("API_JWT_SECRET", "s3cret")
	t.Setenv("POSTGRES_PASSWORD", "pw")
	var out bytes.Buffer
	if err := syncSupavisor(context.Background(), cfg, &out, false, srv.Client()); err != nil {
		t.Fatal(err, out.String())
	}
	tenant := got[0]["tenant"].(map[string]any)
	users := tenant["users"].([]any)[0].(map[string]any)
	if tenant["external_id"] != "app-1" || users["pool_size"].(float64) != 10 || users["mode_type"] != "transaction" || users["db_password"] != "pw" {
		t.Fatalf("tenant body: %v", tenant)
	}
	parts := strings.Split(strings.TrimPrefix(auth[0], "Bearer "), ".")
	if len(parts) != 3 {
		t.Fatalf("bad jwt %q", auth[0])
	}
	if hs256("s3cret", time.Unix(0, 0)) == hs256("other", time.Unix(0, 0)) {
		t.Fatal("signature ignores the secret")
	}
	// over budget: refuses to push
	cfg.Capacity.Apps[0].PoolSize = 500
	if err := syncSupavisor(context.Background(), cfg, &out, false, srv.Client()); err == nil {
		t.Fatal("pushed an over-budget plan")
	}
}

func TestCLIPlanExitCode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	os.WriteFile(p, []byte(`{"state_dir":"`+dir+`","capacity":{"postgres_max_connections":20,"reserved_connections":10,"apps":[{"app_id":"a","pool_size":30}]}}`), 0o600)
	var out bytes.Buffer
	err := runCLI(context.Background(), []string{"plan", "-config", p}, &out, &fakeDocker{})
	if ex, ok := err.(exitErr); !ok || ex != 1 {
		t.Fatalf("want exit 1, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "ERROR") {
		t.Fatalf("no error printed: %s", out.String())
	}
	if err := runCLI(context.Background(), []string{"bogus", "-config", p}, &out, &fakeDocker{}); err == nil {
		t.Fatal("unknown command accepted")
	}
}
