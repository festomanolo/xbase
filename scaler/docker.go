package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner executes an external command. The real one shells out; tests substitute a fake.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type execRunner struct{ dir string }

func (e execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = e.dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// Docker drives the docker CLI for one compose project.
type Docker struct {
	r   Runner
	cfg *Config
}

type Replica struct {
	ID      string // 12-char short id
	Name    string
	Running bool
	Health  string // healthy | unhealthy | starting | "" (image defines no HEALTHCHECK)
	Created time.Time
}

func (d *Docker) composeBase() []string {
	args := append([]string{}, d.cfg.ComposeCmd[1:]...)
	args = append(args, "-p", d.cfg.Project)
	for _, f := range d.cfg.ComposeFiles {
		args = append(args, "-f", f)
	}
	if d.cfg.EnvFile != "" {
		args = append(args, "--env-file", d.cfg.EnvFile)
	}
	return args
}

func (d *Docker) compose(ctx context.Context, rest ...string) (string, error) {
	return d.r.Run(ctx, d.cfg.ComposeCmd[0], append(d.composeBase(), rest...)...)
}

// Replicas lists every container (running or not) of a compose service.
func (d *Docker) Replicas(ctx context.Context, service string) ([]Replica, error) {
	out, err := d.r.Run(ctx, d.cfg.DockerBin, "ps", "-aq",
		"--filter", "label=com.docker.compose.project="+d.cfg.Project,
		"--filter", "label=com.docker.compose.service="+service)
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(out)
	if len(ids) == 0 {
		return nil, nil
	}
	args := append([]string{"inspect", "--format",
		`{{.ID}}|{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.Created}}`}, ids...)
	out, err = d.r.Run(ctx, d.cfg.DockerBin, args...)
	if err != nil {
		return nil, err
	}
	var reps []Replica
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.SplitN(line, "|", 5)
		if len(f) != 5 {
			continue
		}
		created, _ := time.Parse(time.RFC3339Nano, f[4])
		reps = append(reps, Replica{
			ID: f[0][:12], Name: strings.TrimPrefix(f[1], "/"),
			Running: f[2] == "running", Health: f[3], Created: created,
		})
	}
	return reps, nil
}

// CPU returns docker's CPU% (of one core) for the given container ids.
func (d *Docker) CPU(ctx context.Context, ids []string) (map[string]float64, error) {
	out := map[string]float64{}
	if len(ids) == 0 {
		return out, nil
	}
	raw, err := d.r.Run(ctx, d.cfg.DockerBin, append([]string{"stats", "--no-stream", "--format", "{{.ID}}|{{.CPUPerc}}"}, ids...)...)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		id, pct, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		if v, ok := parseCPU(pct); ok {
			out[id] = v
		}
	}
	return out, nil
}

// Probe runs `<binary> probe <path>` inside the container (the images carry no curl).
func (d *Docker) Probe(ctx context.Context, id, binary, path string) (string, error) {
	return d.r.Run(ctx, d.cfg.DockerBin, "exec", id, "/usr/local/bin/"+binary, "probe", path)
}

// Scale converges a service to n containers. noRecreate leaves existing containers
// alone even if their config or image changed (new ones use the current config).
func (d *Docker) Scale(ctx context.Context, service string, n int, noRecreate bool) error {
	args := []string{"up", "-d", "--no-deps"}
	if noRecreate {
		args = append(args, "--no-recreate")
	}
	args = append(args, "--scale", fmt.Sprintf("%s=%d", service, n), service)
	_, err := d.compose(ctx, args...)
	return err
}

func (d *Docker) Build(ctx context.Context, service string) error {
	_, err := d.compose(ctx, "build", service)
	return err
}

func (d *Docker) Stop(ctx context.Context, id string, grace time.Duration) error {
	_, err := d.r.Run(ctx, d.cfg.DockerBin, "stop", "-t", fmt.Sprint(int(grace.Seconds())), id)
	return err
}

func (d *Docker) Remove(ctx context.Context, id string) error {
	_, err := d.r.Run(ctx, d.cfg.DockerBin, "rm", "-f", id)
	return err
}

// Collect samples every running, non-starting replica of a service.
func (d *Docker) Collect(ctx context.Context, svc ServiceConfig) (current int, samples []Sample, err error) {
	reps, err := d.Replicas(ctx, svc.Service)
	if err != nil {
		return 0, nil, err
	}
	var live []Replica
	for _, r := range reps {
		if r.Running {
			current++
			if r.Health != "starting" { // still warming up: neither healthy nor failing yet
				live = append(live, r)
			}
		}
	}
	ids := make([]string, len(live))
	for i, r := range live {
		ids[i] = r.ID
	}
	cpu, cpuErr := d.CPU(ctx, ids)
	if cpuErr != nil {
		return current, nil, cpuErr
	}
	for _, r := range live {
		s := Sample{Name: r.Name, CPU: cpu[r.ID]}
		body, perr := d.Probe(ctx, r.ID, svc.Binary, "/metrics")
		if perr == nil && r.Health != "unhealthy" {
			s.Healthy = true
			s.InFlight, _ = metricValue(body, "xbase_http_in_flight", "")
			s.PoolTotal, _ = metricValue(body, "xbase_db_pool_connections", `state="total"`)
			s.PoolIdle, _ = metricValue(body, "xbase_db_pool_connections", `state="idle"`)
		}
		samples = append(samples, s)
	}
	return current, samples, nil
}
