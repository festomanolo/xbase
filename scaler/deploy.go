package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

type DeployOptions struct {
	Build         bool
	HealthTimeout time.Duration // how long new replicas get to become healthy
	DrainDelay    time.Duration // after they are healthy, let the proxy discover them before stopping the old ones
	StopGrace     time.Duration // SIGTERM -> SIGKILL window while an old replica drains
	Pause         time.Duration // between stopping consecutive old replicas
	Poll          time.Duration
}

func (o *DeployOptions) defaults() {
	if o.HealthTimeout == 0 {
		o.HealthTimeout = 3 * time.Minute
	}
	if o.DrainDelay == 0 {
		o.DrainDelay = 10 * time.Second
	}
	if o.StopGrace == 0 {
		o.StopGrace = 30 * time.Second
	}
	if o.Poll == 0 {
		o.Poll = 2 * time.Second
	}
}

// Deploy replaces every replica of a service without dropping capacity:
//
//  1. start N new replicas next to the N running ones (using the freshly built image),
//  2. wait until all of them pass their health check — if any does not, remove them and
//     abort, leaving the old replicas serving untouched,
//  3. give the proxy time to discover them, then drain and remove the old replicas one
//     at a time (SIGTERM; the backends finish in-flight requests before exiting).
//
// Capacity never falls below N, and a bad release is rolled back automatically.
func Deploy(ctx context.Context, d *Docker, svc ServiceConfig, opt DeployOptions, sleep func(time.Duration)) error {
	opt.defaults()
	if sleep == nil {
		sleep = time.Sleep
	}
	old, err := runningReplicas(ctx, d, svc.Service)
	if err != nil {
		return err
	}
	if len(old) == 0 {
		slog.Info("no running replicas; starting the minimum", "service", svc.Service, "n", svc.Min)
		return d.Scale(ctx, svc.Service, svc.Min, false)
	}
	n := len(old)
	oldIDs := map[string]bool{}
	for _, r := range old {
		oldIDs[r.ID] = true
	}

	if opt.Build {
		slog.Info("building image", "service", svc.Service)
		if err := d.Build(ctx, svc.Service); err != nil {
			return fmt.Errorf("build failed, nothing changed: %w", err)
		}
	}

	slog.Info("starting new replicas alongside the old ones", "service", svc.Service, "old", n, "new", n)
	if err := d.Scale(ctx, svc.Service, 2*n, true); err != nil {
		return fmt.Errorf("could not start new replicas: %w", err)
	}
	fresh, err := newReplicas(ctx, d, svc.Service, oldIDs)
	if err != nil {
		return err
	}

	rollback := func(cause error) error {
		slog.Error("rolling back: removing the new replicas", "cause", cause)
		for _, r := range fresh {
			_ = d.Stop(ctx, r.ID, 5*time.Second)
			_ = d.Remove(ctx, r.ID)
		}
		return fmt.Errorf("deploy aborted, old replicas still serving: %w", cause)
	}

	deadline := time.Now().Add(opt.HealthTimeout)
	for {
		fresh, err = newReplicas(ctx, d, svc.Service, oldIDs)
		if err != nil {
			return rollback(err)
		}
		ready, bad := 0, 0
		for _, r := range fresh {
			switch {
			case !r.Running:
				bad++
			case r.Health == "healthy" || (r.Health == "" && probeOK(ctx, d, svc, r.ID)):
				ready++
			case r.Health == "unhealthy":
				bad++
			}
		}
		if bad > 0 {
			return rollback(fmt.Errorf("%d new replica(s) crashed or reported unhealthy", bad))
		}
		if ready >= n && len(fresh) >= n {
			break
		}
		if time.Now().After(deadline) {
			return rollback(fmt.Errorf("only %d/%d new replicas became healthy within %s", ready, n, opt.HealthTimeout))
		}
		sleep(opt.Poll)
	}
	slog.Info("new replicas healthy", "service", svc.Service, "n", len(fresh))

	sleep(opt.DrainDelay)
	for i, r := range old {
		slog.Info("draining old replica", "container", r.Name, "n", fmt.Sprintf("%d/%d", i+1, n))
		if err := d.Stop(ctx, r.ID, opt.StopGrace); err != nil {
			slog.Warn("stop failed", "container", r.Name, "error", err)
		}
		if err := d.Remove(ctx, r.ID); err != nil {
			slog.Warn("remove failed", "container", r.Name, "error", err)
		}
		if i < n-1 {
			sleep(opt.Pause)
		}
	}
	slog.Info("deploy complete", "service", svc.Service, "replicas", len(fresh))
	return nil
}

func runningReplicas(ctx context.Context, d *Docker, service string) ([]Replica, error) {
	all, err := d.Replicas(ctx, service)
	if err != nil {
		return nil, err
	}
	var out []Replica
	for _, r := range all {
		if r.Running {
			out = append(out, r)
		}
	}
	// oldest first: they are drained in that order
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Created.Before(out[j-1].Created); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

func newReplicas(ctx context.Context, d *Docker, service string, old map[string]bool) ([]Replica, error) {
	all, err := d.Replicas(ctx, service)
	if err != nil {
		return nil, err
	}
	var out []Replica
	for _, r := range all {
		if !old[r.ID] {
			out = append(out, r)
		}
	}
	return out, nil
}

func probeOK(ctx context.Context, d *Docker, svc ServiceConfig, id string) bool {
	_, err := d.Probe(ctx, id, svc.Binary, "/health")
	return err == nil
}
