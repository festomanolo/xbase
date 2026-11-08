// Command xbase-scaler autoscales and rolls out xbase backends running under Docker Compose.
//
//	xbase-scaler run      [-config scaler.json] [-once] [-dry-run]  autoscale loop
//	xbase-scaler deploy   [-config scaler.json] [-build] <service>  zero-downtime rolling replace
//	xbase-scaler status   [-config scaler.json]                     live replicas, CPU, pool use, decision
//	xbase-scaler plan     [-config scaler.json]                     Postgres connection budget check (exit 1 if it does not fit)
//	xbase-scaler supavisor [-config scaler.json] [-dry-run]         create/update one Supavisor tenant per app with its pool size
//
// `run` and `deploy` share a file lock, so a deploy is never disturbed by a scaling action.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := runCLI(context.Background(), os.Args[1:], os.Stdout, execRunner{}); err != nil {
		var ex exitErr
		if errors.As(err, &ex) {
			os.Exit(int(ex))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// exitErr is a non-zero exit that has already been explained on stdout.
type exitErr int

func (e exitErr) Error() string { return fmt.Sprintf("exit %d", int(e)) }

const usage = `usage: xbase-scaler <run|deploy|status|plan|supavisor> [flags]

  run        autoscale every configured service (flags: -once, -dry-run)
  deploy     rolling, health-gated replacement of one service (flags: -build)
  status     show replicas, CPU, pool use and what the autoscaler would do
  plan       check that max replicas x pools fit Postgres max_connections
  supavisor  upsert one Supavisor tenant per capacity app with its pool size (flags: -dry-run)

common flags: -config PATH (default $XBASE_SCALER_CONFIG or ./scaler.json)`

func runCLI(ctx context.Context, args []string, out io.Writer, r Runner) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintln(out, usage)
		if len(args) == 0 {
			return exitErr(2)
		}
		return nil
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(out)
	defCfg := os.Getenv("XBASE_SCALER_CONFIG")
	if defCfg == "" {
		defCfg = "scaler.json"
	}
	cfgPath := fs.String("config", defCfg, "path to the scaler JSON config")
	once := fs.Bool("once", false, "run: one tick, then exit")
	dry := fs.Bool("dry-run", false, "run/supavisor: decide and print, change nothing")
	build := fs.Bool("build", false, "deploy: build the image before rolling it out")
	healthTimeout := fs.Duration("health-timeout", 0, "deploy: how long new replicas get to become healthy (default 3m)")
	if err := fs.Parse(rest); err != nil {
		return exitErr(2)
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if rr, ok := r.(execRunner); ok && rr.dir == "" {
		r = execRunner{dir: cfg.WorkDir}
	}
	d := &Docker{r: r, cfg: cfg}

	switch cmd {
	case "plan":
		p := Plan(cfg.Capacity)
		p.Print(out, cfg.Capacity)
		if !p.OK() {
			return exitErr(1)
		}
		return nil
	case "status":
		return status(ctx, d, cfg, out)
	case "run":
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runLoop(ctx, d, cfg, loopOptions{Once: *once, DryRun: *dry})
	case "deploy":
		if fs.NArg() != 1 {
			return fmt.Errorf("deploy needs exactly one service name")
		}
		svc, ok := cfg.service(fs.Arg(0))
		if !ok {
			return fmt.Errorf("service %q is not in %s", fs.Arg(0), *cfgPath)
		}
		lock, err := waitLock(ctx, cfg.StateDir, 2*time.Minute)
		if err != nil {
			return err
		}
		defer lock.Unlock()
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		return Deploy(ctx, d, svc, DeployOptions{Build: *build, HealthTimeout: *healthTimeout}, nil)
	case "supavisor":
		return syncSupavisor(ctx, cfg, out, *dry, nil)
	}
	fmt.Fprintln(out, usage)
	return exitErr(2)
}

func (c *Config) service(name string) (ServiceConfig, bool) {
	for _, s := range c.Services {
		if s.Service == name {
			return s, true
		}
	}
	return ServiceConfig{}, false
}

// waitLock blocks until the shared lock is free (a scaling tick finishes in seconds).
func waitLock(ctx context.Context, dir string, max time.Duration) (*Lock, error) {
	deadline := time.Now().Add(max)
	for {
		l, err := TryLock(dir)
		if err != nil || l != nil {
			return l, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("another xbase-scaler deploy holds %s/xbase-scaler.lock", dir)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

type loopOptions struct {
	Once   bool
	DryRun bool
	Now    func() time.Time // tests
}

// runLoop ticks every cfg.Interval. A tick that cannot take the lock (a deploy is in
// progress) is skipped and the per-service timers are reset, so a deploy's temporary
// 2N replicas never count as a reason to scale.
func runLoop(ctx context.Context, d *Docker, cfg *Config, opt loopOptions) error {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	states := map[string]*State{}
	for _, s := range cfg.Services {
		states[s.Service] = &State{}
	}
	slog.Info("autoscaler started", "services", len(cfg.Services), "interval", cfg.Interval.D(), "dry_run", opt.DryRun)
	t := time.NewTicker(cfg.Interval.D())
	defer t.Stop()
	for {
		tick(ctx, d, cfg, states, opt)
		if opt.Once {
			return nil
		}
		select {
		case <-ctx.Done():
			slog.Info("autoscaler stopping")
			return nil
		case <-t.C:
		}
	}
}

func tick(ctx context.Context, d *Docker, cfg *Config, states map[string]*State, opt loopOptions) {
	lock, err := TryLock(cfg.StateDir)
	if err != nil {
		slog.Error("lock", "error", err)
		return
	}
	if lock == nil {
		slog.Info("deploy in progress; skipping tick")
		for _, st := range states {
			st.upSince, st.downSince = time.Time{}, time.Time{}
		}
		return
	}
	defer lock.Unlock()

	for _, svc := range cfg.Services {
		tctx, cancel := context.WithTimeout(ctx, cfg.Interval.D()+30*time.Second)
		current, samples, err := d.Collect(tctx, svc)
		if err != nil {
			cancel()
			slog.Error("collect failed; not scaling", "service", svc.Service, "error", err)
			continue
		}
		agg := aggregate(samples, svc.CoresPerReplica)
		dec := Decide(svc, states[svc.Service], opt.Now(), current, agg)
		if dec.Target == current {
			slog.Debug("hold", "service", svc.Service, "replicas", current, "reason", dec.Reason)
			cancel()
			continue
		}
		slog.Info("scaling", "service", svc.Service, "from", current, "to", dec.Target, "reason", dec.Reason, "dry_run", opt.DryRun)
		if !opt.DryRun {
			if err := d.Scale(tctx, svc.Service, dec.Target, true); err != nil {
				slog.Error("scale failed", "service", svc.Service, "error", err)
			}
		}
		cancel()
	}
}

func status(ctx context.Context, d *Docker, cfg *Config, out io.Writer) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tREPLICAS\tHEALTHY\tAVG CPU\tPOOL SATURATED\tMIN-MAX\tWOULD DO")
	for _, svc := range cfg.Services {
		current, samples, err := d.Collect(ctx, svc)
		if err != nil {
			fmt.Fprintf(tw, "%s\t?\t?\t?\t?\t%d-%d\terror: %v\n", svc.Service, svc.Min, svc.Max, err)
			continue
		}
		a := aggregate(samples, svc.CoresPerReplica)
		// a fresh State: report what the thresholds say right now, ignoring the hold timers
		probe := svc
		probe.UpAfter, probe.DownAfter = 0, 0
		dec := Decide(probe, &State{}, time.Now(), current, a)
		fmt.Fprintf(tw, "%s\t%d\t%d\t%.0f%%\t%.0f%%\t%d-%d\t%s\n", svc.Service, current, a.Healthy, a.AvgCPU, a.SatFrac*100, svc.Min, svc.Max, dec.Reason)
	}
	return tw.Flush()
}
