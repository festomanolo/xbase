// xbase Go backend: a lean net/http + pgx service sharing the Rust backend's
// conventions (Supavisor pooling, local JWT verification, RLS impersonation,
// hashed API keys, token-bucket rate limiting). Use it as the template for
// SaaS backends you prefer to write in Go.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/festomanolo/xbase/go-backend/internal/config"
	"github.com/festomanolo/xbase/go-backend/internal/db"
	"github.com/festomanolo/xbase/go-backend/internal/httpapi"
	"github.com/festomanolo/xbase/go-backend/internal/ratelimit"
)

func main() {
	// Operator subcommands (the distroless image has no curl): handled before any
	// configuration is loaded, so they never need DATABASE_URL.
	//   xbase-go-backend healthcheck     exit 0 iff GET /health is 200
	//   xbase-go-backend probe [/path]   print the response body (default /metrics), exit 0 iff 200
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			code, _, err := localGet("/health")
			os.Exit(exitCode(code, err, 200))
		case "probe":
			path := "/metrics"
			if len(os.Args) > 2 {
				path = os.Args[2]
			}
			code, body, err := localGet(path)
			fmt.Print(body)
			os.Exit(exitCode(code, err, 200))
		}
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL, cfg.DBMaxConnections)
	if err != nil {
		return err
	}
	defer pool.Close()

	limiter := ratelimit.New(cfg.RateLimitPerSecond, cfg.RateLimitBurst)
	api := httpapi.New(cfg, pool, limiter)
	api.StartBackground(ctx) // realtime listener, cluster fan-out, rate-limit sweeps

	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting xbase Go backend (Supavisor pooled mode)", "app_id", cfg.AppID, "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	slog.Info("shutdown signal received, draining connections")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
