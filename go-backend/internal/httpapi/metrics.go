package httpapi

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// metrics are Prometheus counters mirroring the Rust backend's /metrics names.
type metrics struct {
	req1xx, req2xx, req3xx, req4xx, req5xx atomic.Uint64
	inFlight                               atomic.Int64
	latencyMicros                          atomic.Uint64
	rateLimited                            atomic.Uint64
	rateLimitFallbacks                     atomic.Uint64
}

func (m *metrics) track(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.inFlight.Add(1)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		m.inFlight.Add(-1)
		m.latencyMicros.Add(uint64(time.Since(start).Microseconds()))
		switch {
		case rec.status < 200:
			m.req1xx.Add(1) // WebSocket upgrades (101)
		case rec.status < 300:
			m.req2xx.Add(1)
		case rec.status < 400:
			m.req3xx.Add(1)
		case rec.status < 500:
			m.req4xx.Add(1)
		default:
			m.req5xx.Add(1)
		}
	})
}

func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if want := s.cfg.MetricsToken; want != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid metrics token")
			return
		}
	}
	m, app := s.metrics, s.cfg.AppID
	total := m.req1xx.Load() + m.req2xx.Load() + m.req3xx.Load() + m.req4xx.Load() + m.req5xx.Load()
	st := s.pool.Stat()
	conns, rooms := s.hub.stats()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	fmt.Fprintf(&b, "# TYPE xbase_http_requests_total counter\n")
	for class, v := range map[string]uint64{"1xx": m.req1xx.Load(), "2xx": m.req2xx.Load(), "3xx": m.req3xx.Load(), "4xx": m.req4xx.Load(), "5xx": m.req5xx.Load()} {
		fmt.Fprintf(&b, "xbase_http_requests_total{app=%q,class=%q} %d\n", app, class, v)
	}
	fmt.Fprintf(&b, "# TYPE xbase_http_request_duration_seconds summary\n")
	fmt.Fprintf(&b, "xbase_http_request_duration_seconds_sum{app=%q} %f\n", app, float64(m.latencyMicros.Load())/1e6)
	fmt.Fprintf(&b, "xbase_http_request_duration_seconds_count{app=%q} %d\n", app, total)
	fmt.Fprintf(&b, "# TYPE xbase_http_in_flight gauge\nxbase_http_in_flight{app=%q} %d\n", app, m.inFlight.Load())
	fmt.Fprintf(&b, "# TYPE xbase_rate_limited_total counter\nxbase_rate_limited_total{app=%q} %d\n", app, m.rateLimited.Load())
	fmt.Fprintf(&b, "# TYPE xbase_rate_limit_fallbacks_total counter\nxbase_rate_limit_fallbacks_total{app=%q} %d\n", app, m.rateLimitFallbacks.Load())
	fmt.Fprintf(&b, "# TYPE xbase_ws_connections gauge\nxbase_ws_connections{app=%q} %d\n", app, conns)
	fmt.Fprintf(&b, "# TYPE xbase_ws_rooms gauge\nxbase_ws_rooms{app=%q} %d\n", app, rooms)
	fmt.Fprintf(&b, "# TYPE xbase_realtime_cluster_messages_total counter\n")
	pub, recv, drop := s.hub.clusterCounters()
	fmt.Fprintf(&b, "xbase_realtime_cluster_messages_total{app=%q,direction=\"published\"} %d\n", app, pub)
	fmt.Fprintf(&b, "xbase_realtime_cluster_messages_total{app=%q,direction=\"received\"} %d\n", app, recv)
	fmt.Fprintf(&b, "xbase_realtime_cluster_messages_total{app=%q,direction=\"dropped\"} %d\n", app, drop)
	fmt.Fprintf(&b, "# TYPE xbase_db_pool_connections gauge\n")
	fmt.Fprintf(&b, "xbase_db_pool_connections{app=%q,state=\"total\"} %d\n", app, st.TotalConns())
	fmt.Fprintf(&b, "xbase_db_pool_connections{app=%q,state=\"idle\"} %d\n", app, st.IdleConns())
	_, _ = w.Write([]byte(b.String()))
}
