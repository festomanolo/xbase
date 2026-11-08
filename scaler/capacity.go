package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// PlanRow is the capacity picture of one app.
type PlanRow struct {
	App          string
	Replicas     int
	PoolSize     int // server connections Supavisor may hold for this app
	ClientDemand int // replicas x per-replica pool: connections the app may open to Supavisor
	MaxClients   int
	Oversub      float64 // client connections per server connection
	Direct       int     // session connections that bypass Supavisor (LISTEN)
}

type PlanResult struct {
	Rows      []PlanRow
	Budget    int // postgres max_connections minus what Supabase's own services reserve
	PoolTotal int
	Direct    int
	Used      int
	Errors    []string
	Warnings  []string
}

func (p PlanResult) OK() bool { return len(p.Errors) == 0 }

// Plan checks that the worst case (every app at max replicas, every server pool full)
// fits inside Postgres' connection limit. Transaction-mode pooling means client
// connections do not map 1:1 to server connections, so the binding constraint is the
// sum of pool sizes plus the direct (LISTEN) sessions that bypass Supavisor.
func Plan(c Capacity) PlanResult {
	var p PlanResult
	p.Budget = c.PostgresMaxConnections - c.ReservedConnections
	for _, a := range c.Apps {
		direct := a.MaxReplicas // go: one LISTEN connection per replica
		if a.Backend == "rust" {
			direct = 2 * a.MaxReplicas // change feed + cluster channel
		}
		row := PlanRow{
			App: a.AppID, Replicas: a.MaxReplicas, PoolSize: a.PoolSize,
			ClientDemand: a.MaxReplicas * a.DBMaxConns, MaxClients: a.MaxClients, Direct: direct,
		}
		if a.PoolSize > 0 {
			row.Oversub = float64(row.ClientDemand) / float64(a.PoolSize)
		}
		p.Rows = append(p.Rows, row)
		p.PoolTotal += a.PoolSize
		p.Direct += direct

		switch {
		case a.PoolSize < 1:
			p.Errors = append(p.Errors, fmt.Sprintf("%s: pool_size must be >= 1", a.AppID))
		case a.PoolSize < a.MaxReplicas:
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s: pool_size %d is smaller than max_replicas %d; replicas will queue behind each other", a.AppID, a.PoolSize, a.MaxReplicas))
		}
		if a.MaxClients > 0 && row.ClientDemand > a.MaxClients {
			p.Errors = append(p.Errors, fmt.Sprintf("%s: %d replicas x %d connections = %d client connections, but Supavisor max_clients is %d (new connections would be refused)",
				a.AppID, a.MaxReplicas, a.DBMaxConns, row.ClientDemand, a.MaxClients))
		}
		if row.Oversub > 6 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s: %.1f client connections per server connection; bursts will queue (raise pool_size or lower db_max_connections)", a.AppID, row.Oversub))
		}
	}
	p.Direct++ // one transient session for migrations at boot
	p.Used = p.PoolTotal + p.Direct
	if p.Used > p.Budget {
		p.Errors = append(p.Errors, fmt.Sprintf("worst case needs %d Postgres connections (pools %d + direct %d) but only %d are available (max_connections %d - reserved %d)",
			p.Used, p.PoolTotal, p.Direct, p.Budget, c.PostgresMaxConnections, c.ReservedConnections))
	}
	return p
}

// Suggest rescales pool sizes proportionally so the worst case fits the budget.
func Suggest(c Capacity, p PlanResult) map[string]int {
	room := p.Budget - p.Direct
	if room < len(c.Apps) || p.PoolTotal == 0 {
		return nil
	}
	out := map[string]int{}
	for _, a := range c.Apps {
		out[a.AppID] = max(1, a.PoolSize*room/p.PoolTotal)
	}
	return out
}

func (p PlanResult) Print(w io.Writer, c Capacity) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "APP\tMAX REPLICAS\tPOOL SIZE\tCLIENT CONNS\tMAX CLIENTS\tCLIENTS/SERVER\tDIRECT")
	for _, r := range p.Rows {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%.1f\t%d\n", r.App, r.Replicas, r.PoolSize, r.ClientDemand, r.MaxClients, r.Oversub, r.Direct)
	}
	tw.Flush()
	fmt.Fprintf(w, "\nPostgres budget: %d = max_connections %d - reserved %d\n", p.Budget, c.PostgresMaxConnections, c.ReservedConnections)
	fmt.Fprintf(w, "Worst case:      %d = pools %d + direct sessions %d\n", p.Used, p.PoolTotal, p.Direct)
	for _, e := range p.Errors {
		fmt.Fprintln(w, "ERROR:  "+e)
	}
	for _, x := range p.Warnings {
		fmt.Fprintln(w, "WARN:   "+x)
	}
	if !p.OK() {
		if s := Suggest(c, p); s != nil {
			var parts []string
			for _, a := range c.Apps {
				parts = append(parts, fmt.Sprintf("%s=%d", a.AppID, s[a.AppID]))
			}
			fmt.Fprintf(w, "SUGGEST pool sizes that fit: %s (or raise Postgres max_connections)\n", strings.Join(parts, ", "))
		}
	} else {
		fmt.Fprintf(w, "OK: %d connections of headroom\n", p.Budget-p.Used)
	}
}
