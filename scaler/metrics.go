package main

import (
	"bufio"
	"strconv"
	"strings"
)

// metricValue returns the value of the first sample of `name` whose label set contains
// `labelSubstr` (pass "" for any). It understands the subset of the Prometheus text
// format that both xbase backends emit.
func metricValue(text, name, labelSubstr string) (float64, bool) {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, name) || strings.HasPrefix(line, "#") {
			continue
		}
		rest := line[len(name):]
		if rest == "" || (rest[0] != '{' && rest[0] != ' ') {
			continue // a longer metric name that merely starts with `name`
		}
		labels := ""
		if rest[0] == '{' {
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				continue
			}
			labels, rest = rest[1:end], rest[end+1:]
		}
		if labelSubstr != "" && !strings.Contains(labels, labelSubstr) {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
			return v, true
		}
	}
	return 0, false
}

// parseCPU parses docker's "12.34%" CPUPerc.
func parseCPU(s string) (float64, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil
}

// Sample is what one replica reports.
type Sample struct {
	Name      string
	Healthy   bool
	CPU       float64 // % of one core, as docker reports it
	InFlight  float64
	PoolTotal float64
	PoolIdle  float64
}

// aggregate folds replica samples into the single observation Decide consumes.
func aggregate(samples []Sample, coresPerReplica float64) Aggregate {
	var a Aggregate
	var cpuSum float64
	var sat int
	for _, s := range samples {
		if !s.Healthy {
			a.Unhealthy++
			continue
		}
		a.Healthy++
		cpuSum += s.CPU / coresPerReplica
		if s.PoolTotal > 0 && s.PoolIdle == 0 && s.InFlight > 0 {
			sat++
		}
	}
	if a.Healthy > 0 {
		a.AvgCPU = cpuSum / float64(a.Healthy)
		a.SatFrac = float64(sat) / float64(a.Healthy)
	}
	return a
}
