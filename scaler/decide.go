package main

import (
	"fmt"
	"time"
)

// Aggregate is one observation of a service's healthy replicas.
type Aggregate struct {
	Healthy   int     // replicas that answered their health probe
	Unhealthy int     // replicas that did not
	AvgCPU    float64 // mean CPU, % of the replica's allowance
	SatFrac   float64 // fraction of healthy replicas whose DB pool is fully busy
}

// State is the per-service memory the decision needs between ticks.
type State struct {
	upSince    time.Time // zero when the scale-up condition is not currently true
	downSince  time.Time
	lastAction time.Time
}

type Decision struct {
	Target int
	Reason string
}

// Decide returns the replica count the service should have. It is a pure function of
// its inputs (the clock is passed in) so the whole policy is unit-tested.
//
// Policy:
//   - Scale up when CPU is high OR the DB pools are saturated, continuously for UpAfter.
//   - Scale down only when CPU is low AND no pool is saturated, continuously for
//     DownAfter, and only if the remaining replicas would still sit below the
//     scale-up threshold (otherwise it would bounce straight back up).
//   - Never act twice within Cooldown. Always stay inside [Min, Max].
//   - If the live count is outside [Min, Max] (manual change, crash), correct it first.
//   - A service with no healthy replica is never "scaled down"; it is left to Docker's
//     restart policy, and brought up to Min if replicas are simply missing.
func Decide(cfg ServiceConfig, st *State, now time.Time, current int, a Aggregate) Decision {
	if current < cfg.Min {
		st.lastAction = now
		return Decision{cfg.Min, fmt.Sprintf("below min (%d < %d)", current, cfg.Min)}
	}
	if current > cfg.Max {
		st.lastAction = now
		return Decision{cfg.Max, fmt.Sprintf("above max (%d > %d)", current, cfg.Max)}
	}
	hold := Decision{current, "steady"}
	if a.Healthy == 0 {
		st.upSince, st.downSince = time.Time{}, time.Time{}
		return Decision{current, "no healthy replicas: not scaling on missing data"}
	}

	wantUp := a.AvgCPU >= cfg.CPUUp || a.SatFrac >= cfg.SaturationUp
	wantDown := a.AvgCPU <= cfg.CPUDown && a.SatFrac == 0 && a.Unhealthy == 0 && current > cfg.Min

	if wantDown && current > 1 {
		// would the survivors be overloaded? (load is conserved when a replica is removed)
		projected := a.AvgCPU * float64(current) / float64(current-1)
		if projected >= cfg.CPUUp-10 {
			wantDown = false
		}
	}

	track := func(cond bool, since *time.Time) {
		if !cond {
			*since = time.Time{}
		} else if since.IsZero() {
			*since = now
		}
	}
	track(wantUp, &st.upSince)
	track(wantDown, &st.downSince)

	cooling := !st.lastAction.IsZero() && now.Sub(st.lastAction) < cfg.Cooldown.D()

	switch {
	case wantUp && current < cfg.Max && now.Sub(st.upSince) >= cfg.UpAfter.D():
		if cooling {
			return Decision{current, fmt.Sprintf("scale-up wanted (cpu %.0f%%, sat %.0f%%) but cooling down", a.AvgCPU, a.SatFrac*100)}
		}
		target := min(current+cfg.StepUp, cfg.Max)
		st.lastAction, st.upSince = now, time.Time{}
		return Decision{target, fmt.Sprintf("scale up: cpu %.0f%% (>= %.0f) / pool saturation %.0f%% for %s", a.AvgCPU, cfg.CPUUp, a.SatFrac*100, cfg.UpAfter.D())}
	case wantUp && current >= cfg.Max:
		return Decision{current, fmt.Sprintf("at max (%d) while overloaded: cpu %.0f%%, sat %.0f%%", cfg.Max, a.AvgCPU, a.SatFrac*100)}
	case wantDown && now.Sub(st.downSince) >= cfg.DownAfter.D():
		if cooling {
			return Decision{current, "scale-down wanted but cooling down"}
		}
		st.lastAction, st.downSince = now, time.Time{}
		return Decision{current - 1, fmt.Sprintf("scale down: cpu %.0f%% (<= %.0f) for %s", a.AvgCPU, cfg.CPUDown, cfg.DownAfter.D())}
	}
	return hold
}
