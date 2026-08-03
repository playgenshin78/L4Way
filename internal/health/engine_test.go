package health

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"flux.local/flux/internal/spec"
)

func TestEngineAppliesHysteresisAndIntervals(t *testing.T) {
	var mu sync.Mutex
	fail := true
	engine := New(func(context.Context, spec.HealthCheckSpec) (time.Duration, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return 5 * time.Millisecond, errors.New("refused")
		}
		return 3 * time.Millisecond, nil
	}, 2)
	desired := spec.DesiredState{NodeID: "node-a", Generation: 7, HealthChecks: []spec.HealthCheckSpec{{
		PoolID: "pool-a", BackendID: "backend-a", Endpoint: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
		Protocol: spec.ProtocolTCP, IntervalSeconds: 2, TimeoutMilliseconds: 500,
		FailureThreshold: 2, SuccessThreshold: 2, ResourceVersion: 9,
	}}}
	now := time.Unix(1_900_000_000, 0)
	first := engine.RunDue(context.Background(), desired, now)
	if len(first) != 1 || first[0].Status != StatusUnknown || first[0].Error == "" {
		t.Fatalf("unexpected first report: %#v", first)
	}
	if got := engine.RunDue(context.Background(), desired, now.Add(time.Second)); len(got) != 0 {
		t.Fatalf("probe ran before its interval: %#v", got)
	}
	second := engine.RunDue(context.Background(), desired, now.Add(2*time.Second))
	if len(second) != 1 || second[0].Status != StatusUnhealthy {
		t.Fatalf("failure threshold was not applied: %#v", second)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	third := engine.RunDue(context.Background(), desired, now.Add(4*time.Second))
	fourth := engine.RunDue(context.Background(), desired, now.Add(6*time.Second))
	if third[0].Status != StatusUnhealthy || fourth[0].Status != StatusHealthy {
		t.Fatalf("success threshold was not applied: third=%#v fourth=%#v", third, fourth)
	}
	if fourth[0].NodeID != "node-a" || fourth[0].Generation != 7 || fourth[0].ResourceVersion != 9 {
		t.Fatalf("report identity was lost: %#v", fourth[0])
	}
}

func TestEngineDropsRemovedProbeState(t *testing.T) {
	engine := New(func(context.Context, spec.HealthCheckSpec) (time.Duration, error) { return 0, errors.New("down") }, 1)
	desired := spec.DesiredState{NodeID: "node-a", Generation: 1, HealthChecks: []spec.HealthCheckSpec{{
		PoolID: "pool-a", BackendID: "backend-a", Protocol: spec.ProtocolTCP,
		IntervalSeconds: 1, TimeoutMilliseconds: 100, FailureThreshold: 1, SuccessThreshold: 1,
	}}}
	now := time.Unix(1_900_000_000, 0)
	if got := engine.RunDue(context.Background(), desired, now); got[0].Status != StatusUnhealthy {
		t.Fatalf("unexpected report: %#v", got)
	}
	desired.HealthChecks = nil
	engine.RunDue(context.Background(), desired, now.Add(time.Second))
	desired.HealthChecks = []spec.HealthCheckSpec{{
		PoolID: "pool-a", BackendID: "backend-a", Protocol: spec.ProtocolTCP,
		IntervalSeconds: 1, TimeoutMilliseconds: 100, FailureThreshold: 2, SuccessThreshold: 1,
	}}
	if got := engine.RunDue(context.Background(), desired, now.Add(2*time.Second)); got[0].Status != StatusUnknown {
		t.Fatalf("removed probe retained hysteresis state: %#v", got)
	}
}
