package health

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"flux.local/flux/internal/spec"
)

type Status string

const (
	StatusUnknown   Status = "unknown"
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
)

type Report struct {
	NodeID          string
	Generation      uint64
	PoolID          string
	BackendID       string
	ResourceVersion uint64
	Status          Status
	Latency         time.Duration
	Error           string
	ObservedAt      time.Time
}

type ProbeFunc func(context.Context, spec.HealthCheckSpec) (time.Duration, error)

type probeKey struct {
	poolID    string
	backendID string
}

type probeState struct {
	lastAttempt        time.Time
	status             Status
	consecutiveSuccess uint8
	consecutiveFailure uint8
	resourceVersion    uint64
}

type Engine struct {
	probe       ProbeFunc
	concurrency int
	mu          sync.Mutex
	states      map[probeKey]probeState
}

func New(probe ProbeFunc, concurrency int) *Engine {
	if probe == nil {
		probe = TCPConnectProbe
	}
	if concurrency < 1 {
		concurrency = 32
	}
	return &Engine{probe: probe, concurrency: concurrency, states: make(map[probeKey]probeState)}
}

// RunDue executes only probes whose interval has elapsed. Hysteresis is kept
// node-locally, while every completed attempt is reported so Controller can
// detect stale observations after an Agent or network outage.
func (e *Engine) RunDue(ctx context.Context, desired spec.DesiredState, now time.Time) []Report {
	now = now.UTC()
	e.mu.Lock()
	active := make(map[probeKey]struct{}, len(desired.HealthChecks))
	due := make([]spec.HealthCheckSpec, 0, len(desired.HealthChecks))
	for _, check := range desired.HealthChecks {
		key := probeKey{poolID: check.PoolID, backendID: check.BackendID}
		active[key] = struct{}{}
		state := e.states[key]
		if state.resourceVersion != check.ResourceVersion {
			state = probeState{resourceVersion: check.ResourceVersion}
			e.states[key] = state
		}
		if state.lastAttempt.IsZero() || !now.Before(state.lastAttempt.Add(time.Duration(check.IntervalSeconds)*time.Second)) {
			due = append(due, check)
		}
	}
	for key := range e.states {
		if _, exists := active[key]; !exists {
			delete(e.states, key)
		}
	}
	e.mu.Unlock()

	type outcome struct {
		check   spec.HealthCheckSpec
		latency time.Duration
		err     error
	}
	results := make(chan outcome, len(due))
	semaphore := make(chan struct{}, e.concurrency)
	var group sync.WaitGroup
	for _, check := range due {
		check := check
		group.Add(1)
		go func() {
			defer group.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				results <- outcome{check: check, err: ctx.Err()}
				return
			}
			defer func() { <-semaphore }()
			probeContext, cancel := context.WithTimeout(ctx, time.Duration(check.TimeoutMilliseconds)*time.Millisecond)
			latency, err := e.probe(probeContext, check)
			cancel()
			results <- outcome{check: check, latency: latency, err: err}
		}()
	}
	group.Wait()
	close(results)

	reports := make([]Report, 0, len(due))
	e.mu.Lock()
	defer e.mu.Unlock()
	for result := range results {
		key := probeKey{poolID: result.check.PoolID, backendID: result.check.BackendID}
		state := e.states[key]
		state.resourceVersion = result.check.ResourceVersion
		state.lastAttempt = now
		if result.err == nil {
			state.consecutiveFailure = 0
			if state.consecutiveSuccess < result.check.SuccessThreshold {
				state.consecutiveSuccess++
			}
			if state.consecutiveSuccess >= result.check.SuccessThreshold {
				state.status = StatusHealthy
			}
		} else {
			state.consecutiveSuccess = 0
			if state.consecutiveFailure < result.check.FailureThreshold {
				state.consecutiveFailure++
			}
			if state.consecutiveFailure >= result.check.FailureThreshold {
				state.status = StatusUnhealthy
			}
		}
		if state.status == "" {
			state.status = StatusUnknown
		}
		e.states[key] = state
		report := Report{
			NodeID: desired.NodeID, Generation: desired.Generation,
			PoolID: result.check.PoolID, BackendID: result.check.BackendID,
			ResourceVersion: result.check.ResourceVersion, Status: state.status,
			Latency: result.latency, ObservedAt: now,
		}
		if result.err != nil {
			report.Error = truncate(result.err.Error(), 512)
		}
		reports = append(reports, report)
	}
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].PoolID == reports[j].PoolID {
			return reports[i].BackendID < reports[j].BackendID
		}
		return reports[i].PoolID < reports[j].PoolID
	})
	return reports
}

func TCPConnectProbe(ctx context.Context, check spec.HealthCheckSpec) (time.Duration, error) {
	if check.Protocol != spec.ProtocolTCP {
		return 0, fmt.Errorf("unsupported health protocol %q", check.Protocol)
	}
	started := time.Now()
	dialer := net.Dialer{}
	address := net.JoinHostPort(check.Endpoint.Address.String(), strconv.Itoa(int(check.Endpoint.Port)))
	connection, err := dialer.DialContext(ctx, "tcp", address)
	latency := time.Since(started)
	if err != nil {
		return latency, err
	}
	if err := connection.Close(); err != nil {
		return latency, fmt.Errorf("close health connection: %w", err)
	}
	return latency, nil
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
