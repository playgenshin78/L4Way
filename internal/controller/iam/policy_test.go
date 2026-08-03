package iam

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"flux.local/flux/internal/spec"
)

func TestPolicyAuthorizeForward(t *testing.T) {
	now := time.Now().UTC()
	tenantExpiry := now.Add(24 * time.Hour)
	forwardExpiry := now.Add(12 * time.Hour)
	policy := Policy{
		TenantID: "tenant-a", AllowedIngressNodes: []string{"node-a"}, AllowedExitNodes: []string{"node-b"},
		AllowedListenIPs: []string{"198.51.100.10"}, AllowedPortRanges: []PortRange{{Start: 10000, End: 20000}},
		AllowedProtocols: []spec.Protocol{spec.ProtocolTCP, spec.ProtocolUDP}, AllowViaExit: true, MaxForwards: 3,
		IngressRateLimitBPS: 10_000_000, EgressRateLimitBPS: 20_000_000, TrafficQuotaBytes: 1_000_000_000,
		AllowedTargetCIDRs: []string{"10.0.0.0/8", "203.0.113.0/24"}, DeniedTargetCIDRs: []string{"10.1.0.0/16"}, ResourceVersion: 1,
	}
	forward := spec.ForwardSpec{
		ID: "forward-a", UserID: "tenant-a", Protocols: []spec.Protocol{spec.ProtocolTCP}, IngressNodeID: "node-a",
		ExitNodeID: "node-b", Listen: spec.Endpoint{Address: netip.MustParseAddr("198.51.100.10"), Port: 12000},
		Target: spec.Endpoint{Address: netip.MustParseAddr("10.2.0.10"), Port: 443}, PathMode: spec.PathViaExit,
		RateLimit:    &spec.RateLimitSpec{IngressBitsPerSecond: 5_000_000, EgressBitsPerSecond: 10_000_000, BurstBytes: 64 * 1024},
		TrafficQuota: &spec.TrafficQuotaSpec{Bytes: 500_000_000, Policy: spec.QuotaPolicyPause}, ExpiresAt: &forwardExpiry,
		Lifecycle: spec.LifecycleActive, ResourceVersion: 1,
	}
	if err := policy.AuthorizeForward(forward, 1, &tenantExpiry, now); err != nil {
		t.Fatalf("authorize valid forward: %v", err)
	}
	withoutChildLimits := forward
	withoutChildLimits.RateLimit = nil
	withoutChildLimits.TrafficQuota = nil
	if err := policy.AuthorizeForward(withoutChildLimits, 1, &tenantExpiry, now); err != nil {
		t.Fatalf("tenant-wide limits must not require duplicate per-forward limits: %v", err)
	}
	dataPlanePolicy, err := policy.DataPlanePolicy()
	if err != nil {
		t.Fatal(err)
	}
	if dataPlanePolicy == nil || dataPlanePolicy.UserID != policy.TenantID ||
		dataPlanePolicy.RateLimit == nil || dataPlanePolicy.RateLimit.IngressBitsPerSecond != policy.IngressRateLimitBPS ||
		dataPlanePolicy.RateLimit.EgressBitsPerSecond != policy.EgressRateLimitBPS ||
		dataPlanePolicy.TrafficQuota == nil || dataPlanePolicy.TrafficQuota.Bytes != policy.TrafficQuotaBytes ||
		dataPlanePolicy.ResourceVersion != policy.ResourceVersion {
		t.Fatalf("data-plane policy = %+v", dataPlanePolicy)
	}

	tests := []struct {
		name   string
		mutate func(*spec.ForwardSpec)
		count  uint32
	}{
		{"wrong owner", func(value *spec.ForwardSpec) { value.UserID = "tenant-b" }, 1},
		{"wrong ingress", func(value *spec.ForwardSpec) { value.IngressNodeID = "node-c" }, 1},
		{"wrong port", func(value *spec.ForwardSpec) { value.Listen.Port = 80 }, 1},
		{"protected target", func(value *spec.ForwardSpec) { value.Target.Address = netip.MustParseAddr("169.254.169.254") }, 1},
		{"explicitly denied target", func(value *spec.ForwardSpec) { value.Target.Address = netip.MustParseAddr("10.1.1.1") }, 1},
		{"rate exceeds", func(value *spec.ForwardSpec) { value.RateLimit.IngressBitsPerSecond = 11_000_000 }, 1},
		{"already expired", func(value *spec.ForwardSpec) { expired := now.Add(-time.Second); value.ExpiresAt = &expired }, 1},
		{"limit reached", func(*spec.ForwardSpec) {}, 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := forward
			rate := *forward.RateLimit
			candidate.RateLimit = &rate
			test.mutate(&candidate)
			if err := policy.AuthorizeForward(candidate, test.count, &tenantExpiry, now); !errors.Is(err, ErrForbidden) {
				t.Fatalf("authorization error = %v, want ErrForbidden", err)
			}
		})
	}
}

func TestEmptyPolicyGrantsNothing(t *testing.T) {
	policy := EmptyPolicy("tenant-a")
	if dataPlanePolicy, err := policy.DataPlanePolicy(); err != nil || dataPlanePolicy != nil {
		t.Fatalf("empty data-plane policy = %+v, err = %v", dataPlanePolicy, err)
	}
	forward := spec.ForwardSpec{UserID: "tenant-a", IngressNodeID: "node-a"}
	if err := policy.AuthorizeForward(forward, 0, nil, time.Now()); !errors.Is(err, ErrForbidden) {
		t.Fatalf("authorization error = %v, want ErrForbidden", err)
	}
}
