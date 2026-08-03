package cluster

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"flux.local/flux/internal/health"
	"flux.local/flux/internal/spec"
)

func TestPlaceFailsOverAndCompileBuildsBothNodeRoles(t *testing.T) {
	plan := testPlan()
	plan.Nodes[0].ProtocolBlocks = &spec.ProtocolBlockPolicy{HTTP: true, SOCKS: true}
	runtimes := testRuntimes()
	now := time.Unix(1_900_000_000, 0).UTC()
	initial, err := Place(plan, runtimes, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := initial.Placements[0]; got.IngressID != "node-a" || got.ExitID != "node-b" || got.BackendID != "primary" || got.FabricInID != "fabric-ab" || got.FabricOutID != "fabric-ba" {
		t.Fatalf("unexpected initial placement: %#v", got)
	}
	if len(initial.Alerts) != 1 || initial.Alerts[0].Code != "backend_health_unknown" {
		t.Fatalf("initial unknown health was not surfaced: %#v", initial.Alerts)
	}
	observations := map[HealthKey]HealthObservation{
		{NodeID: "node-b", PoolID: "web-pool", BackendID: "primary"}:   {Status: health.StatusUnhealthy, ResourceVersion: 1, ObservedAt: now},
		{NodeID: "node-b", PoolID: "web-pool", BackendID: "secondary"}: {Status: health.StatusHealthy, ResourceVersion: 1, ObservedAt: now},
	}
	failover, err := Place(plan, runtimes, observations, initial.Placements, now)
	if err != nil {
		t.Fatal(err)
	}
	if failover.Placements[0].BackendID != "secondary" || len(failover.Alerts) != 0 {
		t.Fatalf("healthy failover was not selected: %#v %#v", failover.Placements, failover.Alerts)
	}
	observations[HealthKey{NodeID: "node-b", PoolID: "web-pool", BackendID: "secondary"}] = HealthObservation{Status: health.StatusUnhealthy, ResourceVersion: 1, ObservedAt: now}
	exhausted, err := Place(plan, runtimes, observations, failover.Placements, now)
	if err != nil {
		t.Fatal(err)
	}
	if exhausted.Placements[0].BackendID != "secondary" || len(exhausted.Alerts) != 1 || exhausted.Alerts[0].Code != "backend_pool_exhausted" {
		t.Fatalf("all-down pool did not retain its previous backend: %#v %#v", exhausted.Placements, exhausted.Alerts)
	}
	desired, err := Compile(plan, failover, map[string]netip.Addr{"web": netip.MustParseAddr("10.253.0.10")}, runtimes)
	if err != nil {
		t.Fatal(err)
	}
	if desired["node-a"].ProtocolBlocks == nil || !desired["node-a"].ProtocolBlocks.HTTP || !desired["node-a"].ProtocolBlocks.SOCKS {
		t.Fatalf("node protocol policy was not compiled: %+v", desired["node-a"].ProtocolBlocks)
	}
	if desired["node-b"].ProtocolBlocks != nil {
		t.Fatalf("protocol policy leaked to another node: %+v", desired["node-b"].ProtocolBlocks)
	}
	ingress := desired["node-a"]
	exit := desired["node-b"]
	if len(ingress.Forwards) != 1 || len(exit.Forwards) != 1 || len(ingress.FabricLinks) != 1 || len(exit.FabricLinks) != 1 {
		t.Fatalf("via-exit roles were not compiled: ingress=%#v exit=%#v", ingress, exit)
	}
	if len(ingress.HealthChecks) != 0 || len(exit.HealthChecks) != 2 {
		t.Fatalf("health probes must execute at exit: ingress=%#v exit=%#v", ingress.HealthChecks, exit.HealthChecks)
	}
	if ingress.Forwards[0].Target.Address.String() != "192.0.2.20" || exit.Forwards[0].ServiceVIP == nil || exit.Forwards[0].ServiceVIP.String() != "10.253.0.10" {
		t.Fatalf("compiled target or VIP is wrong: ingress=%#v exit=%#v", ingress.Forwards[0], exit.Forwards[0])
	}
	if ingress.FabricLinks[0].WireGuard.PeerPublicKey != runtimes["node-b"].WireGuardPublicKey || exit.FabricLinks[0].WireGuard.PeerPublicKey != runtimes["node-a"].WireGuardPublicKey {
		t.Fatal("WireGuard public keys were not resolved from live node identity")
	}
}

func TestPlaceRejectsUnavailableOrSameFailureDomain(t *testing.T) {
	plan := testPlan()
	runtimes := testRuntimes()
	runtime := runtimes["node-b"]
	runtime.Available = false
	runtimes["node-b"] = runtime
	if _, err := Place(plan, runtimes, nil, nil, time.Now()); !errors.Is(err, ErrNoPlacement) {
		t.Fatalf("unavailable exit was accepted: %v", err)
	}
	runtime.Available = true
	runtimes["node-b"] = runtime
	plan.Nodes[1].FailureDomain = "zone-a"
	if _, err := Place(plan, runtimes, nil, nil, time.Now()); !errors.Is(err, ErrNoPlacement) {
		t.Fatalf("same failure domain was accepted under distinct policy: %v", err)
	}
	plan.Forwards[0].FailureDomainPolicy = FailureDomainPrefer
	if _, err := Place(plan, runtimes, nil, nil, time.Now()); err != nil {
		t.Fatalf("prefer_distinct should fall back when needed: %v", err)
	}
}

func TestPlanJSONIsStrictAndChecksumCanonical(t *testing.T) {
	plan := testPlan()
	encoded, err := EncodePlanJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"rollout"`)) {
		t.Fatalf("an omitted rollout strategy changed the schema v1 canonical JSON: %s", encoded)
	}
	decoded, err := DecodePlanJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := plan.Checksum()
	second, _ := decoded.Checksum()
	if first != second {
		t.Fatalf("checksum changed after round trip: %s != %s", first, second)
	}
	explicitDefault := plan
	explicitDefault.Rollout = &RolloutStrategy{CanaryPercent: 100}
	third, _ := explicitDefault.Checksum()
	if first != third {
		t.Fatalf("explicit rollout defaults changed canonical checksum: %s != %s", first, third)
	}
	bad := append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...)
	if _, err := DecodePlanJSON(bad); err == nil {
		t.Fatal("unknown cluster-plan field was accepted")
	}
}

func TestDomainTargetIsCanonicalInPlanAndConcreteInDesiredState(t *testing.T) {
	plan := testPlan()
	plan.BackendPools[0].Backends[0].Target.Hostname = "Example.COM."
	if err := plan.Validate(); err != nil {
		t.Fatalf("domain target plan rejected: %v", err)
	}
	if got := plan.Canonical().BackendPools[0].Backends[0].Target.Hostname; got != "example.com" {
		t.Fatalf("canonical hostname = %q", got)
	}
	placed, err := Place(plan, testRuntimes(), nil, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	desired, err := Compile(plan, placed, map[string]netip.Addr{"web": netip.MustParseAddr("10.253.0.10")}, testRuntimes())
	if err != nil {
		t.Fatal(err)
	}
	for nodeID, state := range desired {
		for _, forward := range state.Forwards {
			if forward.Target.Hostname != "" || forward.Target.Address.String() != "192.0.2.10" {
				t.Fatalf("node %s received unresolved target: %+v", nodeID, forward.Target)
			}
		}
	}
}

func TestPlanListenIPsAreCanonicalAndValidated(t *testing.T) {
	plan := testPlan()
	plan.Nodes[0].ListenIPs = []netip.Addr{
		netip.MustParseAddr("203.0.113.11"),
		netip.MustParseAddr("203.0.113.10"),
	}
	canonical := plan.Canonical()
	if canonical.Nodes[0].ListenIPs[0].String() != "203.0.113.10" {
		t.Fatalf("listen IPs were not canonicalized: %+v", canonical.Nodes[0].ListenIPs)
	}
	plan.Nodes[0].ListenIPs = []netip.Addr{
		netip.MustParseAddr("203.0.113.10"),
		netip.MustParseAddr("203.0.113.10"),
	}
	if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), "listen_ips contains a duplicate") {
		t.Fatalf("duplicate listen IP validation error = %v", err)
	}
}

func TestEmptyClusterPlanIsValid(t *testing.T) {
	plan := Plan{
		SchemaVersion: PlanSchemaVersionV1, ID: "empty", Revision: 1, NodeOfflineAfterSeconds: 90,
		Nodes: []Node{}, BackendPools: []BackendPool{}, Forwards: []Forward{},
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("empty plan should support uninstalling the final node: %v", err)
	}
	result, err := Place(plan, map[string]NodeRuntime{}, nil, nil, time.Now().UTC())
	if err != nil || len(result.Placements) != 0 {
		t.Fatalf("Place(empty) result=%+v err=%v", result, err)
	}
}

func testPlan() Plan {
	return Plan{
		SchemaVersion: PlanSchemaVersionV1, ID: "edge", Revision: 1, NodeOfflineAfterSeconds: 90,
		ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")},
		Nodes: []Node{
			{ID: "node-a", Enabled: true, Roles: []NodeRole{RoleIngress}, Labels: map[string]string{"region": "hk"}, FailureDomain: "zone-a", Capacity: Capacity{MaxForwards: 100, IngressBitsPerSecond: 1_000_000_000, EgressBitsPerSecond: 1_000_000_000}, FabricLinks: []FabricLink{{
				ID: "fabric-ab", PeerNodeID: "node-b", Transport: spec.FabricWireGuard, Interface: "fluxwg0",
				LocalAddress: netip.MustParsePrefix("10.250.0.0/31"), PeerAddress: netip.MustParseAddr("10.250.0.1"),
				MTU: 1420, RoutingID: 100, WireGuard: &WireGuardLink{Endpoint: "198.51.100.20:51820", ListenPort: 51820, PersistentKeepaliveSeconds: 25}, ResourceVersion: 1,
			}}},
			{ID: "node-b", Enabled: true, Roles: []NodeRole{RoleExit}, Labels: map[string]string{"region": "sg"}, FailureDomain: "zone-b", Capacity: Capacity{MaxForwards: 100, IngressBitsPerSecond: 1_000_000_000, EgressBitsPerSecond: 1_000_000_000}, FabricLinks: []FabricLink{{
				ID: "fabric-ba", PeerNodeID: "node-a", Transport: spec.FabricWireGuard, Interface: "fluxwg0",
				LocalAddress: netip.MustParsePrefix("10.250.0.1/31"), PeerAddress: netip.MustParseAddr("10.250.0.0"),
				MTU: 1420, RoutingID: 101, WireGuard: &WireGuardLink{Endpoint: "198.51.100.10:51820", ListenPort: 51820, PersistentKeepaliveSeconds: 25}, ResourceVersion: 1,
			}}},
		},
		BackendPools: []BackendPool{{
			ID: "web-pool", ResourceVersion: 1,
			Health: &HealthPolicy{IntervalSeconds: 2, TimeoutMilliseconds: 500, FailureThreshold: 2, SuccessThreshold: 2, StaleAfterSeconds: 10},
			Backends: []Backend{
				{ID: "primary", Target: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 8443}, Priority: 10, ResourceVersion: 1},
				{ID: "secondary", Target: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.20"), Port: 8443}, Priority: 20, ResourceVersion: 1},
			},
		}},
		Forwards: []Forward{{
			ID: "web", UserID: "user-a", Protocols: []spec.Protocol{spec.ProtocolTCP},
			Listen: spec.Endpoint{Address: netip.MustParseAddr("203.0.113.10"), Port: 443}, PathMode: spec.PathViaExit,
			Ingress: NodeSelector{NodeIDs: []string{"node-a"}}, Exit: &NodeSelector{NodeIDs: []string{"node-b"}},
			FailureDomainPolicy: FailureDomainDistinct, BackendPoolID: "web-pool", SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade},
			Reservation: Reservation{IngressBitsPerSecond: 100_000_000, EgressBitsPerSecond: 100_000_000}, Lifecycle: spec.LifecycleActive, ResourceVersion: 1,
		}},
	}
}

func testRuntimes() map[string]NodeRuntime {
	capabilities := map[string]uint32{
		"nft.direct": 2, "nft.via-exit": 1, "fabric.policy-routing": 1, "fabric.mss-clamp": 1,
		"fabric.wireguard": 1, "health.tcp-connect": 1, "usage.l3": 1, "tc.rate-limit": 1,
	}
	clone := func() map[string]uint32 {
		result := make(map[string]uint32, len(capabilities))
		for key, value := range capabilities {
			result[key] = value
		}
		return result
	}
	return map[string]NodeRuntime{
		"node-a": {ID: "node-a", Available: true, Capabilities: clone(), WireGuardPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="},
		"node-b": {ID: "node-b", Available: true, Capabilities: clone(), WireGuardPublicKey: "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A="},
	}
}
