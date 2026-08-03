package store

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"flux.local/flux/internal/cluster"
	"flux.local/flux/internal/health"
	"flux.local/flux/internal/spec"
)

func TestNextAvailableVIPSkipsReservedAndUsedAddresses(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.253.0.0/29")}
	used := map[netip.Addr]string{netip.MustParseAddr("10.253.0.1"): "one"}
	cursors := map[string]uint64{}
	first, ok := nextAvailableVIP(prefixes, used, cursors)
	if !ok || first.String() != "10.253.0.2" {
		t.Fatalf("unexpected first VIP: %s %v", first, ok)
	}
	used[first] = "two"
	second, ok := nextAvailableVIP(prefixes, used, cursors)
	if !ok || second.String() != "10.253.0.3" {
		t.Fatalf("unexpected second VIP: %s %v", second, ok)
	}
	for _, address := range []string{"10.253.0.3", "10.253.0.4", "10.253.0.5", "10.253.0.6"} {
		used[netip.MustParseAddr(address)] = address
	}
	if _, ok := nextAvailableVIP(prefixes, used, cursors); ok {
		t.Fatal("allocator returned network, broadcast, or an already used address")
	}
}

func TestPlacementsEqualIncludesBackendAndFabric(t *testing.T) {
	base := cluster.Placement{ForwardID: "web", IngressID: "node-a", ExitID: "node-b", BackendID: "one", PathMode: spec.PathViaExit, FabricInID: "ab", FabricOutID: "ba", Target: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443}}
	if !placementsEqual([]cluster.Placement{base}, []cluster.Placement{base}) {
		t.Fatal("identical placements differ")
	}
	changed := base
	changed.BackendID = "two"
	if placementsEqual([]cluster.Placement{base}, []cluster.Placement{changed}) {
		t.Fatal("backend failover was ignored")
	}
}

func TestBackendPoolExplicitlyUnhealthyRequiresFreshCompleteEvidence(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	pool := cluster.BackendPool{
		ID: "web", Health: &cluster.HealthPolicy{StaleAfterSeconds: 10},
		Backends: []cluster.Backend{{ID: "one", ResourceVersion: 1}, {ID: "two", ResourceVersion: 2}},
	}
	observations := map[cluster.HealthKey]cluster.HealthObservation{
		{NodeID: "node-a", PoolID: "web", BackendID: "one"}: {Status: health.StatusUnhealthy, ResourceVersion: 1, ObservedAt: now},
		{NodeID: "node-a", PoolID: "web", BackendID: "two"}: {Status: health.StatusUnhealthy, ResourceVersion: 2, ObservedAt: now},
	}
	if !backendPoolExplicitlyUnhealthy(pool, "node-a", observations, now) {
		t.Fatal("complete fresh unhealthy evidence did not trip the canary gate")
	}
	value := observations[cluster.HealthKey{NodeID: "node-a", PoolID: "web", BackendID: "two"}]
	value.ObservedAt = now.Add(-11 * time.Second)
	observations[cluster.HealthKey{NodeID: "node-a", PoolID: "web", BackendID: "two"}] = value
	if backendPoolExplicitlyUnhealthy(pool, "node-a", observations, now) {
		t.Fatal("stale partial evidence tripped the canary gate")
	}
}

func TestClusterRolloutDetailRoundTripPreservesPlacementAndVIP(t *testing.T) {
	detail := clusterRolloutDetail{
		Version: 1, CommitPlacements: true, CanaryForwardIDs: []string{"web"},
		ServiceVIPs: map[string]netip.Addr{"web": netip.MustParseAddr("10.253.0.10")},
		Placements:  []cluster.Placement{{ForwardID: "web", IngressID: "node-a", ExitID: "node-b", PathMode: spec.PathViaExit, Target: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443}}},
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	var decoded clusterRolloutDetail
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ServiceVIPs["web"] != detail.ServiceVIPs["web"] || !placementsEqual(decoded.Placements, detail.Placements) || len(decoded.CanaryForwardIDs) != 1 {
		t.Fatalf("rollout detail did not round trip: %#v", decoded)
	}
}

func TestPreserveRuntimeLifecyclesSurvivesPlacementChangeButHonorsNewerIntent(t *testing.T) {
	current := map[string]spec.DesiredState{"node-a": directStateForStoreTest("node-a", spec.LifecyclePaused, 2)}
	target := map[string]spec.DesiredState{"node-b": directStateForStoreTest("node-b", spec.LifecycleActive, 1)}
	preserveRuntimeLifecycles(current, target)
	if target["node-b"].Forwards[0].Lifecycle != spec.LifecyclePaused || target["node-b"].Forwards[0].ResourceVersion != 2 {
		t.Fatalf("runtime pause was lost during placement change: %#v", target["node-b"].Forwards[0])
	}
	newer := map[string]spec.DesiredState{"node-b": directStateForStoreTest("node-b", spec.LifecycleActive, 3)}
	preserveRuntimeLifecycles(current, newer)
	if newer["node-b"].Forwards[0].Lifecycle != spec.LifecycleActive || newer["node-b"].Forwards[0].ResourceVersion != 3 {
		t.Fatalf("newer plan intent did not supersede runtime pause: %#v", newer["node-b"].Forwards[0])
	}
}

func directStateForStoreTest(nodeID string, lifecycle spec.Lifecycle, resourceVersion uint64) spec.DesiredState {
	return spec.DesiredState{
		SchemaVersion: spec.CurrentSchemaVersion, NodeID: nodeID, Generation: 1, ManagementDomain: "cluster:edge",
		Forwards: []spec.ForwardSpec{{
			ID: "web", UserID: "user-a", Protocols: []spec.Protocol{spec.ProtocolTCP}, IngressNodeID: nodeID,
			Listen: spec.Endpoint{Address: netip.MustParseAddr("203.0.113.10"), Port: 443}, Target: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 8443},
			PathMode: spec.PathDirect, SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade}, Lifecycle: lifecycle, ResourceVersion: resourceVersion,
		}},
	}
}
