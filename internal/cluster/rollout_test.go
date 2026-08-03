package cluster

import (
	"errors"
	"net/netip"
	"testing"

	"flux.local/flux/internal/spec"
)

func TestBuildRolloutStagesMovesExitBeforeIngressAndCleansOldExit(t *testing.T) {
	current := viaExitStates("node-a", "node-b", "fabric-ab", "fabric-ba")
	target := viaExitStates("node-a", "node-c", "fabric-ac", "fabric-ca")
	current["node-c"] = emptyStageState("node-c")
	target["node-b"] = emptyStageState("node-b")

	stages, canary, err := BuildRolloutStages("edge", RolloutStrategy{}, current, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(canary) != 0 || len(stages) != 3 {
		t.Fatalf("unexpected staged rollout: canary=%v stages=%#v", canary, stages)
	}
	if stages[0].Phase != RolloutPhasePrepare || !hasForward(stages[0].Desired["node-c"], "web") || len(stages[0].Desired) != 1 {
		t.Fatalf("new exit was not the isolated prepare barrier: %#v", stages[0])
	}
	if stages[1].Phase != RolloutPhasePromote || stages[1].Desired["node-a"].Forwards[0].ExitNodeID != "node-c" {
		t.Fatalf("ingress was not promoted after prepare: %#v", stages[1])
	}
	if stages[2].Phase != RolloutPhaseCleanup || hasForward(stages[2].Desired["node-b"], "web") {
		t.Fatalf("old exit was not removed in cleanup: %#v", stages[2])
	}
	for _, stage := range stages {
		for nodeID, desired := range stage.Desired {
			if err := desired.Validate(); err != nil {
				t.Fatalf("%s/%s target %s is invalid: %v", stage.Wave, stage.Phase, nodeID, err)
			}
		}
	}
}

func TestBuildRolloutStagesCanarySelectionAndBakeAreDeterministic(t *testing.T) {
	current := map[string]spec.DesiredState{"node-a": emptyStageState("node-a")}
	target := map[string]spec.DesiredState{"node-a": directState("node-a", "one", 10001, "192.0.2.11")}
	second := directForward("node-a", "two", 10002, "192.0.2.12")
	targetState := target["node-a"]
	targetState.Forwards = append(targetState.Forwards, second)
	target["node-a"] = targetState.Canonical()
	strategy := RolloutStrategy{CanaryPercent: 50, BakeSeconds: 30}

	first, canary, err := BuildRolloutStages("edge", strategy, current, target)
	if err != nil {
		t.Fatal(err)
	}
	secondRun, secondCanary, err := BuildRolloutStages("edge", strategy, current, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(canary) != 1 || len(secondCanary) != 1 || canary[0] != secondCanary[0] {
		t.Fatalf("canary selection is not stable: %v / %v", canary, secondCanary)
	}
	if len(first) != 3 || first[0].Wave != RolloutWaveCanary || first[0].Phase != RolloutPhasePromote || first[1].Phase != RolloutPhaseBake || first[1].BakeSeconds != 30 || first[2].Wave != RolloutWaveFull {
		t.Fatalf("unexpected canary barriers: %#v", first)
	}
	if !reflectStages(first, secondRun) {
		t.Fatal("identical input produced a different rollout")
	}
}

func TestBuildRolloutStagesRejectsInPlaceActiveFabricMutation(t *testing.T) {
	current := viaExitStates("node-a", "node-b", "fabric-ab", "fabric-ba")
	target := cloneStateMap(current)
	state := target["node-a"]
	state.FabricLinks[0].MTU = 1400
	state.FabricLinks[0].ResourceVersion++
	target["node-a"] = state
	if _, _, err := BuildRolloutStages("edge", RolloutStrategy{}, current, target); !errors.Is(err, ErrUnsafeRollout) {
		t.Fatalf("active in-place fabric change was accepted: %v", err)
	}
}

func TestBuildRolloutStagesRejectsIngressMoveOnSharedExit(t *testing.T) {
	current := viaExitStates("node-a", "node-b", "fabric-ab", "fabric-ba")
	target := viaExitStates("node-c", "node-b", "fabric-cb", "fabric-bc")
	current["node-c"] = emptyStageState("node-c")
	target["node-a"] = emptyStageState("node-a")
	if _, _, err := BuildRolloutStages("edge", RolloutStrategy{}, current, target); !errors.Is(err, ErrUnsafeRollout) {
		t.Fatalf("shared-exit ingress move was accepted: %v", err)
	}
}

func TestPlanValidateRolloutStrategy(t *testing.T) {
	plan := testPlan()
	plan.Rollout = &RolloutStrategy{CanaryPercent: 50}
	if err := plan.Validate(); err == nil {
		t.Fatal("canary without bake window was accepted")
	}
	plan.Rollout.BakeSeconds = 60
	if err := plan.Validate(); err != nil {
		t.Fatalf("valid canary strategy was rejected: %v", err)
	}
}

func directState(nodeID, forwardID string, listenPort uint16, target string) spec.DesiredState {
	return spec.DesiredState{
		SchemaVersion: spec.CurrentSchemaVersion, NodeID: nodeID, Generation: 1, ManagementDomain: "cluster:edge",
		Forwards: []spec.ForwardSpec{directForward(nodeID, forwardID, listenPort, target)},
	}.Canonical()
}

func directForward(nodeID, forwardID string, listenPort uint16, target string) spec.ForwardSpec {
	return spec.ForwardSpec{
		ID: forwardID, UserID: "user-a", Protocols: []spec.Protocol{spec.ProtocolTCP}, IngressNodeID: nodeID,
		Listen: spec.Endpoint{Address: netip.MustParseAddr("203.0.113.10"), Port: listenPort},
		Target: spec.Endpoint{Address: netip.MustParseAddr(target), Port: 8443}, PathMode: spec.PathDirect,
		SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade}, Lifecycle: spec.LifecycleActive, ResourceVersion: 1,
	}
}

func viaExitStates(ingressID, exitID, ingressLinkID, exitLinkID string) map[string]spec.DesiredState {
	vip := netip.MustParseAddr("10.253.0.10")
	forward := spec.ForwardSpec{
		ID: "web", UserID: "user-a", Protocols: []spec.Protocol{spec.ProtocolTCP}, IngressNodeID: ingressID, ExitNodeID: exitID,
		Listen: spec.Endpoint{Address: netip.MustParseAddr("203.0.113.10"), Port: 443},
		Target: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 8443}, ServiceVIP: &vip,
		PathMode: spec.PathViaExit, SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade}, Lifecycle: spec.LifecycleActive, ResourceVersion: 1,
	}
	ingressForward := forward
	ingressForward.FabricLinkID = ingressLinkID
	exitForward := forward
	exitForward.FabricLinkID = exitLinkID
	return map[string]spec.DesiredState{
		ingressID: {
			SchemaVersion: spec.CurrentSchemaVersion, NodeID: ingressID, Generation: 1, ManagementDomain: "cluster:edge",
			ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")},
			FabricLinks:  []spec.FabricLinkSpec{testDirectLink(ingressLinkID, exitID)}, Forwards: []spec.ForwardSpec{ingressForward},
		},
		exitID: {
			SchemaVersion: spec.CurrentSchemaVersion, NodeID: exitID, Generation: 1, ManagementDomain: "cluster:edge",
			ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")},
			FabricLinks:  []spec.FabricLinkSpec{testDirectLink(exitLinkID, ingressID)}, Forwards: []spec.ForwardSpec{exitForward},
		},
	}
}

func testDirectLink(id, peer string) spec.FabricLinkSpec {
	pairs := map[string]struct {
		local netip.Prefix
		peer  netip.Addr
		iface string
		route uint16
	}{
		"fabric-ab": {netip.MustParsePrefix("10.250.0.0/31"), netip.MustParseAddr("10.250.0.1"), "eth1", 100},
		"fabric-ba": {netip.MustParsePrefix("10.250.0.1/31"), netip.MustParseAddr("10.250.0.0"), "eth1", 101},
		"fabric-ac": {netip.MustParsePrefix("10.250.0.2/31"), netip.MustParseAddr("10.250.0.3"), "eth2", 102},
		"fabric-ca": {netip.MustParsePrefix("10.250.0.3/31"), netip.MustParseAddr("10.250.0.2"), "eth2", 103},
		"fabric-cb": {netip.MustParsePrefix("10.250.0.4/31"), netip.MustParseAddr("10.250.0.5"), "eth3", 104},
		"fabric-bc": {netip.MustParsePrefix("10.250.0.5/31"), netip.MustParseAddr("10.250.0.4"), "eth3", 105},
	}
	pair := pairs[id]
	return spec.FabricLinkSpec{ID: id, PeerNodeID: peer, Transport: spec.FabricDirectL3, Interface: pair.iface, LocalAddress: pair.local, PeerAddress: pair.peer, MTU: 1500, RoutingID: pair.route, Trusted: true, ResourceVersion: 1}
}

func hasForward(state spec.DesiredState, forwardID string) bool {
	for _, forward := range state.Forwards {
		if forward.ID == forwardID {
			return true
		}
	}
	return false
}

func reflectStages(first, second []RolloutStage) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index].Wave != second[index].Wave || first[index].Phase != second[index].Phase || first[index].BakeSeconds != second[index].BakeSeconds {
			return false
		}
		if len(changedStates(first[index].Desired, second[index].Desired)) != 0 || len(changedStates(second[index].Desired, first[index].Desired)) != 0 {
			return false
		}
	}
	return true
}
