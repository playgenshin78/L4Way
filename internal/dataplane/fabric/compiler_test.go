package fabric

import (
	"net/netip"
	"testing"

	"flux.local/flux/internal/spec"
)

func fabricState(nodeID string) spec.DesiredState {
	local := "10.250.0.1/31"
	peer := "10.250.0.0"
	peerNode := "node-b"
	if nodeID == "node-b" {
		local = "10.250.0.0/31"
		peer = "10.250.0.1"
		peerNode = "node-a"
	}
	vip := netip.MustParseAddr("10.253.0.10")
	return spec.DesiredState{
		SchemaVersion: spec.SchemaVersionV3, NodeID: nodeID, Generation: 4,
		ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")},
		FabricLinks: []spec.FabricLinkSpec{{
			ID: "fabric-ab", PeerNodeID: peerNode, Transport: spec.FabricWireGuard,
			Interface: "fluxwg0", LocalAddress: netip.MustParsePrefix(local), PeerAddress: netip.MustParseAddr(peer),
			MTU: 1420, RoutingID: 100, ResourceVersion: 1,
			WireGuard: &spec.WireGuardPeerSpec{
				PeerPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", Endpoint: "203.0.113.2:51820",
				ListenPort: 51820, PersistentKeepaliveSeconds: 25,
			},
		}},
		Forwards: []spec.ForwardSpec{{
			ID: "cross-web", UserID: "user-a", Protocols: []spec.Protocol{spec.ProtocolTCP},
			IngressNodeID: "node-a", ExitNodeID: "node-b",
			Listen:     spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
			Target:     spec.Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
			ServiceVIP: &vip, FabricLinkID: "fabric-ab", PathMode: spec.PathViaExit,
			SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade}, Lifecycle: spec.LifecycleActive, ResourceVersion: 1,
		}},
	}
}

func compileFabric(t *testing.T, state spec.DesiredState) Program {
	t.Helper()
	checksum, err := state.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	program, err := DefaultCompiler().Compile(state, checksum)
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func TestCompileIngressRoutesOnlyAllocatedVIPToPeer(t *testing.T) {
	program := compileFabric(t, fabricState("node-a"))
	if len(program.Links) != 1 || len(program.Routes) != 1 || len(program.Rules) != 0 {
		t.Fatalf("program = %+v", program)
	}
	link := program.Links[0]
	if len(link.AllowedIPs) != 2 || link.AllowedIPs[0].String() != "10.250.0.0/32" || link.AllowedIPs[1].String() != "10.253.0.10/32" {
		t.Fatalf("allowed IPs = %+v", link.AllowedIPs)
	}
	route := program.Routes[0]
	if route.Table != MainRouteTable || route.Destination.String() != "10.253.0.10/32" || route.Gateway == nil || route.Gateway.String() != "10.250.0.0" {
		t.Fatalf("route = %+v", route)
	}
}

func TestCompileExitBuildsDedicatedReturnTableAndMark(t *testing.T) {
	program := compileFabric(t, fabricState("node-b"))
	if len(program.Links) != 1 || len(program.Routes) != 1 || len(program.Rules) != 1 {
		t.Fatalf("program = %+v", program)
	}
	if got := program.Links[0].AllowedIPs; len(got) != 1 || got[0].String() != "10.250.0.1/32" {
		t.Fatalf("exit allowed IPs = %+v", got)
	}
	rule := program.Rules[0]
	if rule.Mark != 0x47000064 || rule.Mask != 0xffffffff || rule.Table != 47100 || rule.Priority != 20100 {
		t.Fatalf("rule = %+v", rule)
	}
	if route := program.Routes[0]; route.Table != 47100 || route.Destination.String() != "10.250.0.1/32" || route.Gateway != nil {
		t.Fatalf("return route = %+v", route)
	}
}

func TestFabricChecksumIgnoresUnrelatedLifecycleGeneration(t *testing.T) {
	first := fabricState("node-a")
	second := fabricState("node-a")
	second.Generation++
	second.Forwards[0].Lifecycle = spec.LifecyclePaused
	second.Forwards[0].ResourceVersion++
	if got, want := compileFabric(t, second).Checksum, compileFabric(t, first).Checksum; got != want {
		t.Fatalf("fabric-only checksum changed: got %s want %s", got, want)
	}
}
