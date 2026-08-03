package spec

import (
	"net/netip"
	"strings"
	"testing"
)

func validState() DesiredState {
	return DesiredState{
		SchemaVersion: CurrentSchemaVersion,
		NodeID:        "node-a",
		Generation:    1,
		Forwards: []ForwardSpec{
			{
				ID:              "forward-1",
				UserID:          "user-1",
				Protocols:       []Protocol{ProtocolTCP},
				IngressNodeID:   "node-a",
				Listen:          Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
				Target:          Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
				PathMode:        PathDirect,
				SNAT:            SNATSpec{Mode: SNATMasquerade},
				Lifecycle:       LifecycleActive,
				ResourceVersion: 1,
			},
		},
	}
}

func TestValidateAcceptsDirectForward(t *testing.T) {
	if err := validState().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestProtocolBlocksRequireV5(t *testing.T) {
	state := validState()
	state.ProtocolBlocks = &ProtocolBlockPolicy{HTTP: true}
	if err := state.Validate(); err != nil {
		t.Fatalf("v5 protocol policy rejected: %v", err)
	}
	state.SchemaVersion = SchemaVersionV4
	if err := state.Validate(); err == nil || !strings.Contains(err.Error(), "protocol_blocks requires schema_version 5") {
		t.Fatalf("v4 protocol policy accepted: %v", err)
	}
}

func TestDesiredStateRejectsUnresolvedHostname(t *testing.T) {
	state := validState()
	state.Forwards[0].Target.Hostname = "example.com"
	if err := state.Validate(); err == nil || !strings.Contains(err.Error(), "must be resolved by Controller") {
		t.Fatalf("unresolved hostname validation error = %v", err)
	}
}

func TestNormalizeHostname(t *testing.T) {
	hostname, err := NormalizeHostname(" BÜCHER.Example. ")
	if err != nil || hostname != "xn--bcher-kva.example" {
		t.Fatalf("normalized hostname = %q, %v", hostname, err)
	}
	for _, value := range []string{"", "-bad.example", "bad_.example"} {
		if _, err := NormalizeHostname(value); err == nil {
			t.Fatalf("invalid hostname %q was accepted", value)
		}
	}
}

func TestValidateFindsListenerConflictPerProtocol(t *testing.T) {
	state := validState()
	second := state.Forwards[0]
	second.ID = "forward-2"
	second.UserID = "user-2"
	state.Forwards = append(state.Forwards, second)

	err := state.Validate()
	if err == nil || !strings.Contains(err.Error(), "listener conflicts") {
		t.Fatalf("Validate() error = %v, want listener conflict", err)
	}

	state.Forwards[1].Protocols = []Protocol{ProtocolUDP}
	if err := state.Validate(); err != nil {
		t.Fatalf("TCP and UDP on the same port should not conflict: %v", err)
	}
}

func TestValidateRejectsAmbiguousDirectPath(t *testing.T) {
	state := validState()
	state.Forwards[0].ExitNodeID = "node-b"
	err := state.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be empty for direct path") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateHealthChecksRequireV4TCPAndHysteresis(t *testing.T) {
	state := validState()
	state.HealthChecks = []HealthCheckSpec{{
		PoolID: "pool-a", BackendID: "backend-a", Endpoint: Endpoint{Address: netip.MustParseAddr("198.51.100.30"), Port: 443},
		Protocol: ProtocolTCP, IntervalSeconds: 2, TimeoutMilliseconds: 500,
		FailureThreshold: 3, SuccessThreshold: 2, ResourceVersion: 1,
	}}
	if err := state.Validate(); err != nil {
		t.Fatalf("valid health check rejected: %v", err)
	}
	state.SchemaVersion = SchemaVersionV3
	if err := state.Validate(); err == nil || !strings.Contains(err.Error(), "requires schema_version 4") {
		t.Fatalf("v3 health check accepted: %v", err)
	}
	state.SchemaVersion = SchemaVersionV4
	state.HealthChecks[0].Protocol = ProtocolUDP
	if err := state.Validate(); err == nil || !strings.Contains(err.Error(), "protocol must be tcp") {
		t.Fatalf("generic UDP health check accepted: %v", err)
	}
}

func TestChecksumIsOrderIndependent(t *testing.T) {
	first := validState()
	first.Forwards[0].Protocols = []Protocol{ProtocolUDP, ProtocolTCP}
	secondForward := first.Forwards[0]
	secondForward.ID = "forward-2"
	secondForward.Listen.Port = 444
	first.Forwards = append(first.Forwards, secondForward)

	second := first
	second.Forwards = append([]ForwardSpec(nil), first.Forwards...)
	second.Forwards[0], second.Forwards[1] = second.Forwards[1], second.Forwards[0]
	second.Forwards[1].Protocols = []Protocol{ProtocolTCP, ProtocolUDP}

	firstChecksum, err := first.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	secondChecksum, err := second.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	if firstChecksum != secondChecksum {
		t.Fatalf("checksums differ: %s != %s", firstChecksum, secondChecksum)
	}
}

func validViaExitState(nodeID string) DesiredState {
	local := "10.250.0.1/31"
	peer := "10.250.0.0"
	peerNode := "node-b"
	if nodeID == "node-b" {
		local = "10.250.0.0/31"
		peer = "10.250.0.1"
		peerNode = "node-a"
	}
	vip := netip.MustParseAddr("10.253.0.10")
	return DesiredState{
		SchemaVersion: SchemaVersionV3,
		NodeID:        nodeID,
		Generation:    1,
		ServiceCIDRs:  []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")},
		FabricLinks: []FabricLinkSpec{{
			ID: "fabric-ab", PeerNodeID: peerNode, Transport: FabricWireGuard,
			Interface: "fluxwg0", LocalAddress: netip.MustParsePrefix(local), PeerAddress: netip.MustParseAddr(peer),
			MTU: 1420, RoutingID: 100, ResourceVersion: 1,
			WireGuard: &WireGuardPeerSpec{
				PeerPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
				Endpoint:      "203.0.113.2:51820", ListenPort: 51820, PersistentKeepaliveSeconds: 25,
			},
		}},
		Forwards: []ForwardSpec{{
			ID: "cross-web", UserID: "user-1", Protocols: []Protocol{ProtocolTCP, ProtocolUDP},
			IngressNodeID: "node-a", ExitNodeID: "node-b",
			Listen:     Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
			Target:     Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
			ServiceVIP: &vip, FabricLinkID: "fabric-ab", PathMode: PathViaExit,
			SNAT: SNATSpec{Mode: SNATMasquerade}, Lifecycle: LifecycleActive, ResourceVersion: 1,
		}},
	}
}

func TestValidateAcceptsBothViaExitNodeRoles(t *testing.T) {
	for _, nodeID := range []string{"node-a", "node-b"} {
		if err := validViaExitState(nodeID).Validate(); err != nil {
			t.Fatalf("Validate(%s) error = %v", nodeID, err)
		}
	}
}

func TestValidateViaExitRequiresAllocatedVIPAndMatchingPeer(t *testing.T) {
	state := validViaExitState("node-a")
	state.Forwards[0].ServiceVIP = addrPointer(netip.MustParseAddr("10.254.0.1"))
	state.FabricLinks[0].PeerNodeID = "node-c"
	err := state.Validate()
	if err == nil || !strings.Contains(err.Error(), "outside service_cidrs") || !strings.Contains(err.Error(), "peer does not match") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsUntrustedPlainFabricAndCIDROverlap(t *testing.T) {
	state := validViaExitState("node-a")
	state.FabricLinks[0].Transport = FabricGRE
	state.FabricLinks[0].WireGuard = nil
	state.FabricLinks[0].GRE = &GRESpec{
		UnderlayLocal: netip.MustParseAddr("203.0.113.1"), UnderlayRemote: netip.MustParseAddr("203.0.113.2"), Key: 7,
	}
	state.ServiceCIDRs = append(state.ServiceCIDRs, netip.MustParsePrefix("10.253.0.0/25"))
	err := state.Validate()
	if err == nil || !strings.Contains(err.Error(), "gre requires trusted=true") || !strings.Contains(err.Error(), "overlaps service_cidrs") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func addrPointer(value netip.Addr) *netip.Addr { return &value }
