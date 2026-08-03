package nft

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"flux.local/flux/internal/spec"
)

func compilerState() spec.DesiredState {
	return spec.DesiredState{
		SchemaVersion: spec.CurrentSchemaVersion,
		NodeID:        "node-a",
		Generation:    7,
		Forwards: []spec.ForwardSpec{
			{
				ID:              "web",
				UserID:          "user-1",
				Protocols:       []spec.Protocol{spec.ProtocolTCP, spec.ProtocolUDP},
				IngressNodeID:   "node-a",
				Listen:          spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
				Target:          spec.Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
				PathMode:        spec.PathDirect,
				SNAT:            spec.SNATSpec{Mode: spec.SNATMasquerade},
				Lifecycle:       spec.LifecycleActive,
				ResourceVersion: 3,
			},
		},
	}
}

func compileTestState(t *testing.T, state spec.DesiredState, tableExists bool) Program {
	t.Helper()
	checksum, err := state.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	program, err := DefaultCompiler().Compile(state, checksum, tableExists)
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func TestCompileBuildsProtocolSpecificMapsAndScopedSNAT(t *testing.T) {
	program := compileTestState(t, compilerState(), false)
	checks := []string{
		"map dnat_addresses_tcp",
		"map dnat_ports_udp",
		"192.0.2.10 . 443 : 198.51.100.20",
		"192.0.2.10 . 443 : 8443",
		"ct original ip daddr . ct original proto-dst @masquerade_tcp masquerade",
		"counter flux_generation_7",
		"counter flux_desired_",
		"counter flux_program_",
	}
	for _, check := range checks {
		if !strings.Contains(program.Script, check) {
			t.Errorf("script does not contain %q\n%s", check, program.Script)
		}
	}
	if strings.Contains(program.Script, "flush ruleset") {
		t.Fatal("compiler must never flush the complete ruleset")
	}
	if len(program.Counters) != 4 {
		t.Fatalf("counter bindings = %d, want 4", len(program.Counters))
	}
	if !strings.Contains(program.Script, "ct direction original") || !strings.Contains(program.Script, "ct direction reply") {
		t.Fatal("compiler must account upload and download separately")
	}
}

func TestCompileBuildsNodeProtocolBlocksWithoutPortRules(t *testing.T) {
	state := compilerState()
	state.ProtocolBlocks = &spec.ProtocolBlockPolicy{HTTP: true, HTTPS: true, SOCKS: true, TLS: true}
	program := compileTestState(t, state, false)
	checks := []string{
		"chain protocol_block",
		"@ih,0,32 { 0x47455420, 0x50555420, 0x50524920 } drop",
		"@ih,0,64 0x434f4e4e45435420 drop",
		"@ih,0,16 { 0x0401, 0x0402 } @ih,64,8 0x00 drop",
		"@ih,0,24 { 0x050100, 0x050102 } drop",
		"@ih,0,24 { 0x160301, 0x160302, 0x160303, 0x160304 } @ih,40,8 0x01 drop",
		"@managed_tcp jump protocol_block",
	}
	for _, check := range checks {
		if !strings.Contains(program.Script, check) {
			t.Errorf("protocol policy script does not contain %q", check)
		}
	}
	if strings.Contains(program.Script, "tcp dport { 80") || strings.Contains(program.Script, "tcp dport { 443") {
		t.Fatalf("protocol blocking must not use destination-port deny rules:\n%s", program.Script)
	}
	if strings.Contains(program.Script, "chain https_alpn") {
		t.Fatal("HTTPS ALPN scan is redundant when the broader TLS policy is enabled")
	}
}

func TestCompileHTTPSScansTLSALPNAndAllowsUnclassifiedCiphertext(t *testing.T) {
	state := compilerState()
	state.ProtocolBlocks = &spec.ProtocolBlockPolicy{HTTPS: true}
	program := compileTestState(t, state, false)
	for _, check := range []string{
		"jump https_alpn",
		"chain https_alpn",
		"0x08687474702f312e31 drop",
		"0x026832 drop",
	} {
		if !strings.Contains(program.Script, check) {
			t.Errorf("HTTPS classifier does not contain %q", check)
		}
	}
	if strings.Contains(program.Script, "tcp dport 443 drop") || strings.Contains(program.Script, "tcp dport { 443") {
		t.Fatal("opaque traffic on port 443 must not be blocked by port number")
	}
}

func viaExitCompilerState(nodeID string) spec.DesiredState {
	ingress := nodeID == "node-a"
	local := "10.250.0.1/31"
	peer := "10.250.0.0"
	peerNode := "node-b"
	if !ingress {
		local = "10.250.0.0/31"
		peer = "10.250.0.1"
		peerNode = "node-a"
	}
	vip := netip.MustParseAddr("10.253.0.10")
	return spec.DesiredState{
		SchemaVersion: spec.SchemaVersionV3,
		NodeID:        nodeID,
		Generation:    9,
		ServiceCIDRs:  []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")},
		FabricLinks: []spec.FabricLinkSpec{{
			ID: "fabric-ab", PeerNodeID: peerNode, Transport: spec.FabricWireGuard,
			Interface: "fluxwg0", LocalAddress: netip.MustParsePrefix(local), PeerAddress: netip.MustParseAddr(peer),
			MTU: 1420, RoutingID: 100, ResourceVersion: 1,
			WireGuard: &spec.WireGuardPeerSpec{
				PeerPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
				Endpoint:      "203.0.113.2:51820", ListenPort: 51820, PersistentKeepaliveSeconds: 25,
			},
		}},
		Forwards: []spec.ForwardSpec{{
			ID: "cross-web", UserID: "user-1", Protocols: []spec.Protocol{spec.ProtocolTCP},
			IngressNodeID: "node-a", ExitNodeID: "node-b",
			Listen:     spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
			Target:     spec.Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
			ServiceVIP: &vip, FabricLinkID: "fabric-ab", PathMode: spec.PathViaExit,
			SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade}, Lifecycle: spec.LifecycleActive, ResourceVersion: 1,
		}},
	}
}

func TestCompileViaExitIngressUsesServiceVIPAndInternalSNAT(t *testing.T) {
	program := compileTestState(t, viaExitCompilerState("node-a"), false)
	checks := []string{
		"192.0.2.10 . 443 : 10.253.0.10",
		"192.0.2.10 . 443 : 8443",
		"192.0.2.10 . 443 : 10.250.0.1",
		"elements = { 192.0.2.10 . 443 };",
		"tcp option maxseg size set rt mtu",
	}
	for _, check := range checks {
		if !strings.Contains(program.Script, check) {
			t.Errorf("ingress script does not contain %q\n%s", check, program.Script)
		}
	}
	if strings.Contains(program.Script, "10.253.0.10 . 8443 : 0x47000064") {
		t.Fatal("ingress must not install the exit return mark")
	}
	if len(program.Counters) != 2 {
		t.Fatalf("ingress counter bindings = %d, want 2", len(program.Counters))
	}
}

func TestCompileViaExitExitDoesSecondDNATAndReturnMarkWithoutBilling(t *testing.T) {
	program := compileTestState(t, viaExitCompilerState("node-b"), false)
	checks := []string{
		"10.253.0.10 . 8443 : 198.51.100.20",
		"10.253.0.10 . 8443 : 8443",
		"10.253.0.10 . 8443 : 0x47000064",
		"ct direction reply ct mark & 0xffff0000 == 0x47000000 meta mark set ct mark",
		"elements = { 10.253.0.10 . 8443 };",
	}
	for _, check := range checks {
		if !strings.Contains(program.Script, check) {
			t.Errorf("exit script does not contain %q\n%s", check, program.Script)
		}
	}
	if len(program.Counters) != 0 {
		t.Fatalf("exit must not duplicate billable ingress counters: %+v", program.Counters)
	}
}

func TestCompileStaticSNATUsesAddressMap(t *testing.T) {
	state := compilerState()
	address := netip.MustParseAddr("192.0.2.99")
	state.Forwards[0].SNAT = spec.SNATSpec{Mode: spec.SNATStatic, Address: &address}
	program := compileTestState(t, state, false)
	if !strings.Contains(program.Script, "192.0.2.10 . 443 : 192.0.2.99") || !strings.Contains(program.Script, "snat ip to ct original") {
		t.Fatalf("static SNAT map is missing:\n%s", program.Script)
	}
}

func TestCompileReplacesOnlyOwnedTableWhenPresent(t *testing.T) {
	program := compileTestState(t, compilerState(), true)
	if !strings.HasPrefix(program.Script, "delete table inet flux\n") {
		t.Fatalf("script prefix is unsafe or unexpected:\n%s", program.Script)
	}
	if strings.Count(program.Script, "delete table") != 1 {
		t.Fatal("compiler should only delete its owned table")
	}
}

func TestCompilePausePrecedesAccountingAndNAT(t *testing.T) {
	state := compilerState()
	state.Forwards[0].Lifecycle = spec.LifecyclePaused
	program := compileTestState(t, state, true)
	drop := strings.Index(program.Script, "@paused_tcp drop")
	counter := strings.Index(program.Script, "counter name")
	nat := strings.Index(program.Script, "dnat ip to")
	if drop < 0 || counter < 0 || nat < 0 || drop >= counter {
		t.Fatalf("pause must precede accounting in the forward hook:\n%s", program.Script)
	}
	if !strings.Contains(program.Script, "hook prerouting priority dstnat") || !strings.Contains(program.Script, "hook forward priority -10") {
		t.Fatalf("NAT and pause hooks are not explicit:\n%s", program.Script)
	}
}

func TestCompileEnforcesExpirationAtRuntime(t *testing.T) {
	state := compilerState()
	expires := time.Unix(100, 0).UTC()
	state.Forwards[0].ExpiresAt = &expires
	checksum, err := state.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	program, err := DefaultCompiler().CompileAt(state, checksum, false, time.Unix(101, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(program.Script, "elements = { 192.0.2.10 . 443 };") {
		t.Fatalf("expired forward was not hard-blocked:\n%s", program.Script)
	}
}

func TestCompileMarksRateLimitedTraffic(t *testing.T) {
	state := compilerState()
	state.Forwards[0].RateLimit = &spec.RateLimitSpec{IngressBitsPerSecond: 1_000_000, BurstBytes: 64_000}
	state.Forwards[0].TrafficClassID = 22
	checksum, err := state.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	program, err := DefaultCompiler().Compile(state, checksum, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(program.Script, "0x46000016") || !strings.Contains(program.Script, "meta mark set") {
		t.Fatalf("rate class mark is missing:\n%s", program.Script)
	}
}

func TestCompileDrainsOnlyNewConnections(t *testing.T) {
	state := compilerState()
	state.Forwards[0].Lifecycle = spec.LifecycleDraining
	deadline := time.Now().Add(time.Hour).UTC()
	state.Forwards[0].DrainDeadline = &deadline
	checksum, err := state.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	program, err := DefaultCompiler().CompileAt(state, checksum, false, deadline.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(program.Script, "ct state new") || !strings.Contains(program.Script, "@draining_tcp drop") {
		t.Fatalf("drain rule is missing:\n%s", program.Script)
	}
}

func TestCompileIsDeterministicForEquivalentOrdering(t *testing.T) {
	first := compilerState()
	second := compilerState()
	second.Forwards[0].Protocols[0], second.Forwards[0].Protocols[1] = second.Forwards[0].Protocols[1], second.Forwards[0].Protocols[0]

	firstProgram := compileTestState(t, first, false)
	secondProgram := compileTestState(t, second, false)
	if firstProgram.Script != secondProgram.Script {
		t.Fatal("equivalent desired states generated different programs")
	}
}

func TestProgramChecksumIsDistinctFromDesiredChecksum(t *testing.T) {
	state := compilerState()
	desiredChecksum, err := state.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	if DefaultCompiler().ProgramChecksum(desiredChecksum) == desiredChecksum {
		t.Fatal("program checksum must include the compiler ABI")
	}
}
