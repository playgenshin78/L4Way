package tc

import (
	"net/netip"
	"strings"
	"testing"

	"flux.local/flux/internal/spec"
)

func rateState() spec.DesiredState {
	return spec.DesiredState{
		SchemaVersion: spec.SchemaVersionV2,
		NodeID:        "node-a",
		Generation:    4,
		UserPolicies: []spec.UserPolicySpec{{
			UserID: "user-a", TrafficClassID: 20,
			RateLimit:       &spec.RateLimitSpec{IngressBitsPerSecond: 20_000_000, EgressBitsPerSecond: 30_000_000, BurstBytes: 65536},
			ResourceVersion: 1,
		}},
		Forwards: []spec.ForwardSpec{{
			ID: "web", UserID: "user-a", Protocols: []spec.Protocol{spec.ProtocolTCP}, IngressNodeID: "node-a",
			Listen: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443}, Target: spec.Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
			PathMode: spec.PathDirect, SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade}, TrafficClassID: 21,
			RateLimit: &spec.RateLimitSpec{IngressBitsPerSecond: 5_000_000, EgressBitsPerSecond: 8_000_000, BurstBytes: 32768},
			Lifecycle: spec.LifecycleActive, ResourceVersion: 1,
		}},
	}
}

func TestCompileBuildsHTBIFBAndMarkClassifiers(t *testing.T) {
	state := rateState()
	checksum, _ := state.Checksum()
	program, err := NewCompiler(Config{PublicInterface: "eth0", IFBInterface: "flux-ifb0", UploadLinkBitsPerSecond: 100_000_000, DownloadLinkBitsPerSecond: 100_000_000, AllowReplaceRoot: true}).Compile(state, checksum)
	if err != nil {
		t.Fatal(err)
	}
	checks := []string{
		"qdisc add dev eth0 root handle 1: htb",
		"classid 1:14 htb rate 30000000bit",
		"classid 1:15 htb rate 8000000bit",
		"handle 0x46000015 fw classid 1:15",
		"flower dst_ip 192.0.2.10 ip_proto tcp dst_port 443",
		"mirred egress redirect dev flux-ifb0",
	}
	for _, check := range checks {
		if !strings.Contains(program.Batch, check) {
			t.Errorf("tc batch does not contain %q:\n%s", check, program.Batch)
		}
	}
	if !program.Active || len(program.ExpectedClasses) != 4 || len(program.Checksum) != 64 {
		t.Fatalf("unexpected program: %+v", program)
	}
}

func TestCompileRequiresExplicitRootOwnership(t *testing.T) {
	state := rateState()
	checksum, _ := state.Checksum()
	_, err := NewCompiler(Config{PublicInterface: "eth0", IFBInterface: "flux-ifb0", UploadLinkBitsPerSecond: 1, DownloadLinkBitsPerSecond: 1}).Compile(state, checksum)
	if err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("Compile() error = %v", err)
	}
}

func TestCompileNoRateDoesNotRequireInterfaces(t *testing.T) {
	state := rateState()
	state.UserPolicies = nil
	state.Forwards[0].RateLimit = nil
	state.Forwards[0].TrafficClassID = 0
	checksum, _ := state.Checksum()
	program, err := NewCompiler(Config{}).Compile(state, checksum)
	if err != nil {
		t.Fatal(err)
	}
	if program.Active || program.Batch != "" || len(program.Checksum) != 64 {
		t.Fatalf("unexpected inactive program: %+v", program)
	}
}
