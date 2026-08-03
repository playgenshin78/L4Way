package fabric

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"flux.local/flux/internal/spec"
)

type runnerCall struct {
	path  string
	args  []string
	stdin string
}

type recordingRunner struct{ calls []runnerCall }

func (r *recordingRunner) Run(_ context.Context, path string, args []string, stdin []byte) ([]byte, []byte, error) {
	r.calls = append(r.calls, runnerCall{path: path, args: append([]string(nil), args...), stdin: string(stdin)})
	if strings.Contains(strings.Join(args, " "), "link show dev fluxwg0") {
		return []byte(`[{"ifname":"fluxwg0","mtu":1420,"ifalias":"managed-by=flux;fabric=fabric-ab","linkinfo":{"info_kind":"wireguard"}}]`), nil, nil
	}
	return nil, nil, nil
}

type missingRouteRunner struct{}

func (missingRouteRunner) Run(context.Context, string, []string, []byte) ([]byte, []byte, error) {
	return nil, []byte("Error: ipv4: FIB table does not exist.\nDump terminated"), errors.New("exit status 2")
}

type wireGuardDumpRunner struct{}

func (wireGuardDumpRunner) Run(context.Context, string, []string, []byte) ([]byte, []byte, error) {
	return []byte("private\tpublic\t51820\toff\npeer-key\t(none)\t192.0.2.10:51820\t10.250.0.0/32\t0\t0\t0\t25\n"), nil, nil
}

func TestVerifyWireGuardAcceptsStandardEightFieldPeerDump(t *testing.T) {
	executor, err := NewExecutor(Config{IPPath: "ip", WGPath: "wg", SysctlPath: "sysctl", PrivateKeyPath: "key", AllowManage: true}, wireGuardDumpRunner{})
	if err != nil {
		t.Fatal(err)
	}
	link := LinkPlan{
		Interface: "fluxwg0",
		WireGuard: &spec.WireGuardPeerSpec{
			PeerPublicKey: "peer-key", Endpoint: "192.0.2.10:51820", ListenPort: 51820, PersistentKeepaliveSeconds: 25,
		},
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/32")},
	}
	if err := executor.verifyWireGuard(context.Background(), link); err != nil {
		t.Fatal(err)
	}
}

func TestRoutesTreatsMissingPolicyTableAsEmpty(t *testing.T) {
	executor, err := NewExecutor(Config{IPPath: "ip", WGPath: "wg", SysctlPath: "sysctl", PrivateKeyPath: "key", AllowManage: true}, missingRouteRunner{})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := executor.routes(context.Background(), RoutePlan{Destination: netip.MustParsePrefix("10.250.0.0/32"), Table: 47100})
	if err != nil || len(routes) != 0 {
		t.Fatalf("routes = %+v, error = %v", routes, err)
	}
}

func TestRouteMatchesNumericProtocolAndBareHostDestination(t *testing.T) {
	installed := routeJSON{
		Destination: "10.250.0.0",
		Device:      "fluxwg0",
		Protocol:    []byte(`"186"`),
	}
	expected := RoutePlan{
		Destination: netip.MustParsePrefix("10.250.0.0/32"),
		Interface:   "fluxwg0",
		Protocol:    RouteProtocol,
	}
	if !routeMatches(installed, expected) {
		t.Fatal("bare host route with numeric protocol did not match")
	}
}

func TestCheckRequiresExplicitFabricOwnership(t *testing.T) {
	executor, err := NewExecutor(Config{IPPath: "ip", WGPath: "wg", SysctlPath: "sysctl", PrivateKeyPath: "key", AllowManage: false}, &recordingRunner{})
	if err != nil {
		t.Fatal(err)
	}
	err = executor.Check(context.Background(), Program{}, Program{Active: true})
	if err != ErrOwnershipRequired {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestCleanupDeletesOnlyOwnedRoutesRulesAndManagedLinks(t *testing.T) {
	runner := &recordingRunner{}
	executor, err := NewExecutor(Config{IPPath: "ip", WGPath: "wg", SysctlPath: "sysctl", PrivateKeyPath: "key", AllowManage: true}, runner)
	if err != nil {
		t.Fatal(err)
	}
	gateway := netip.MustParseAddr("10.250.0.2")
	previous := Program{
		Active: true,
		Links: []LinkPlan{
			{ID: "fabric-ab", Interface: "fluxwg0", Transport: spec.FabricWireGuard},
			{Interface: "eth1", Transport: spec.FabricDirectL3},
		},
		Routes: []RoutePlan{{Destination: netip.MustParsePrefix("10.253.0.10/32"), Interface: "fluxwg0", Gateway: &gateway, Table: 254, Protocol: RouteProtocol}},
		Rules:  []RulePlan{{Mark: 0x47000064, Mask: 0xffffffff, Table: 47100, Priority: 20100}},
	}
	if err := executor.Cleanup(context.Background(), previous, Program{}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %+v", runner.calls)
	}
	batch := runner.calls[1].stdin
	for _, want := range []string{"route del 10.253.0.10/32 via 10.250.0.2 dev fluxwg0 table 254 proto 186", "rule del priority 20100 fwmark 0x47000064/0xffffffff lookup 47100", "link del dev fluxwg0"} {
		if !strings.Contains(batch, want) {
			t.Errorf("cleanup batch does not contain %q:\n%s", want, batch)
		}
	}
	if strings.Contains(batch, "link del dev eth1") {
		t.Fatal("cleanup attempted to delete a direct_l3 interface")
	}
}
