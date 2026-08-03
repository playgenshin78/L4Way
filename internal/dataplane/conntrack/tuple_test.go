package conntrack

import (
	"net/netip"
	"testing"

	"flux.local/flux/internal/spec"
)

func TestOriginalDestinationUsesNodeRole(t *testing.T) {
	vip := netip.MustParseAddr("10.253.0.10")
	forward := spec.ForwardSpec{
		PathMode: spec.PathViaExit, IngressNodeID: "node-a", ExitNodeID: "node-b", ServiceVIP: &vip,
		Listen: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
		Target: spec.Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
	}
	if got := originalDestination("node-a", forward); got.Address.String() != "192.0.2.10" || got.Port != 443 {
		t.Fatalf("ingress tuple = %+v", got)
	}
	if got := originalDestination("node-b", forward); got.Address.String() != "10.253.0.10" || got.Port != 8443 {
		t.Fatalf("exit tuple = %+v", got)
	}
}
