package conntrack

import (
	"net/netip"

	"flux.local/flux/internal/spec"
)

type originalTuple struct {
	Address netip.Addr
	Port    uint16
}

func originalDestination(nodeID string, forward spec.ForwardSpec) originalTuple {
	if forward.PathMode == spec.PathViaExit && nodeID == forward.ExitNodeID && forward.ServiceVIP != nil {
		return originalTuple{Address: forward.ServiceVIP.Unmap(), Port: forward.Target.Port}
	}
	return originalTuple{Address: forward.Listen.Address.Unmap(), Port: forward.Listen.Port}
}
