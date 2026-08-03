//go:build linux

package conntrack

import (
	"context"
	"fmt"
	"net"

	"flux.local/flux/internal/spec"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Cleaner struct{}

func NewCleaner() *Cleaner { return &Cleaner{} }

// Delete removes flows by their pre-NAT original destination tuple. One table
// dump is shared by all filters, avoiding a shell process per forward.
func (*Cleaner) Delete(ctx context.Context, nodeID string, forwards []spec.ForwardSpec) (uint, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	filters := make([]netlink.CustomConntrackFilter, 0, len(forwards)*2)
	for _, forward := range forwards {
		destination := originalDestination(nodeID, forward)
		for _, protocol := range forward.Protocols {
			filter := &netlink.ConntrackFilter{}
			protocolNumber := uint8(6)
			if protocol == spec.ProtocolUDP {
				protocolNumber = 17
			}
			if err := filter.AddProtocol(protocolNumber); err != nil {
				return 0, fmt.Errorf("set conntrack protocol for %s: %w", forward.ID, err)
			}
			if err := filter.AddIP(netlink.ConntrackOrigDstIP, net.IP(destination.Address.AsSlice())); err != nil {
				return 0, fmt.Errorf("set conntrack destination for %s: %w", forward.ID, err)
			}
			if err := filter.AddPort(netlink.ConntrackOrigDstPort, destination.Port); err != nil {
				return 0, fmt.Errorf("set conntrack port for %s: %w", forward.ID, err)
			}
			filters = append(filters, filter)
		}
	}
	if len(filters) == 0 {
		return 0, nil
	}
	deleted, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, filters...)
	if err != nil {
		return deleted, fmt.Errorf("delete conntrack flows: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return deleted, err
	}
	return deleted, nil
}
