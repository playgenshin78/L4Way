package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
)

func (s DesiredState) Canonical() DesiredState {
	result := s
	if s.ProtocolBlocks != nil && s.ProtocolBlocks.Any() {
		policy := *s.ProtocolBlocks
		result.ProtocolBlocks = &policy
	} else {
		result.ProtocolBlocks = nil
	}
	result.ServiceCIDRs = append([]netip.Prefix(nil), s.ServiceCIDRs...)
	for i := range result.ServiceCIDRs {
		result.ServiceCIDRs[i] = canonicalPrefix(result.ServiceCIDRs[i])
	}
	sort.Slice(result.ServiceCIDRs, func(i, j int) bool {
		return result.ServiceCIDRs[i].String() < result.ServiceCIDRs[j].String()
	})
	result.FabricLinks = append([]FabricLinkSpec(nil), s.FabricLinks...)
	for i := range result.FabricLinks {
		link := &result.FabricLinks[i]
		link.LocalAddress = canonicalInterfacePrefix(link.LocalAddress)
		link.PeerAddress = link.PeerAddress.Unmap()
		if link.WireGuard != nil {
			peer := *link.WireGuard
			link.WireGuard = &peer
		}
		if link.GRE != nil {
			gre := *link.GRE
			gre.UnderlayLocal = gre.UnderlayLocal.Unmap()
			gre.UnderlayRemote = gre.UnderlayRemote.Unmap()
			link.GRE = &gre
		}
	}
	sort.Slice(result.FabricLinks, func(i, j int) bool {
		return result.FabricLinks[i].ID < result.FabricLinks[j].ID
	})
	result.HealthChecks = append([]HealthCheckSpec(nil), s.HealthChecks...)
	for i := range result.HealthChecks {
		result.HealthChecks[i].Endpoint.Address = result.HealthChecks[i].Endpoint.Address.Unmap()
		result.HealthChecks[i].Endpoint.Hostname = ""
	}
	sort.Slice(result.HealthChecks, func(i, j int) bool {
		if result.HealthChecks[i].PoolID == result.HealthChecks[j].PoolID {
			return result.HealthChecks[i].BackendID < result.HealthChecks[j].BackendID
		}
		return result.HealthChecks[i].PoolID < result.HealthChecks[j].PoolID
	})
	result.UserPolicies = append([]UserPolicySpec(nil), s.UserPolicies...)
	sort.Slice(result.UserPolicies, func(i, j int) bool {
		return result.UserPolicies[i].UserID < result.UserPolicies[j].UserID
	})
	result.Forwards = append([]ForwardSpec(nil), s.Forwards...)
	for i := range result.Forwards {
		forward := &result.Forwards[i]
		forward.Protocols = append([]Protocol(nil), forward.Protocols...)
		sort.Slice(forward.Protocols, func(i, j int) bool {
			return forward.Protocols[i] < forward.Protocols[j]
		})
		forward.Listen.Address = forward.Listen.Address.Unmap()
		forward.Listen.Hostname = ""
		forward.Target.Address = forward.Target.Address.Unmap()
		forward.Target.Hostname = ""
		if forward.ServiceVIP != nil {
			value := forward.ServiceVIP.Unmap()
			forward.ServiceVIP = &value
		}
		if forward.SNAT.Address != nil {
			value := forward.SNAT.Address.Unmap()
			forward.SNAT.Address = &value
		}
	}
	sort.Slice(result.Forwards, func(i, j int) bool {
		return result.Forwards[i].ID < result.Forwards[j].ID
	})
	return result
}

func canonicalPrefix(prefix netip.Prefix) netip.Prefix {
	if !prefix.IsValid() {
		return prefix
	}
	address := prefix.Addr().Unmap()
	bits := prefix.Bits()
	if prefix.Addr().Is4In6() {
		bits -= 96
	}
	return netip.PrefixFrom(address, bits).Masked()
}

func canonicalInterfacePrefix(prefix netip.Prefix) netip.Prefix {
	if !prefix.IsValid() {
		return prefix
	}
	address := prefix.Addr().Unmap()
	bits := prefix.Bits()
	if prefix.Addr().Is4In6() {
		bits -= 96
	}
	return netip.PrefixFrom(address, bits)
}

func (s DesiredState) Checksum() (string, error) {
	canonical := s.Canonical()
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
