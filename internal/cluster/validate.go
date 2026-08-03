package cluster

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"flux.local/flux/internal/spec"
)

const (
	maxPlanNodes        = 10_000
	maxPlanBackendPools = 10_000
	maxBackendsPerPool  = 128
)

type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	return "invalid cluster plan: " + strings.Join(e.Issues, "; ")
}

func (p Plan) Validate() error {
	var issues []string
	if p.SchemaVersion != PlanSchemaVersionV1 {
		issues = append(issues, "schema_version must be 1")
	}
	if err := spec.ValidateIdentifier("id", p.ID); err != nil {
		issues = append(issues, err.Error())
	}
	if len(p.ID) > 120 {
		issues = append(issues, "id must not exceed 120 characters so its management domain remains valid")
	}
	if p.Revision == 0 {
		issues = append(issues, "revision must be greater than zero")
	}
	if p.NodeOfflineAfterSeconds < 10 || p.NodeOfflineAfterSeconds > 600 {
		issues = append(issues, "node_offline_after_seconds must be between 10 and 600")
	}
	rollout := p.EffectiveRolloutStrategy()
	canaryPercent := rollout.EffectiveCanaryPercent()
	if canaryPercent < 1 || canaryPercent > 100 {
		issues = append(issues, "rollout.canary_percent must be between 1 and 100, or zero for the 100% default")
	}
	if canaryPercent < 100 {
		if rollout.BakeSeconds < 1 || rollout.BakeSeconds > 86_400 {
			issues = append(issues, "rollout.bake_seconds must be between 1 and 86400 when canary_percent is below 100")
		}
	} else if rollout.BakeSeconds != 0 {
		issues = append(issues, "rollout.bake_seconds requires canary_percent below 100")
	}
	if len(p.Nodes) > maxPlanNodes {
		issues = append(issues, fmt.Sprintf("nodes must not exceed %d entries", maxPlanNodes))
	}
	if len(p.BackendPools) > maxPlanBackendPools {
		issues = append(issues, fmt.Sprintf("backend_pools must not exceed %d entries", maxPlanBackendPools))
	} else if len(p.BackendPools) == 0 && len(p.Forwards) != 0 {
		issues = append(issues, "backend_pools must not be empty when forwards are configured")
	}
	if len(p.Forwards) > spec.MaxForwardsPerSnapshot {
		issues = append(issues, fmt.Sprintf("forwards exceeds limit %d", spec.MaxForwardsPerSnapshot))
	}

	serviceCIDRs := make([]netip.Prefix, 0, len(p.ServiceCIDRs))
	for i, prefix := range p.ServiceCIDRs {
		name := fmt.Sprintf("service_cidrs[%d]", i)
		if !validIPv4Prefix(prefix) {
			issues = append(issues, name+" must be a masked IPv4 prefix")
			continue
		}
		prefix = prefix.Masked()
		for j, existing := range serviceCIDRs {
			if prefixesOverlap(prefix, existing) {
				issues = append(issues, fmt.Sprintf("%s overlaps service_cidrs[%d]", name, j))
			}
		}
		serviceCIDRs = append(serviceCIDRs, prefix)
	}

	nodes := make(map[string]Node, len(p.Nodes))
	for i, node := range p.Nodes {
		name := fmt.Sprintf("nodes[%d]", i)
		if err := spec.ValidateIdentifier(name+".id", node.ID); err != nil {
			issues = append(issues, err.Error())
		} else if _, exists := nodes[node.ID]; exists {
			issues = append(issues, name+".id is duplicated")
		} else {
			nodes[node.ID] = node
		}
		if err := spec.ValidateIdentifier(name+".failure_domain", node.FailureDomain); err != nil {
			issues = append(issues, err.Error())
		}
		if node.Capacity.MaxForwards == 0 || node.Capacity.MaxForwards > spec.MaxForwardsPerSnapshot {
			issues = append(issues, fmt.Sprintf("%s.capacity.max_forwards must be between 1 and %d", name, spec.MaxForwardsPerSnapshot))
		}
		seenRoles := make(map[NodeRole]struct{}, len(node.Roles))
		if len(node.Roles) == 0 {
			issues = append(issues, name+".roles must not be empty")
		}
		for _, role := range node.Roles {
			if role != RoleIngress && role != RoleExit {
				issues = append(issues, name+".roles contains an unsupported value")
			}
			if _, exists := seenRoles[role]; exists {
				issues = append(issues, name+".roles contains a duplicate")
			}
			seenRoles[role] = struct{}{}
		}
		if len(node.Labels) > 64 {
			issues = append(issues, name+".labels exceeds 64 entries")
		}
		for key, value := range node.Labels {
			if err := spec.ValidateIdentifier(name+".labels key", key); err != nil {
				issues = append(issues, err.Error())
			}
			if err := spec.ValidateIdentifier(name+".labels value", value); err != nil {
				issues = append(issues, err.Error())
			}
		}
		if len(node.ListenIPs) > 64 {
			issues = append(issues, name+".listen_ips exceeds 64 entries")
		}
		seenListenIPs := make(map[netip.Addr]struct{}, len(node.ListenIPs))
		for j, address := range node.ListenIPs {
			address = address.Unmap()
			if !validIPv4Address(address) {
				issues = append(issues, fmt.Sprintf("%s.listen_ips[%d] is not a usable IPv4 address", name, j))
				continue
			}
			if _, exists := seenListenIPs[address]; exists {
				issues = append(issues, name+".listen_ips contains a duplicate")
			}
			seenListenIPs[address] = struct{}{}
		}
		seenLinks := make(map[string]struct{}, len(node.FabricLinks))
		seenRouting := make(map[uint16]struct{}, len(node.FabricLinks))
		for j, link := range node.FabricLinks {
			linkName := fmt.Sprintf("%s.fabric_links[%d]", name, j)
			if err := spec.ValidateIdentifier(linkName+".id", link.ID); err != nil {
				issues = append(issues, err.Error())
			} else if _, exists := seenLinks[link.ID]; exists {
				issues = append(issues, linkName+".id is duplicated")
			} else {
				seenLinks[link.ID] = struct{}{}
			}
			if err := spec.ValidateIdentifier(linkName+".peer_node_id", link.PeerNodeID); err != nil || link.PeerNodeID == node.ID {
				issues = append(issues, linkName+".peer_node_id is invalid")
			}
			if len(link.Interface) == 0 || len(link.Interface) > 15 {
				issues = append(issues, linkName+".interface is invalid")
			}
			if !validIPv4InterfacePrefix(link.LocalAddress) || !validIPv4Address(link.PeerAddress) || !link.LocalAddress.Masked().Contains(link.PeerAddress.Unmap()) || link.LocalAddress.Addr().Unmap() == link.PeerAddress.Unmap() {
				issues = append(issues, linkName+" has an invalid local/peer address pair")
			}
			if link.MTU < 1280 || link.MTU > 9000 {
				issues = append(issues, linkName+".mtu must be between 1280 and 9000")
			}
			if link.RoutingID == 0 || link.RoutingID == 65535 {
				issues = append(issues, linkName+".routing_id is reserved")
			} else if _, exists := seenRouting[link.RoutingID]; exists {
				issues = append(issues, linkName+".routing_id is duplicated")
			} else {
				seenRouting[link.RoutingID] = struct{}{}
			}
			if link.ResourceVersion == 0 {
				issues = append(issues, linkName+".resource_version must be greater than zero")
			}
			switch link.Transport {
			case spec.FabricWireGuard:
				if link.WireGuard == nil || link.WireGuard.Endpoint == "" || link.WireGuard.ListenPort == 0 || link.GRE != nil {
					issues = append(issues, linkName+" wireguard settings are incomplete")
				}
			case spec.FabricDirectL3:
				if !link.Trusted || link.WireGuard != nil || link.GRE != nil {
					issues = append(issues, linkName+" direct_l3 requires trusted=true and no encapsulation settings")
				}
			case spec.FabricGRE:
				if !link.Trusted || link.GRE == nil || link.WireGuard != nil {
					issues = append(issues, linkName+" gre requires trusted=true and GRE settings")
				}
			default:
				issues = append(issues, linkName+".transport is unsupported")
			}
		}
	}
	for _, node := range p.Nodes {
		for _, link := range node.FabricLinks {
			peer, exists := nodes[link.PeerNodeID]
			if !exists {
				issues = append(issues, fmt.Sprintf("node %s fabric %s references an unknown peer", node.ID, link.ID))
				continue
			}
			if _, _, exists := matchingLinks(node, peer); !exists {
				issues = append(issues, fmt.Sprintf("node %s fabric %s has no reciprocal peer link", node.ID, link.ID))
			}
		}
	}
	dummyRuntimes := make(map[string]NodeRuntime, len(nodes))
	for nodeID := range nodes {
		dummyRuntimes[nodeID] = NodeRuntime{ID: nodeID, WireGuardPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}
	}
	for _, node := range p.Nodes {
		state := spec.DesiredState{SchemaVersion: spec.CurrentSchemaVersion, NodeID: node.ID, Generation: 1, ServiceCIDRs: p.ServiceCIDRs}
		for _, link := range node.FabricLinks {
			compiled, err := compileLink(link, dummyRuntimes)
			if err != nil {
				issues = append(issues, fmt.Sprintf("node %s fabric %s is invalid: %v", node.ID, link.ID, err))
				continue
			}
			state.FabricLinks = append(state.FabricLinks, compiled)
		}
		if err := state.Validate(); err != nil {
			issues = append(issues, fmt.Sprintf("node %s fabric template is invalid: %v", node.ID, err))
		}
	}

	pools := make(map[string]BackendPool, len(p.BackendPools))
	for i, pool := range p.BackendPools {
		name := fmt.Sprintf("backend_pools[%d]", i)
		if err := spec.ValidateIdentifier(name+".id", pool.ID); err != nil {
			issues = append(issues, err.Error())
		} else if _, exists := pools[pool.ID]; exists {
			issues = append(issues, name+".id is duplicated")
		} else {
			pools[pool.ID] = pool
		}
		if pool.ResourceVersion == 0 {
			issues = append(issues, name+".resource_version must be greater than zero")
		}
		if len(pool.Backends) == 0 || len(pool.Backends) > maxBackendsPerPool {
			issues = append(issues, fmt.Sprintf("%s.backends must contain between 1 and %d entries", name, maxBackendsPerPool))
		}
		seenBackends := make(map[string]struct{}, len(pool.Backends))
		for j, backend := range pool.Backends {
			backendName := fmt.Sprintf("%s.backends[%d]", name, j)
			if err := spec.ValidateIdentifier(backendName+".id", backend.ID); err != nil {
				issues = append(issues, err.Error())
			} else if _, exists := seenBackends[backend.ID]; exists {
				issues = append(issues, backendName+".id is duplicated")
			} else {
				seenBackends[backend.ID] = struct{}{}
			}
			if !validTargetEndpoint(backend.Target) {
				issues = append(issues, backendName+".target is invalid")
			}
			if backend.ProbeEndpoint != nil && !validTargetEndpoint(*backend.ProbeEndpoint) {
				issues = append(issues, backendName+".probe_endpoint is invalid")
			}
			if backend.ResourceVersion == 0 {
				issues = append(issues, backendName+".resource_version must be greater than zero")
			}
		}
		if health := pool.Health; health != nil {
			if health.IntervalSeconds < 1 || health.IntervalSeconds > 300 || health.TimeoutMilliseconds < 100 || health.TimeoutMilliseconds > 30_000 || uint32(health.TimeoutMilliseconds) > uint32(health.IntervalSeconds)*1_000 {
				issues = append(issues, name+".health interval or timeout is invalid")
			}
			if health.FailureThreshold < 1 || health.FailureThreshold > 10 || health.SuccessThreshold < 1 || health.SuccessThreshold > 10 {
				issues = append(issues, name+".health thresholds must be between 1 and 10")
			}
			if health.StaleAfterSeconds < health.IntervalSeconds || health.StaleAfterSeconds > 3600 {
				issues = append(issues, name+".health.stale_after_seconds must be at least one interval and at most 3600")
			}
		}
	}

	for i, policy := range p.UserPolicies {
		if policy.TrafficClassID != 0 {
			issues = append(issues, fmt.Sprintf("user_policies[%d].traffic_class_id must be zero; Controller allocates it", i))
		}
	}
	if len(p.UserPolicies) != 0 {
		policyNodeID := "policy-validation"
		if len(p.Nodes) != 0 {
			policyNodeID = p.Nodes[0].ID
		}
		policyState := spec.DesiredState{SchemaVersion: spec.CurrentSchemaVersion, NodeID: policyNodeID, Generation: 1, UserPolicies: p.UserPolicies}
		if err := policyState.Validate(); err != nil {
			issues = append(issues, "user_policies are invalid: "+err.Error())
		}
	}
	forwardIDs := make(map[string]struct{}, len(p.Forwards))
	listeners := make(map[string]string, len(p.Forwards)*2)
	for i, forward := range p.Forwards {
		name := fmt.Sprintf("forwards[%d]", i)
		if err := spec.ValidateIdentifier(name+".id", forward.ID); err != nil {
			issues = append(issues, err.Error())
		} else if _, exists := forwardIDs[forward.ID]; exists {
			issues = append(issues, name+".id is duplicated")
		} else {
			forwardIDs[forward.ID] = struct{}{}
		}
		if err := spec.ValidateIdentifier(name+".user_id", forward.UserID); err != nil {
			issues = append(issues, err.Error())
		}
		if _, exists := pools[forward.BackendPoolID]; !exists {
			issues = append(issues, name+".backend_pool_id does not exist")
		}
		if !validListenEndpoint(forward.Listen) {
			issues = append(issues, name+".listen is invalid")
		}
		seenProtocols := make(map[spec.Protocol]struct{}, len(forward.Protocols))
		if len(forward.Protocols) == 0 {
			issues = append(issues, name+".protocols must not be empty")
		}
		for _, protocol := range forward.Protocols {
			if protocol != spec.ProtocolTCP && protocol != spec.ProtocolUDP {
				issues = append(issues, name+".protocols contains an unsupported value")
			}
			if _, exists := seenProtocols[protocol]; exists {
				issues = append(issues, name+".protocols contains a duplicate")
			}
			seenProtocols[protocol] = struct{}{}
			key := forward.Listen.Address.Unmap().String() + "/" + string(protocol) + fmt.Sprintf("/%d", forward.Listen.Port)
			if owner, exists := listeners[key]; exists {
				issues = append(issues, fmt.Sprintf("%s listener conflicts with forward %s", name, owner))
			} else {
				listeners[key] = forward.ID
			}
		}
		issues = append(issues, validateSelector(name+".ingress", forward.Ingress, nodes, RoleIngress)...)
		switch forward.PathMode {
		case spec.PathDirect:
			if forward.Exit != nil {
				issues = append(issues, name+".exit must be empty for direct path")
			}
		case spec.PathViaExit:
			if forward.Exit == nil {
				issues = append(issues, name+".exit is required for via_exit path")
			} else {
				issues = append(issues, validateSelector(name+".exit", *forward.Exit, nodes, RoleExit)...)
			}
			policy := effectiveFailurePolicy(forward.FailureDomainPolicy)
			if policy != FailureDomainDistinct && policy != FailureDomainPrefer && policy != FailureDomainAny {
				issues = append(issues, name+".failure_domain_policy is unsupported")
			}
			if len(serviceCIDRs) == 0 {
				issues = append(issues, name+" via_exit requires service_cidrs")
			}
			if pool, exists := pools[forward.BackendPoolID]; exists && len(pool.Backends) != 0 {
				servicePort := pool.Backends[0].Target.Port
				for _, backend := range pool.Backends[1:] {
					if backend.Target.Port != servicePort {
						issues = append(issues, name+" via_exit backend pool must use one stable target port for safe exit-first rollout")
						break
					}
				}
			}
		default:
			issues = append(issues, name+".path_mode is unsupported")
		}
		if forward.ResourceVersion == 0 {
			issues = append(issues, name+".resource_version must be greater than zero")
		}
		if forward.RateLimit != nil && forward.RateLimit.IngressBitsPerSecond == 0 && forward.RateLimit.EgressBitsPerSecond == 0 || forward.RateLimit != nil && forward.RateLimit.BurstBytes == 0 {
			issues = append(issues, name+".rate_limit is invalid")
		}
		if forward.TrafficQuota != nil && (forward.TrafficQuota.Bytes == 0 || forward.TrafficQuota.Policy != spec.QuotaPolicyPause) {
			issues = append(issues, name+".traffic_quota is invalid")
		}
		if forward.Reservation.IngressBitsPerSecond == 0 && forward.RateLimit != nil {
			forward.Reservation.IngressBitsPerSecond = forward.RateLimit.IngressBitsPerSecond
		}
		if forward.Reservation.EgressBitsPerSecond == 0 && forward.RateLimit != nil {
			forward.Reservation.EgressBitsPerSecond = forward.RateLimit.EgressBitsPerSecond
		}
		if forward.Lifecycle != spec.LifecycleActive && forward.Lifecycle != spec.LifecyclePaused && forward.Lifecycle != spec.LifecycleDraining && forward.Lifecycle != spec.LifecycleForceDeleting {
			issues = append(issues, name+".lifecycle is unsupported")
		}
		if forward.Lifecycle == spec.LifecycleDraining && (forward.DrainDeadline == nil || forward.DrainDeadline.IsZero()) || forward.Lifecycle != spec.LifecycleDraining && forward.DrainDeadline != nil {
			issues = append(issues, name+".drain_deadline does not match lifecycle")
		}
		if forward.ExpiresAt != nil && forward.ExpiresAt.IsZero() {
			issues = append(issues, name+".expires_at must not be zero")
		}
		switch forward.SNAT.Mode {
		case spec.SNATMasquerade:
			if forward.SNAT.Address != nil {
				issues = append(issues, name+".snat.address must be empty for masquerade")
			}
		case spec.SNATStatic:
			if forward.SNAT.Address == nil || !validIPv4Address(*forward.SNAT.Address) {
				issues = append(issues, name+".snat.address is required and must be IPv4 for static mode")
			}
		default:
			issues = append(issues, name+".snat.mode is unsupported")
		}
	}
	if len(issues) != 0 {
		sort.Strings(issues)
		return &ValidationError{Issues: issues}
	}
	return nil
}

func validateSelector(name string, selector NodeSelector, nodes map[string]Node, role NodeRole) []string {
	var issues []string
	if len(selector.NodeIDs) == 0 && len(selector.MatchLabels) == 0 {
		return []string{name + " must constrain node_ids or match_labels"}
	}
	seen := make(map[string]struct{}, len(selector.NodeIDs))
	for _, nodeID := range selector.NodeIDs {
		if _, exists := seen[nodeID]; exists {
			issues = append(issues, name+".node_ids contains a duplicate")
		}
		seen[nodeID] = struct{}{}
		if _, exists := nodes[nodeID]; !exists {
			issues = append(issues, name+".node_ids references an unknown node")
		}
	}
	for key, value := range selector.MatchLabels {
		if spec.ValidateIdentifier(name+".match_labels key", key) != nil || spec.ValidateIdentifier(name+".match_labels value", value) != nil {
			issues = append(issues, name+".match_labels contains an invalid key or value")
		}
	}
	matched := false
	for _, node := range nodes {
		if selectorMatches(selector, node) && nodeHasRole(node, role) {
			matched = true
			break
		}
	}
	if !matched {
		issues = append(issues, name+" matches no node with the required role")
	}
	return issues
}

func validListenEndpoint(endpoint spec.Endpoint) bool {
	return endpoint.Hostname == "" && validIPv4Address(endpoint.Address) && endpoint.Port != 0
}

func validTargetEndpoint(endpoint spec.Endpoint) bool {
	if !validIPv4Address(endpoint.Address) || endpoint.Port == 0 {
		return false
	}
	if endpoint.Hostname == "" {
		return true
	}
	_, err := spec.NormalizeHostname(endpoint.Hostname)
	return err == nil
}

func validIPv4Address(address netip.Addr) bool {
	return address.IsValid() && address.Unmap().Is4() && !address.Unmap().IsUnspecified() && !address.Unmap().IsMulticast()
}

func validIPv4Prefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix.Addr().Is4() && prefix.Bits() >= 0 && prefix.Bits() <= 32 && prefix == prefix.Masked()
}

func validIPv4InterfacePrefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix.Addr().Is4() && prefix.Bits() >= 1 && prefix.Bits() <= 32
}

func prefixesOverlap(first, second netip.Prefix) bool {
	return first.Contains(second.Addr()) || second.Contains(first.Addr())
}

func effectiveFailurePolicy(policy FailureDomainPolicy) FailureDomainPolicy {
	if policy == "" {
		return FailureDomainDistinct
	}
	return policy
}
