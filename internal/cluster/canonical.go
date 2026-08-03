package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"

	"flux.local/flux/internal/spec"
)

func (p Plan) Canonical() Plan {
	result := p
	rollout := p.EffectiveRolloutStrategy()
	if rollout.EffectiveCanaryPercent() == 100 {
		rollout.CanaryPercent = 0
	}
	if rollout == (RolloutStrategy{}) {
		result.Rollout = nil
	} else {
		result.Rollout = &rollout
	}
	result.ServiceCIDRs = append([]netip.Prefix(nil), p.ServiceCIDRs...)
	for i := range result.ServiceCIDRs {
		result.ServiceCIDRs[i] = result.ServiceCIDRs[i].Masked()
	}
	sort.Slice(result.ServiceCIDRs, func(i, j int) bool { return result.ServiceCIDRs[i].String() < result.ServiceCIDRs[j].String() })
	result.Nodes = append([]Node(nil), p.Nodes...)
	for i := range result.Nodes {
		node := &result.Nodes[i]
		if node.ProtocolBlocks != nil && node.ProtocolBlocks.Any() {
			policy := *node.ProtocolBlocks
			node.ProtocolBlocks = &policy
		} else {
			node.ProtocolBlocks = nil
		}
		node.Roles = append([]NodeRole(nil), node.Roles...)
		sort.Slice(node.Roles, func(i, j int) bool { return node.Roles[i] < node.Roles[j] })
		node.Labels = cloneLabels(node.Labels)
		node.ListenIPs = append([]netip.Addr(nil), node.ListenIPs...)
		for addressIndex := range node.ListenIPs {
			node.ListenIPs[addressIndex] = node.ListenIPs[addressIndex].Unmap()
		}
		sort.Slice(node.ListenIPs, func(i, j int) bool { return node.ListenIPs[i].Less(node.ListenIPs[j]) })
		node.FabricLinks = append([]FabricLink(nil), node.FabricLinks...)
		sort.Slice(node.FabricLinks, func(i, j int) bool { return node.FabricLinks[i].ID < node.FabricLinks[j].ID })
	}
	sort.Slice(result.Nodes, func(i, j int) bool { return result.Nodes[i].ID < result.Nodes[j].ID })
	result.UserPolicies = append([]spec.UserPolicySpec(nil), p.UserPolicies...)
	sort.Slice(result.UserPolicies, func(i, j int) bool { return result.UserPolicies[i].UserID < result.UserPolicies[j].UserID })
	result.BackendPools = append([]BackendPool(nil), p.BackendPools...)
	for i := range result.BackendPools {
		pool := &result.BackendPools[i]
		pool.Backends = append([]Backend(nil), pool.Backends...)
		for backendIndex := range pool.Backends {
			backend := &pool.Backends[backendIndex]
			backend.Target = canonicalTargetEndpoint(backend.Target)
			if backend.ProbeEndpoint != nil {
				probe := canonicalTargetEndpoint(*backend.ProbeEndpoint)
				backend.ProbeEndpoint = &probe
			}
		}
		sort.Slice(pool.Backends, func(i, j int) bool {
			if pool.Backends[i].Priority == pool.Backends[j].Priority {
				return pool.Backends[i].ID < pool.Backends[j].ID
			}
			return pool.Backends[i].Priority < pool.Backends[j].Priority
		})
	}
	sort.Slice(result.BackendPools, func(i, j int) bool { return result.BackendPools[i].ID < result.BackendPools[j].ID })
	result.Forwards = append([]Forward(nil), p.Forwards...)
	for i := range result.Forwards {
		forward := &result.Forwards[i]
		forward.Protocols = append([]spec.Protocol(nil), forward.Protocols...)
		sort.Slice(forward.Protocols, func(i, j int) bool { return forward.Protocols[i] < forward.Protocols[j] })
		forward.Ingress = canonicalSelector(forward.Ingress)
		if forward.Exit != nil {
			exit := canonicalSelector(*forward.Exit)
			forward.Exit = &exit
		}
		if forward.PathMode == spec.PathViaExit {
			forward.FailureDomainPolicy = effectiveFailurePolicy(forward.FailureDomainPolicy)
		}
	}
	sort.Slice(result.Forwards, func(i, j int) bool { return result.Forwards[i].ID < result.Forwards[j].ID })
	return result
}

func canonicalTargetEndpoint(endpoint spec.Endpoint) spec.Endpoint {
	endpoint.Address = endpoint.Address.Unmap()
	if endpoint.Hostname != "" {
		if hostname, err := spec.NormalizeHostname(endpoint.Hostname); err == nil {
			endpoint.Hostname = hostname
		}
	}
	return endpoint
}

func (p Plan) Checksum() (string, error) {
	encoded, err := json.Marshal(p.Canonical())
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalSelector(selector NodeSelector) NodeSelector {
	selector.NodeIDs = append([]string(nil), selector.NodeIDs...)
	sort.Strings(selector.NodeIDs)
	selector.MatchLabels = cloneLabels(selector.MatchLabels)
	return selector
}

func cloneLabels(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
