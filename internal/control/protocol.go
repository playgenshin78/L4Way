package control

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"sort"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/spec"
)

const (
	ProtocolVersion uint32 = 1
)

var AgentVersion = "dev"

var checksumPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func DefaultCapabilities() []*controlv1.Capability {
	return []*controlv1.Capability{
		{Name: "nft.direct", Version: 2},
		{Name: "nft.via-exit", Version: 1},
		{Name: "nft.static-snat", Version: 1},
		{Name: "nft.directional-counters", Version: 1},
		{Name: "nft.drain", Version: 1},
		{Name: "nft.force-delete", Version: 1},
		{Name: "policy.local-deadline", Version: 1},
		{Name: "tc.rate-limit", Version: 1},
		{Name: "usage.l3", Version: 1},
		{Name: "fabric.policy-routing", Version: 1},
		{Name: "fabric.wireguard", Version: 1},
		{Name: "fabric.direct-l3", Version: 1},
		{Name: "fabric.gre", Version: 1},
		{Name: "fabric.mss-clamp", Version: 1},
		{Name: "health.tcp-connect", Version: 1},
		{Name: "nft.protocol-block", Version: 1},
		{Name: "diagnostics.tcp-connect", Version: 1},
		{Name: "agent.maintenance", Version: 1},
	}
}

func RequiredCapabilities(desired spec.DesiredState) []*controlv1.Capability {
	required := map[string]uint32{}
	if desired.ProtocolBlocks != nil && desired.ProtocolBlocks.Any() {
		required["nft.protocol-block"] = 1
	}
	ingressUsers := make(map[string]struct{})
	for _, forward := range desired.Forwards {
		isIngress := forward.IngressNodeID == desired.NodeID
		if isIngress {
			ingressUsers[forward.UserID] = struct{}{}
		}
		switch forward.PathMode {
		case spec.PathDirect:
			if desired.SchemaVersion >= spec.SchemaVersionV2 {
				required["nft.direct"] = 2
			} else {
				required["nft.direct"] = 1
			}
		case spec.PathViaExit:
			required["nft.via-exit"] = 1
		}
		if forward.SNAT.Mode == spec.SNATStatic {
			required["nft.static-snat"] = 1
		}
		if isIngress && forward.RateLimit != nil {
			required["tc.rate-limit"] = 1
		}
		if isIngress && forward.TrafficQuota != nil {
			required["usage.l3"] = 1
			required["nft.directional-counters"] = 1
		}
		if forward.ExpiresAt != nil || forward.DrainDeadline != nil {
			required["policy.local-deadline"] = 1
		}
		if forward.Lifecycle == spec.LifecycleDraining {
			required["nft.drain"] = 1
		}
		if forward.Lifecycle == spec.LifecycleForceDeleting {
			required["nft.force-delete"] = 1
		}
	}
	for _, policy := range desired.UserPolicies {
		_, usedAtIngress := ingressUsers[policy.UserID]
		if usedAtIngress && policy.RateLimit != nil {
			required["tc.rate-limit"] = 1
		}
		if usedAtIngress && policy.TrafficQuota != nil {
			required["usage.l3"] = 1
			required["nft.directional-counters"] = 1
		}
	}
	for _, link := range desired.FabricLinks {
		required["fabric.policy-routing"] = 1
		required["fabric.mss-clamp"] = 1
		switch link.Transport {
		case spec.FabricWireGuard:
			required["fabric.wireguard"] = 1
		case spec.FabricDirectL3:
			required["fabric.direct-l3"] = 1
		case spec.FabricGRE:
			required["fabric.gre"] = 1
		}
	}
	if len(desired.HealthChecks) != 0 {
		required["health.tcp-connect"] = 1
	}
	result := make([]*controlv1.Capability, 0, len(required))
	for name, version := range required {
		result = append(result, &controlv1.Capability{Name: name, Version: version})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func ValidateCapabilities(capabilities []*controlv1.Capability) error {
	seen := make(map[string]uint32, len(capabilities))
	for _, capability := range capabilities {
		if capability == nil {
			return errors.New("capability must not be nil")
		}
		if err := spec.ValidateIdentifier("capability.name", capability.Name); err != nil {
			return err
		}
		if capability.Version == 0 {
			return fmt.Errorf("capability %s version must be greater than zero", capability.Name)
		}
		if _, exists := seen[capability.Name]; exists {
			return fmt.Errorf("capability %s is duplicated", capability.Name)
		}
		seen[capability.Name] = capability.Version
	}
	return nil
}

func MissingCapabilities(supported, required []*controlv1.Capability) []string {
	available := make(map[string]uint32, len(supported))
	for _, capability := range supported {
		if capability != nil && capability.Version > available[capability.Name] {
			available[capability.Name] = capability.Version
		}
	}
	var missing []string
	for _, capability := range required {
		if capability == nil || available[capability.Name] < capability.Version {
			if capability == nil {
				missing = append(missing, "<nil>")
			} else {
				missing = append(missing, fmt.Sprintf("%s@%d", capability.Name, capability.Version))
			}
		}
	}
	sort.Strings(missing)
	return missing
}

func ValidChecksum(value string) bool {
	return checksumPattern.MatchString(value)
}

func SessionNonce() ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate session nonce: %w", err)
	}
	return nonce, nil
}
