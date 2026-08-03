package control

import (
	"testing"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/spec"
)

func TestRequiredCapabilitiesFollowFabricAndIngressOwnership(t *testing.T) {
	desired := fabricCapabilityState()
	desired.HealthChecks = []spec.HealthCheckSpec{{PoolID: "pool-a", BackendID: "backend-a"}}
	desired.ProtocolBlocks = &spec.ProtocolBlockPolicy{TLS: true}
	capabilities := capabilityMap(RequiredCapabilities(desired))
	for _, name := range []string{"nft.via-exit", "fabric.policy-routing", "fabric.mss-clamp", "fabric.wireguard", "health.tcp-connect", "nft.protocol-block"} {
		if capabilities[name] == 0 {
			t.Fatalf("missing capability %s: %+v", name, capabilities)
		}
	}
	if capabilities["tc.rate-limit"] == 0 || capabilities["usage.l3"] == 0 {
		t.Fatalf("ingress policy capabilities are missing: %+v", capabilities)
	}

	desired.NodeID = "node-b"
	capabilities = capabilityMap(RequiredCapabilities(desired))
	if capabilities["tc.rate-limit"] != 0 || capabilities["usage.l3"] != 0 {
		t.Fatalf("exit node should not duplicate ingress shaping or billing: %+v", capabilities)
	}
}

func TestDefaultCapabilitiesAdvertiseInteractiveDiagnosticsAndMaintenance(t *testing.T) {
	capabilities := capabilityMap(DefaultCapabilities())
	for _, name := range []string{"diagnostics.tcp-connect", "agent.maintenance"} {
		if capabilities[name] != 1 {
			t.Fatalf("capability %s=%d", name, capabilities[name])
		}
	}
}

func fabricCapabilityState() spec.DesiredState {
	return spec.DesiredState{
		SchemaVersion: spec.SchemaVersionV3,
		NodeID:        "node-a",
		FabricLinks:   []spec.FabricLinkSpec{{Transport: spec.FabricWireGuard}},
		UserPolicies: []spec.UserPolicySpec{{
			UserID: "user-a", RateLimit: &spec.RateLimitSpec{IngressBitsPerSecond: 1, BurstBytes: 1},
			TrafficQuota: &spec.TrafficQuotaSpec{Bytes: 1, Policy: spec.QuotaPolicyPause},
		}},
		Forwards: []spec.ForwardSpec{{
			UserID: "user-a", IngressNodeID: "node-a", PathMode: spec.PathViaExit,
		}},
	}
}

func capabilityMap(capabilities []*controlv1.Capability) map[string]uint32 {
	result := make(map[string]uint32, len(capabilities))
	for _, capability := range capabilities {
		result[capability.Name] = capability.Version
	}
	return result
}
