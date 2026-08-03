package cluster

import (
	"net/netip"
	"time"

	"flux.local/flux/internal/health"
	"flux.local/flux/internal/spec"
)

const PlanSchemaVersionV1 uint32 = 1

type NodeRole string

const (
	RoleIngress NodeRole = "ingress"
	RoleExit    NodeRole = "exit"
)

type FailureDomainPolicy string

const (
	FailureDomainDistinct FailureDomainPolicy = "distinct"
	FailureDomainPrefer   FailureDomainPolicy = "prefer_distinct"
	FailureDomainAny      FailureDomainPolicy = "any"
)

type Capacity struct {
	MaxForwards          uint32 `json:"max_forwards"`
	IngressBitsPerSecond uint64 `json:"ingress_bits_per_second,omitempty"`
	EgressBitsPerSecond  uint64 `json:"egress_bits_per_second,omitempty"`
}

type Reservation struct {
	IngressBitsPerSecond uint64 `json:"ingress_bits_per_second,omitempty"`
	EgressBitsPerSecond  uint64 `json:"egress_bits_per_second,omitempty"`
}

// RolloutStrategy controls Controller-side publication ordering. A zero
// CanaryPercent means 100% for backwards-compatible plans. Failed stages
// always use automatic compensation; this is not a per-plan safety toggle.
type RolloutStrategy struct {
	CanaryPercent uint8  `json:"canary_percent,omitempty"`
	BakeSeconds   uint32 `json:"bake_seconds,omitempty"`
}

func (s RolloutStrategy) EffectiveCanaryPercent() uint8 {
	if s.CanaryPercent == 0 {
		return 100
	}
	return s.CanaryPercent
}

func (p Plan) EffectiveRolloutStrategy() RolloutStrategy {
	if p.Rollout == nil {
		return RolloutStrategy{}
	}
	return *p.Rollout
}

type NodeSelector struct {
	NodeIDs     []string          `json:"node_ids,omitempty"`
	MatchLabels map[string]string `json:"match_labels,omitempty"`
}

type WireGuardLink struct {
	Endpoint                   string `json:"endpoint"`
	ListenPort                 uint16 `json:"listen_port"`
	PersistentKeepaliveSeconds uint16 `json:"persistent_keepalive_seconds,omitempty"`
}

type FabricLink struct {
	ID              string               `json:"id"`
	PeerNodeID      string               `json:"peer_node_id"`
	Transport       spec.FabricTransport `json:"transport"`
	Interface       string               `json:"interface"`
	LocalAddress    netip.Prefix         `json:"local_address"`
	PeerAddress     netip.Addr           `json:"peer_address"`
	MTU             uint16               `json:"mtu"`
	RoutingID       uint16               `json:"routing_id"`
	Trusted         bool                 `json:"trusted,omitempty"`
	WireGuard       *WireGuardLink       `json:"wireguard,omitempty"`
	GRE             *spec.GRESpec        `json:"gre,omitempty"`
	ResourceVersion uint64               `json:"resource_version"`
}

type Node struct {
	ID             string                    `json:"id"`
	Enabled        bool                      `json:"enabled"`
	Roles          []NodeRole                `json:"roles"`
	Labels         map[string]string         `json:"labels,omitempty"`
	ListenIPs      []netip.Addr              `json:"listen_ips,omitempty"`
	FailureDomain  string                    `json:"failure_domain"`
	Capacity       Capacity                  `json:"capacity"`
	FabricLinks    []FabricLink              `json:"fabric_links,omitempty"`
	ProtocolBlocks *spec.ProtocolBlockPolicy `json:"protocol_blocks,omitempty"`
}

type HealthPolicy struct {
	IntervalSeconds     uint16 `json:"interval_seconds"`
	TimeoutMilliseconds uint16 `json:"timeout_milliseconds"`
	FailureThreshold    uint8  `json:"failure_threshold"`
	SuccessThreshold    uint8  `json:"success_threshold"`
	StaleAfterSeconds   uint16 `json:"stale_after_seconds"`
}

type Backend struct {
	ID              string         `json:"id"`
	Target          spec.Endpoint  `json:"target"`
	ProbeEndpoint   *spec.Endpoint `json:"probe_endpoint,omitempty"`
	Priority        uint16         `json:"priority"`
	ResourceVersion uint64         `json:"resource_version"`
}

type BackendPool struct {
	ID              string        `json:"id"`
	Backends        []Backend     `json:"backends"`
	Health          *HealthPolicy `json:"health,omitempty"`
	ResourceVersion uint64        `json:"resource_version"`
}

type Forward struct {
	ID                  string                 `json:"id"`
	UserID              string                 `json:"user_id"`
	Protocols           []spec.Protocol        `json:"protocols"`
	Listen              spec.Endpoint          `json:"listen"`
	PathMode            spec.PathMode          `json:"path_mode"`
	Ingress             NodeSelector           `json:"ingress"`
	Exit                *NodeSelector          `json:"exit,omitempty"`
	FailureDomainPolicy FailureDomainPolicy    `json:"failure_domain_policy,omitempty"`
	BackendPoolID       string                 `json:"backend_pool_id"`
	SNAT                spec.SNATSpec          `json:"snat"`
	Reservation         Reservation            `json:"reservation,omitempty"`
	RateLimit           *spec.RateLimitSpec    `json:"rate_limit,omitempty"`
	TrafficQuota        *spec.TrafficQuotaSpec `json:"traffic_quota,omitempty"`
	ExpiresAt           *time.Time             `json:"expires_at,omitempty"`
	DrainDeadline       *time.Time             `json:"drain_deadline,omitempty"`
	Lifecycle           spec.Lifecycle         `json:"lifecycle"`
	ResourceVersion     uint64                 `json:"resource_version"`
}

type Plan struct {
	SchemaVersion           uint32                `json:"schema_version"`
	ID                      string                `json:"id"`
	Revision                uint64                `json:"revision"`
	NodeOfflineAfterSeconds uint16                `json:"node_offline_after_seconds"`
	Rollout                 *RolloutStrategy      `json:"rollout,omitempty"`
	ServiceCIDRs            []netip.Prefix        `json:"service_cidrs,omitempty"`
	Nodes                   []Node                `json:"nodes"`
	UserPolicies            []spec.UserPolicySpec `json:"user_policies,omitempty"`
	BackendPools            []BackendPool         `json:"backend_pools"`
	Forwards                []Forward             `json:"forwards"`
}

type NodeRuntime struct {
	ID                 string
	Available          bool
	LastSeen           time.Time
	Capabilities       map[string]uint32
	WireGuardPublicKey string
}

type HealthKey struct {
	NodeID    string
	PoolID    string
	BackendID string
}

type HealthObservation struct {
	Status          health.Status
	ResourceVersion uint64
	ObservedAt      time.Time
}

type Placement struct {
	ForwardID   string        `json:"forward_id"`
	IngressID   string        `json:"ingress_node_id"`
	ExitID      string        `json:"exit_node_id,omitempty"`
	BackendID   string        `json:"backend_id"`
	Target      spec.Endpoint `json:"target"`
	PathMode    spec.PathMode `json:"path_mode"`
	FabricInID  string        `json:"fabric_in_id,omitempty"`
	FabricOutID string        `json:"fabric_out_id,omitempty"`
}

type Alert struct {
	Code      string `json:"code"`
	ForwardID string `json:"forward_id"`
	PoolID    string `json:"pool_id"`
	Detail    string `json:"detail"`
}

type Result struct {
	Placements []Placement
	Alerts     []Alert
}
