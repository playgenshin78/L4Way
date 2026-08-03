package spec

import (
	"net/netip"
	"time"
)

const (
	SchemaVersionV1      uint32 = 1
	SchemaVersionV2      uint32 = 2
	SchemaVersionV3      uint32 = 3
	SchemaVersionV4      uint32 = 4
	SchemaVersionV5      uint32 = 5
	CurrentSchemaVersion        = SchemaVersionV5
)

func SupportedSchemaVersion(version uint32) bool {
	return version == SchemaVersionV1 || version == SchemaVersionV2 || version == SchemaVersionV3 || version == SchemaVersionV4 || version == SchemaVersionV5
}

func SupportedSchemaVersions() []uint32 {
	return []uint32{SchemaVersionV1, SchemaVersionV2, SchemaVersionV3, SchemaVersionV4, SchemaVersionV5}
}

type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

type PathMode string

const (
	PathDirect  PathMode = "direct"
	PathViaExit PathMode = "via_exit"
)

type Lifecycle string

const (
	LifecycleActive        Lifecycle = "active"
	LifecyclePaused        Lifecycle = "paused"
	LifecycleDraining      Lifecycle = "draining"
	LifecycleForceDeleting Lifecycle = "force_deleting"
)

type TrafficDirection string

const (
	DirectionUpload   TrafficDirection = "upload"
	DirectionDownload TrafficDirection = "download"
)

type SNATMode string

const (
	SNATMasquerade SNATMode = "masquerade"
	SNATStatic     SNATMode = "static"
)

type QuotaPolicy string

const QuotaPolicyPause QuotaPolicy = "pause"

type FabricTransport string

const (
	FabricWireGuard FabricTransport = "wireguard"
	FabricDirectL3  FabricTransport = "direct_l3"
	FabricGRE       FabricTransport = "gre"
)

type Endpoint struct {
	Address  netip.Addr `json:"address"`
	Hostname string     `json:"hostname,omitempty"`
	Port     uint16     `json:"port"`
}

type SNATSpec struct {
	Mode    SNATMode    `json:"mode"`
	Address *netip.Addr `json:"address,omitempty"`
}

type RateLimitSpec struct {
	IngressBitsPerSecond uint64 `json:"ingress_bits_per_second,omitempty"`
	EgressBitsPerSecond  uint64 `json:"egress_bits_per_second,omitempty"`
	BurstBytes           uint64 `json:"burst_bytes"`
}

type TrafficQuotaSpec struct {
	Bytes  uint64      `json:"bytes"`
	Policy QuotaPolicy `json:"policy"`
}

// WireGuardPeerSpec contains only public peer material. The node private key
// is generated and persisted by Agent and is never part of Desired State.
type WireGuardPeerSpec struct {
	PeerPublicKey              string `json:"peer_public_key"`
	Endpoint                   string `json:"endpoint"`
	ListenPort                 uint16 `json:"listen_port"`
	PersistentKeepaliveSeconds uint16 `json:"persistent_keepalive_seconds,omitempty"`
}

type GRESpec struct {
	UnderlayLocal  netip.Addr `json:"underlay_local"`
	UnderlayRemote netip.Addr `json:"underlay_remote"`
	Key            uint32     `json:"key"`
}

// FabricLinkSpec describes one node-to-node carrier. It may serve any number
// of user forwards; it is never created per user. RoutingID allocates a Flux
// owned policy-routing mark/table pair and must be unique on the node.
type FabricLinkSpec struct {
	ID              string             `json:"id"`
	PeerNodeID      string             `json:"peer_node_id"`
	Transport       FabricTransport    `json:"transport"`
	Interface       string             `json:"interface"`
	LocalAddress    netip.Prefix       `json:"local_address"`
	PeerAddress     netip.Addr         `json:"peer_address"`
	MTU             uint16             `json:"mtu"`
	RoutingID       uint16             `json:"routing_id"`
	Trusted         bool               `json:"trusted,omitempty"`
	WireGuard       *WireGuardPeerSpec `json:"wireguard,omitempty"`
	GRE             *GRESpec           `json:"gre,omitempty"`
	ResourceVersion uint64             `json:"resource_version"`
}

// UserPolicySpec is evaluated per node. A user's aggregate rate limit is
// therefore a node-local budget, not a globally synchronized packet shaper.
type UserPolicySpec struct {
	UserID          string            `json:"user_id"`
	TrafficClassID  uint16            `json:"traffic_class_id,omitempty"`
	RateLimit       *RateLimitSpec    `json:"rate_limit,omitempty"`
	TrafficQuota    *TrafficQuotaSpec `json:"traffic_quota,omitempty"`
	ResourceVersion uint64            `json:"resource_version"`
}

// ProtocolBlockPolicy is a node-wide policy for traffic handled by Flux.
// It deliberately uses protocol signatures instead of destination ports so
// unrelated opaque/encrypted traffic on ports such as 443 remains allowed.
type ProtocolBlockPolicy struct {
	HTTP  bool `json:"http,omitempty"`
	HTTPS bool `json:"https,omitempty"`
	SOCKS bool `json:"socks,omitempty"`
	TLS   bool `json:"tls,omitempty"`
}

func (p ProtocolBlockPolicy) Any() bool {
	return p.HTTP || p.HTTPS || p.SOCKS || p.TLS
}

// HealthCheckSpec is an active probe executed by the node that can actually
// reach a backend. Phase 5 deliberately supports TCP connect probes only:
// generic UDP has no portable request/response contract and must use a TCP
// sidecar probe (or a future explicitly versioned application probe).
type HealthCheckSpec struct {
	PoolID              string   `json:"pool_id"`
	BackendID           string   `json:"backend_id"`
	Endpoint            Endpoint `json:"endpoint"`
	Protocol            Protocol `json:"protocol"`
	IntervalSeconds     uint16   `json:"interval_seconds"`
	TimeoutMilliseconds uint16   `json:"timeout_milliseconds"`
	FailureThreshold    uint8    `json:"failure_threshold"`
	SuccessThreshold    uint8    `json:"success_threshold"`
	ResourceVersion     uint64   `json:"resource_version"`
}

// ForwardSpec is the controller-resolved intent delivered to a node. Physical
// fabric transport is deliberately not part of this object.
type ForwardSpec struct {
	ID              string            `json:"id"`
	UserID          string            `json:"user_id"`
	Protocols       []Protocol        `json:"protocols"`
	IngressNodeID   string            `json:"ingress_node_id"`
	ExitNodeID      string            `json:"exit_node_id,omitempty"`
	Listen          Endpoint          `json:"listen"`
	Target          Endpoint          `json:"target"`
	ServiceVIP      *netip.Addr       `json:"service_vip,omitempty"`
	FabricLinkID    string            `json:"fabric_link_id,omitempty"`
	PathMode        PathMode          `json:"path_mode"`
	SNAT            SNATSpec          `json:"snat"`
	TrafficClassID  uint16            `json:"traffic_class_id,omitempty"`
	RateLimit       *RateLimitSpec    `json:"rate_limit,omitempty"`
	TrafficQuota    *TrafficQuotaSpec `json:"traffic_quota,omitempty"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
	DrainDeadline   *time.Time        `json:"drain_deadline,omitempty"`
	Lifecycle       Lifecycle         `json:"lifecycle"`
	ResourceVersion uint64            `json:"resource_version"`
}

func (f ForwardSpec) EffectiveLifecycle(now time.Time) Lifecycle {
	if f.ExpiresAt != nil && !now.Before(*f.ExpiresAt) {
		return LifecyclePaused
	}
	if f.Lifecycle == LifecycleDraining && f.DrainDeadline != nil && !now.Before(*f.DrainDeadline) {
		// Locally turn a completed drain into a hard block. Conntrack cleanup is
		// reserved for an explicit force_deleting generation from Controller.
		return LifecyclePaused
	}
	return f.Lifecycle
}

type DesiredState struct {
	SchemaVersion    uint32               `json:"schema_version"`
	NodeID           string               `json:"node_id"`
	Generation       uint64               `json:"generation"`
	ManagementDomain string               `json:"management_domain,omitempty"`
	ServiceCIDRs     []netip.Prefix       `json:"service_cidrs,omitempty"`
	FabricLinks      []FabricLinkSpec     `json:"fabric_links,omitempty"`
	HealthChecks     []HealthCheckSpec    `json:"health_checks,omitempty"`
	UserPolicies     []UserPolicySpec     `json:"user_policies,omitempty"`
	ProtocolBlocks   *ProtocolBlockPolicy `json:"protocol_blocks,omitempty"`
	Forwards         []ForwardSpec        `json:"forwards"`
}
