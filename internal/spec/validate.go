package spec

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxForwardsPerSnapshot     = 100_000
	MaxFabricLinksPerSnapshot  = 1_024
	MaxServiceCIDRsPerSnapshot = 256
	MaxHealthChecksPerSnapshot = 4_096
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

func ValidateIdentifier(name, value string) error {
	if !validIdentifier(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	return "invalid desired state: " + strings.Join(e.Issues, "; ")
}

func (s DesiredState) Validate() error {
	var issues []string
	if !SupportedSchemaVersion(s.SchemaVersion) {
		issues = append(issues, fmt.Sprintf("schema_version must be one of %d, %d, %d, %d or %d", SchemaVersionV1, SchemaVersionV2, SchemaVersionV3, SchemaVersionV4, SchemaVersionV5))
	}
	if !validIdentifier(s.NodeID) {
		issues = append(issues, "node_id is invalid")
	}
	if s.Generation == 0 {
		issues = append(issues, "generation must be greater than zero")
	}
	if s.ManagementDomain != "" {
		if s.SchemaVersion < SchemaVersionV4 {
			issues = append(issues, "management_domain requires schema_version 4")
		}
		if !validIdentifier(s.ManagementDomain) {
			issues = append(issues, "management_domain is invalid")
		}
	}
	if len(s.Forwards) > MaxForwardsPerSnapshot {
		issues = append(issues, fmt.Sprintf("forwards exceeds limit %d", MaxForwardsPerSnapshot))
	}
	if len(s.FabricLinks) > MaxFabricLinksPerSnapshot {
		issues = append(issues, fmt.Sprintf("fabric_links exceeds limit %d", MaxFabricLinksPerSnapshot))
	}
	if len(s.ServiceCIDRs) > MaxServiceCIDRsPerSnapshot {
		issues = append(issues, fmt.Sprintf("service_cidrs exceeds limit %d", MaxServiceCIDRsPerSnapshot))
	}
	if len(s.HealthChecks) > MaxHealthChecksPerSnapshot {
		issues = append(issues, fmt.Sprintf("health_checks exceeds limit %d", MaxHealthChecksPerSnapshot))
	}

	serviceCIDRs := make([]netip.Prefix, 0, len(s.ServiceCIDRs))
	for i, prefix := range s.ServiceCIDRs {
		name := fmt.Sprintf("service_cidrs[%d]", i)
		if issue := validateIPv4Prefix(name, prefix); issue != "" {
			issues = append(issues, issue)
			continue
		}
		prefix = canonicalPrefix(prefix)
		for j, existing := range serviceCIDRs {
			if prefixesOverlap(prefix, existing) {
				issues = append(issues, fmt.Sprintf("%s overlaps service_cidrs[%d]", name, j))
			}
		}
		serviceCIDRs = append(serviceCIDRs, prefix)
	}
	if s.SchemaVersion < SchemaVersionV3 && (len(s.ServiceCIDRs) != 0 || len(s.FabricLinks) != 0) {
		issues = append(issues, "service_cidrs and fabric_links require schema_version 3")
	}
	if s.SchemaVersion < SchemaVersionV4 && len(s.HealthChecks) != 0 {
		issues = append(issues, "health_checks requires schema_version 4")
	}
	if s.SchemaVersion < SchemaVersionV5 && s.ProtocolBlocks != nil && s.ProtocolBlocks.Any() {
		issues = append(issues, "protocol_blocks requires schema_version 5")
	}

	fabricLinks := make(map[string]FabricLinkSpec, len(s.FabricLinks))
	routingOwners := make(map[uint16]string, len(s.FabricLinks))
	interfaceOwners := make(map[string]FabricTransport, len(s.FabricLinks))
	type localAddressOwner struct {
		name      string
		transport FabricTransport
		device    string
	}
	localAddressOwners := make(map[netip.Addr]localAddressOwner, len(s.FabricLinks))
	for i, link := range s.FabricLinks {
		prefix := fmt.Sprintf("fabric_links[%d]", i)
		if !validIdentifier(link.ID) {
			issues = append(issues, prefix+".id is invalid")
		} else if _, exists := fabricLinks[link.ID]; exists {
			issues = append(issues, prefix+".id is duplicated")
		} else {
			fabricLinks[link.ID] = link
		}
		if !validIdentifier(link.PeerNodeID) || link.PeerNodeID == s.NodeID {
			issues = append(issues, prefix+".peer_node_id is invalid or refers to this node")
		}
		if !interfacePattern.MatchString(link.Interface) {
			issues = append(issues, prefix+".interface is invalid")
		} else if owner, exists := interfaceOwners[link.Interface]; exists && (owner != FabricDirectL3 || link.Transport != FabricDirectL3) {
			issues = append(issues, prefix+".interface conflicts with another managed fabric")
		} else {
			interfaceOwners[link.Interface] = link.Transport
		}
		if issue := validateIPv4InterfacePrefix(prefix+".local_address", link.LocalAddress); issue != "" {
			issues = append(issues, issue)
		} else {
			local := link.LocalAddress.Addr().Unmap()
			if owner, exists := localAddressOwners[local]; exists && (owner.transport != FabricDirectL3 || link.Transport != FabricDirectL3 || owner.device != link.Interface) {
				issues = append(issues, prefix+".local_address conflicts with "+owner.name)
			} else {
				localAddressOwners[local] = localAddressOwner{name: prefix, transport: link.Transport, device: link.Interface}
			}
			for j, serviceCIDR := range serviceCIDRs {
				if prefixesOverlap(link.LocalAddress.Masked(), serviceCIDR) {
					issues = append(issues, fmt.Sprintf("%s.local_address overlaps service_cidrs[%d]", prefix, j))
				}
			}
		}
		issues = append(issues, validateIPv4(prefix+".peer_address", link.PeerAddress)...)
		if link.LocalAddress.IsValid() && link.PeerAddress.IsValid() {
			localPrefix := link.LocalAddress.Masked()
			peer := link.PeerAddress.Unmap()
			if !localPrefix.Contains(peer) || peer == link.LocalAddress.Addr().Unmap() {
				issues = append(issues, prefix+".peer_address must be a different address inside local_address prefix")
			}
			for j, serviceCIDR := range serviceCIDRs {
				if serviceCIDR.Contains(peer) {
					issues = append(issues, fmt.Sprintf("%s.peer_address overlaps service_cidrs[%d]", prefix, j))
				}
			}
		}
		if link.MTU < 1280 || link.MTU > 9000 {
			issues = append(issues, prefix+".mtu must be between 1280 and 9000")
		}
		if link.RoutingID == 0 || link.RoutingID == 65535 {
			issues = append(issues, prefix+".routing_id is reserved")
		} else if owner, exists := routingOwners[link.RoutingID]; exists {
			issues = append(issues, prefix+".routing_id conflicts with "+owner)
		} else {
			routingOwners[link.RoutingID] = prefix
		}
		if link.ResourceVersion == 0 {
			issues = append(issues, prefix+".resource_version must be greater than zero")
		}
		switch link.Transport {
		case FabricWireGuard:
			if link.WireGuard == nil {
				issues = append(issues, prefix+".wireguard is required")
			} else {
				issues = append(issues, validateWireGuard(prefix+".wireguard", *link.WireGuard)...)
			}
			if link.GRE != nil {
				issues = append(issues, prefix+".gre must be empty for wireguard")
			}
		case FabricDirectL3:
			if !link.Trusted {
				issues = append(issues, prefix+" direct_l3 requires trusted=true")
			}
			if link.WireGuard != nil || link.GRE != nil {
				issues = append(issues, prefix+" direct_l3 must not contain wireguard or gre settings")
			}
		case FabricGRE:
			if !link.Trusted {
				issues = append(issues, prefix+" gre requires trusted=true")
			}
			if link.GRE == nil {
				issues = append(issues, prefix+".gre is required")
			} else {
				issues = append(issues, validateGRE(prefix+".gre", *link.GRE)...)
			}
			if link.WireGuard != nil {
				issues = append(issues, prefix+".wireguard must be empty for gre")
			}
		default:
			issues = append(issues, prefix+".transport is unsupported")
		}
	}

	type healthKey struct {
		poolID    string
		backendID string
	}
	healthChecks := make(map[healthKey]struct{}, len(s.HealthChecks))
	for i, check := range s.HealthChecks {
		prefix := fmt.Sprintf("health_checks[%d]", i)
		if !validIdentifier(check.PoolID) {
			issues = append(issues, prefix+".pool_id is invalid")
		}
		if !validIdentifier(check.BackendID) {
			issues = append(issues, prefix+".backend_id is invalid")
		}
		key := healthKey{poolID: check.PoolID, backendID: check.BackendID}
		if _, exists := healthChecks[key]; exists {
			issues = append(issues, prefix+" duplicates a pool/backend probe")
		} else {
			healthChecks[key] = struct{}{}
		}
		issues = append(issues, validateEndpoint(prefix+".endpoint", check.Endpoint)...)
		if check.Protocol != ProtocolTCP {
			issues = append(issues, prefix+".protocol must be tcp")
		}
		if check.IntervalSeconds < 1 || check.IntervalSeconds > 300 {
			issues = append(issues, prefix+".interval_seconds must be between 1 and 300")
		}
		if check.TimeoutMilliseconds < 100 || check.TimeoutMilliseconds > 30_000 {
			issues = append(issues, prefix+".timeout_milliseconds must be between 100 and 30000")
		} else if check.IntervalSeconds != 0 && uint32(check.TimeoutMilliseconds) > uint32(check.IntervalSeconds)*1_000 {
			issues = append(issues, prefix+".timeout_milliseconds must not exceed interval_seconds")
		}
		if check.FailureThreshold < 1 || check.FailureThreshold > 10 {
			issues = append(issues, prefix+".failure_threshold must be between 1 and 10")
		}
		if check.SuccessThreshold < 1 || check.SuccessThreshold > 10 {
			issues = append(issues, prefix+".success_threshold must be between 1 and 10")
		}
		if check.ResourceVersion == 0 {
			issues = append(issues, prefix+".resource_version must be greater than zero")
		}
		for j, serviceCIDR := range serviceCIDRs {
			if serviceCIDR.Contains(check.Endpoint.Address.Unmap()) {
				issues = append(issues, fmt.Sprintf("%s.endpoint.address overlaps service_cidrs[%d]", prefix, j))
			}
		}
	}

	userPolicies := make(map[string]UserPolicySpec, len(s.UserPolicies))
	classOwners := make(map[uint16]string, len(s.UserPolicies)+len(s.Forwards))
	for i, policy := range s.UserPolicies {
		prefix := fmt.Sprintf("user_policies[%d]", i)
		if !validIdentifier(policy.UserID) {
			issues = append(issues, prefix+".user_id is invalid")
		} else if _, exists := userPolicies[policy.UserID]; exists {
			issues = append(issues, prefix+".user_id is duplicated")
		} else {
			userPolicies[policy.UserID] = policy
		}
		if policy.ResourceVersion == 0 {
			issues = append(issues, prefix+".resource_version must be greater than zero")
		}
		if policy.RateLimit == nil && policy.TrafficQuota == nil {
			issues = append(issues, prefix+" must set rate_limit or traffic_quota")
		}
		issues = append(issues, validateRateLimit(prefix+".rate_limit", policy.RateLimit)...)
		issues = append(issues, validateQuota(prefix+".traffic_quota", policy.TrafficQuota)...)
		if policy.TrafficClassID != 0 {
			if policy.TrafficClassID == 1 || policy.TrafficClassID == 65535 {
				issues = append(issues, prefix+".traffic_class_id is reserved")
			} else if owner, exists := classOwners[policy.TrafficClassID]; exists {
				issues = append(issues, fmt.Sprintf("%s.traffic_class_id conflicts with %s", prefix, owner))
			} else {
				classOwners[policy.TrafficClassID] = prefix
			}
		}
	}
	if s.SchemaVersion == SchemaVersionV1 && len(s.UserPolicies) != 0 {
		issues = append(issues, "user_policies requires schema_version 2")
	}

	ids := make(map[string]struct{}, len(s.Forwards))
	type listenKey struct {
		address  netip.Addr
		protocol Protocol
		port     uint16
	}
	listeners := make(map[listenKey]string, len(s.Forwards))
	serviceVIPOwners := make(map[netip.Addr]string, len(s.Forwards))

	for i, forward := range s.Forwards {
		prefix := fmt.Sprintf("forwards[%d]", i)
		if !validIdentifier(forward.ID) {
			issues = append(issues, prefix+".id is invalid")
		} else if _, exists := ids[forward.ID]; exists {
			issues = append(issues, prefix+".id is duplicated")
		} else {
			ids[forward.ID] = struct{}{}
		}
		if !validIdentifier(forward.UserID) {
			issues = append(issues, prefix+".user_id is invalid")
		}
		if !validIdentifier(forward.IngressNodeID) {
			issues = append(issues, prefix+".ingress_node_id is invalid")
		}
		if forward.ResourceVersion == 0 {
			issues = append(issues, prefix+".resource_version must be greater than zero")
		}
		if forward.TrafficClassID != 0 {
			if forward.TrafficClassID == 1 || forward.TrafficClassID == 65535 {
				issues = append(issues, prefix+".traffic_class_id is reserved")
			} else if owner, exists := classOwners[forward.TrafficClassID]; exists {
				issues = append(issues, fmt.Sprintf("%s.traffic_class_id conflicts with %s", prefix, owner))
			} else {
				classOwners[forward.TrafficClassID] = prefix
			}
		}
		issues = append(issues, validateEndpoint(prefix+".listen", forward.Listen)...)
		issues = append(issues, validateEndpoint(prefix+".target", forward.Target)...)

		seenProtocols := make(map[Protocol]struct{}, len(forward.Protocols))
		if len(forward.Protocols) == 0 {
			issues = append(issues, prefix+".protocols must not be empty")
		}
		for _, protocol := range forward.Protocols {
			if protocol != ProtocolTCP && protocol != ProtocolUDP {
				issues = append(issues, prefix+".protocols contains unsupported value "+string(protocol))
				continue
			}
			if _, exists := seenProtocols[protocol]; exists {
				issues = append(issues, prefix+".protocols contains duplicate "+string(protocol))
				continue
			}
			seenProtocols[protocol] = struct{}{}
			matchAddress := forward.Listen.Address.Unmap()
			matchPort := forward.Listen.Port
			if forward.PathMode == PathViaExit && s.NodeID == forward.ExitNodeID && forward.ServiceVIP != nil {
				matchAddress = forward.ServiceVIP.Unmap()
				matchPort = forward.Target.Port
			}
			key := listenKey{address: matchAddress, protocol: protocol, port: matchPort}
			if owner, exists := listeners[key]; exists {
				issues = append(issues, fmt.Sprintf("%s listener conflicts with forward %s", prefix, owner))
			} else {
				listeners[key] = forward.ID
			}
		}

		switch forward.PathMode {
		case PathDirect:
			if forward.ExitNodeID != "" {
				issues = append(issues, prefix+".exit_node_id must be empty for direct path")
			}
			if forward.ServiceVIP != nil {
				issues = append(issues, prefix+".service_vip must be empty for direct path")
			}
			if forward.FabricLinkID != "" {
				issues = append(issues, prefix+".fabric_link_id must be empty for direct path")
			}
			if forward.IngressNodeID != s.NodeID {
				issues = append(issues, prefix+" direct path is not assigned to this node")
			}
		case PathViaExit:
			if s.SchemaVersion < SchemaVersionV3 {
				issues = append(issues, prefix+" via_exit path requires schema_version 3")
			}
			if !validIdentifier(forward.ExitNodeID) {
				issues = append(issues, prefix+".exit_node_id is required for via_exit path")
			}
			if forward.ExitNodeID == forward.IngressNodeID {
				issues = append(issues, prefix+".exit_node_id must differ from ingress_node_id")
			}
			if s.NodeID != forward.IngressNodeID && s.NodeID != forward.ExitNodeID {
				issues = append(issues, prefix+" via_exit path is not assigned to this node")
			}
			if forward.ServiceVIP == nil {
				issues = append(issues, prefix+".service_vip is required for via_exit path")
			} else {
				issues = append(issues, validateIPv4(prefix+".service_vip", *forward.ServiceVIP)...)
				vip := forward.ServiceVIP.Unmap()
				contained := false
				for _, serviceCIDR := range serviceCIDRs {
					contained = contained || serviceCIDR.Contains(vip)
				}
				if !contained {
					issues = append(issues, prefix+".service_vip is outside service_cidrs")
				}
				if owner, exists := serviceVIPOwners[vip]; exists && owner != forward.ID {
					issues = append(issues, prefix+".service_vip conflicts with forward "+owner)
				} else {
					serviceVIPOwners[vip] = forward.ID
				}
			}
			if !validIdentifier(forward.FabricLinkID) {
				issues = append(issues, prefix+".fabric_link_id is required for via_exit path")
			} else if link, exists := fabricLinks[forward.FabricLinkID]; !exists {
				issues = append(issues, prefix+".fabric_link_id does not exist")
			} else {
				expectedPeer := forward.ExitNodeID
				if s.NodeID == forward.ExitNodeID {
					expectedPeer = forward.IngressNodeID
				}
				if link.PeerNodeID != expectedPeer {
					issues = append(issues, prefix+".fabric_link_id peer does not match the opposite node")
				}
			}
		default:
			issues = append(issues, prefix+".path_mode is unsupported")
		}

		switch forward.Lifecycle {
		case LifecycleActive, LifecyclePaused, LifecycleDraining, LifecycleForceDeleting:
		default:
			issues = append(issues, prefix+".lifecycle is unsupported")
		}

		switch forward.SNAT.Mode {
		case SNATMasquerade:
			if forward.SNAT.Address != nil {
				issues = append(issues, prefix+".snat.address must be empty for masquerade")
			}
		case SNATStatic:
			if forward.SNAT.Address == nil {
				issues = append(issues, prefix+".snat.address is required for static mode")
			} else {
				issues = append(issues, validateIPv4(prefix+".snat.address", *forward.SNAT.Address)...)
			}
		default:
			issues = append(issues, prefix+".snat.mode is unsupported")
		}

		issues = append(issues, validateRateLimit(prefix+".rate_limit", forward.RateLimit)...)
		issues = append(issues, validateQuota(prefix+".traffic_quota", forward.TrafficQuota)...)
		for j, serviceCIDR := range serviceCIDRs {
			if serviceCIDR.Contains(forward.Listen.Address.Unmap()) {
				issues = append(issues, fmt.Sprintf("%s.listen.address overlaps service_cidrs[%d]", prefix, j))
			}
			if serviceCIDR.Contains(forward.Target.Address.Unmap()) {
				issues = append(issues, fmt.Sprintf("%s.target.address overlaps service_cidrs[%d]", prefix, j))
			}
			if forward.SNAT.Address != nil && serviceCIDR.Contains(forward.SNAT.Address.Unmap()) {
				issues = append(issues, fmt.Sprintf("%s.snat.address overlaps service_cidrs[%d]", prefix, j))
			}
		}
		if forward.ExpiresAt != nil && forward.ExpiresAt.IsZero() {
			issues = append(issues, prefix+".expires_at must not be zero")
		}
		if forward.Lifecycle == LifecycleDraining {
			if forward.DrainDeadline == nil || forward.DrainDeadline.IsZero() {
				issues = append(issues, prefix+".drain_deadline is required while draining")
			}
		} else if forward.DrainDeadline != nil {
			issues = append(issues, prefix+".drain_deadline is only valid while draining")
		}
		if s.SchemaVersion == SchemaVersionV1 && (forward.TrafficClassID != 0 || forward.RateLimit != nil || forward.TrafficQuota != nil || forward.ExpiresAt != nil || forward.DrainDeadline != nil || forward.Lifecycle == LifecycleForceDeleting) {
			issues = append(issues, prefix+" uses fields that require schema_version 2")
		}
	}

	if len(issues) != 0 {
		return &ValidationError{Issues: issues}
	}
	return nil
}

func validateRateLimit(name string, limit *RateLimitSpec) []string {
	if limit == nil {
		return nil
	}
	var issues []string
	if limit.IngressBitsPerSecond == 0 && limit.EgressBitsPerSecond == 0 {
		issues = append(issues, name+" must set at least one direction")
	}
	if limit.BurstBytes == 0 {
		issues = append(issues, name+".burst_bytes must be greater than zero")
	}
	return issues
}

func validateQuota(name string, quota *TrafficQuotaSpec) []string {
	if quota == nil {
		return nil
	}
	var issues []string
	if quota.Bytes == 0 {
		issues = append(issues, name+".bytes must be greater than zero")
	}
	if quota.Policy != QuotaPolicyPause {
		issues = append(issues, name+".policy is unsupported")
	}
	return issues
}

func validIdentifier(value string) bool {
	return identifierPattern.MatchString(value)
}

func validateEndpoint(name string, endpoint Endpoint) []string {
	issues := validateIPv4(name+".address", endpoint.Address)
	if endpoint.Hostname != "" {
		issues = append(issues, name+".hostname must be resolved by Controller before publication")
	}
	if endpoint.Port == 0 {
		issues = append(issues, name+".port must be greater than zero")
	}
	return issues
}

func validateIPv4(name string, address netip.Addr) []string {
	if !address.IsValid() {
		return []string{name + " is invalid"}
	}
	address = address.Unmap()
	if !address.Is4() {
		return []string{name + " must be IPv4"}
	}
	if address.IsUnspecified() {
		return []string{name + " must be a concrete address"}
	}
	if address.IsMulticast() {
		return []string{name + " must not be multicast"}
	}
	return nil
}

func validateIPv4Prefix(name string, prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return name + " is invalid"
	}
	address := prefix.Addr().Unmap()
	if !address.Is4() {
		return name + " must be IPv4"
	}
	if address.IsUnspecified() || address.IsMulticast() {
		return name + " must be a concrete unicast prefix"
	}
	canonical := canonicalPrefix(prefix)
	if prefix.Addr().Unmap() != canonical.Addr() {
		return name + " must be network-masked"
	}
	return ""
}

func validateIPv4InterfacePrefix(name string, prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return name + " is invalid"
	}
	address := prefix.Addr().Unmap()
	if !address.Is4() {
		return name + " must be IPv4"
	}
	if address.IsUnspecified() || address.IsMulticast() {
		return name + " must use a concrete unicast address"
	}
	bits := prefix.Bits()
	if prefix.Addr().Is4In6() {
		bits -= 96
	}
	if bits < 1 || bits > 32 {
		return name + " prefix length is invalid"
	}
	return ""
}

func prefixesOverlap(first, second netip.Prefix) bool {
	if !first.IsValid() || !second.IsValid() {
		return false
	}
	first = canonicalPrefix(first)
	second = canonicalPrefix(second)
	return first.Contains(second.Addr()) || second.Contains(first.Addr())
}

func validateWireGuard(name string, peer WireGuardPeerSpec) []string {
	var issues []string
	if err := ValidateWireGuardPublicKey(name+".peer_public_key", peer.PeerPublicKey); err != nil {
		issues = append(issues, err.Error())
	}
	host, portText, err := net.SplitHostPort(peer.Endpoint)
	if err != nil || host == "" {
		issues = append(issues, name+".endpoint must be host:port")
	} else {
		port, portErr := strconv.ParseUint(portText, 10, 16)
		if portErr != nil || port == 0 {
			issues = append(issues, name+".endpoint port is invalid")
		}
		address, addressErr := netip.ParseAddr(host)
		if addressErr != nil || !address.Unmap().Is4() || address.IsUnspecified() || address.IsMulticast() {
			issues = append(issues, name+".endpoint host must be a concrete IPv4 address")
		}
	}
	if peer.ListenPort == 0 {
		issues = append(issues, name+".listen_port must be greater than zero")
	}
	if peer.PersistentKeepaliveSeconds > 3600 {
		issues = append(issues, name+".persistent_keepalive_seconds must not exceed 3600")
	}
	return issues
}

func ValidateWireGuardPublicKey(name, encoded string) error {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%s must be a base64-encoded 32-byte key", name)
	}
	allZero := true
	for _, value := range decoded {
		allZero = allZero && value == 0
	}
	if allZero {
		return fmt.Errorf("%s must not be all zero", name)
	}
	public, err := ecdh.X25519().NewPublicKey(decoded)
	if err != nil {
		return fmt.Errorf("%s is not a valid X25519 key", name)
	}
	probeBytes := make([]byte, 32)
	probeBytes[0] = 1
	probe, err := ecdh.X25519().NewPrivateKey(probeBytes)
	if err != nil {
		return fmt.Errorf("validate %s: %w", name, err)
	}
	if _, err := probe.ECDH(public); err != nil {
		return fmt.Errorf("%s is a low-order X25519 key", name)
	}
	return nil
}

func validateGRE(name string, gre GRESpec) []string {
	issues := validateIPv4(name+".underlay_local", gre.UnderlayLocal)
	issues = append(issues, validateIPv4(name+".underlay_remote", gre.UnderlayRemote)...)
	if gre.UnderlayLocal.IsValid() && gre.UnderlayRemote.IsValid() && gre.UnderlayLocal.Unmap() == gre.UnderlayRemote.Unmap() {
		issues = append(issues, name+" underlay endpoints must differ")
	}
	if gre.Key == 0 {
		issues = append(issues, name+".key must be greater than zero")
	}
	return issues
}
