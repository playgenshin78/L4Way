package iam

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

	"flux.local/flux/internal/spec"
)

var protectedTargetCIDRs = mustPrefixes("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")

func (p Policy) Validate() error {
	if err := ValidateInternalID("tenant_id", p.TenantID); err != nil {
		return err
	}
	if p.ResourceVersion == 0 {
		return errors.New("policy resource_version must be greater than zero")
	}
	if p.MaxForwards > 1_000_000 {
		return errors.New("max_forwards exceeds the supported limit")
	}
	if p.IngressRateLimitBPS > math.MaxInt64 || p.EgressRateLimitBPS > math.MaxInt64 || p.TrafficQuotaBytes > math.MaxInt64 {
		return errors.New("policy numeric limit exceeds SQLite integer range")
	}
	for name, values := range map[string][]string{
		"allowed_ingress_nodes": p.AllowedIngressNodes,
		"allowed_exit_nodes":    p.AllowedExitNodes,
	} {
		if err := validateIdentifiers(name, values); err != nil {
			return err
		}
	}
	if err := validateListenIPs(p.AllowedListenIPs); err != nil {
		return err
	}
	for index, portRange := range p.AllowedPortRanges {
		if portRange.Start == 0 || portRange.End == 0 || portRange.Start > portRange.End {
			return fmt.Errorf("allowed_port_ranges[%d] is invalid", index)
		}
	}
	seenProtocols := make(map[spec.Protocol]bool)
	for _, protocol := range p.AllowedProtocols {
		if protocol != spec.ProtocolTCP && protocol != spec.ProtocolUDP {
			return fmt.Errorf("allowed protocol %q is unsupported", protocol)
		}
		if seenProtocols[protocol] {
			return fmt.Errorf("allowed protocol %q is duplicated", protocol)
		}
		seenProtocols[protocol] = true
	}
	if _, err := parsePrefixes("allowed_target_cidrs", p.AllowedTargetCIDRs); err != nil {
		return err
	}
	if _, err := parsePrefixes("denied_target_cidrs", p.DeniedTargetCIDRs); err != nil {
		return err
	}
	return nil
}

func (p Policy) AuthorizeForward(forward spec.ForwardSpec, currentForwardCount uint32, tenantExpiresAt *time.Time, now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if forward.UserID != p.TenantID {
		return violation("forward does not belong to the authenticated tenant")
	}
	if p.MaxForwards == 0 || currentForwardCount >= p.MaxForwards {
		return violation("forward limit has been reached")
	}
	if !contains(p.AllowedIngressNodes, forward.IngressNodeID) {
		return violation("ingress node is not assigned to this tenant")
	}
	if forward.PathMode == spec.PathViaExit {
		if !p.AllowViaExit {
			return violation("cross-node forwarding is not allowed")
		}
		if forward.ExitNodeID == "" || !contains(p.AllowedExitNodes, forward.ExitNodeID) {
			return violation("exit node is not assigned to this tenant")
		}
	} else if forward.PathMode != spec.PathDirect {
		return violation("forward path mode is unsupported")
	}
	listenIP := forward.Listen.Address
	if !listenIP.Is4() || !contains(p.AllowedListenIPs, listenIP.String()) {
		return violation("listen IP is not assigned to this tenant")
	}
	if !portAllowed(p.AllowedPortRanges, forward.Listen.Port) {
		return violation("listen port is outside the assigned ranges")
	}
	if len(forward.Protocols) == 0 {
		return violation("at least one protocol is required")
	}
	for _, protocol := range forward.Protocols {
		if !protocolAllowed(p.AllowedProtocols, protocol) {
			return violation("protocol is not assigned to this tenant")
		}
	}
	if err := p.AuthorizeTarget(forward.Target.Address); err != nil {
		return err
	}
	if forward.RateLimit != nil {
		if p.IngressRateLimitBPS > 0 && forward.RateLimit.IngressBitsPerSecond > p.IngressRateLimitBPS {
			return violation("upload rate exceeds the tenant policy")
		}
		if p.EgressRateLimitBPS > 0 && forward.RateLimit.EgressBitsPerSecond > p.EgressRateLimitBPS {
			return violation("download rate exceeds the tenant policy")
		}
	}
	if forward.TrafficQuota != nil && p.TrafficQuotaBytes > 0 && forward.TrafficQuota.Bytes > p.TrafficQuotaBytes {
		return violation("traffic quota exceeds the tenant policy")
	}
	if forward.ExpiresAt != nil && !now.Before(*forward.ExpiresAt) {
		return violation("forward expiry must be in the future")
	}
	if tenantExpiresAt != nil {
		if !now.Before(*tenantExpiresAt) {
			return violation("tenant has expired")
		}
		if forward.ExpiresAt == nil || forward.ExpiresAt.After(*tenantExpiresAt) {
			return violation("forward expiry must not exceed tenant expiry")
		}
	}
	return nil
}

// DataPlanePolicy converts the tenant-wide limits into the node-local policy
// carried by Desired State. Per-forward limits remain optional and, when
// present, are checked as stricter child limits by AuthorizeForward.
func (p Policy) DataPlanePolicy() (*spec.UserPolicySpec, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var rateLimit *spec.RateLimitSpec
	if p.IngressRateLimitBPS > 0 || p.EgressRateLimitBPS > 0 {
		maximumRate := p.IngressRateLimitBPS
		if p.EgressRateLimitBPS > maximumRate {
			maximumRate = p.EgressRateLimitBPS
		}
		burstBytes := maximumRate / 80
		if maximumRate%80 != 0 {
			burstBytes++
		}
		if burstBytes < 64*1024 {
			burstBytes = 64 * 1024
		}
		rateLimit = &spec.RateLimitSpec{
			IngressBitsPerSecond: p.IngressRateLimitBPS,
			EgressBitsPerSecond:  p.EgressRateLimitBPS,
			BurstBytes:           burstBytes,
		}
	}
	var trafficQuota *spec.TrafficQuotaSpec
	if p.TrafficQuotaBytes > 0 {
		trafficQuota = &spec.TrafficQuotaSpec{Bytes: p.TrafficQuotaBytes, Policy: spec.QuotaPolicyPause}
	}
	if rateLimit == nil && trafficQuota == nil {
		return nil, nil
	}
	return &spec.UserPolicySpec{
		UserID: p.TenantID, RateLimit: rateLimit, TrafficQuota: trafficQuota, ResourceVersion: p.ResourceVersion,
	}, nil
}

// AuthorizeTarget applies the tenant's protected, denied and allowed network
// rules to a concrete address, including addresses refreshed from DNS.
func (p Policy) AuthorizeTarget(address netip.Addr) error {
	if !address.Is4() {
		return violation("only IPv4 targets are supported")
	}
	for _, prefix := range protectedTargetCIDRs {
		if prefix.Contains(address) {
			return violation("target is in a protected system network")
		}
	}
	denied, _ := parsePrefixes("denied_target_cidrs", p.DeniedTargetCIDRs)
	for _, prefix := range denied {
		if prefix.Contains(address) {
			return violation("target is explicitly denied by the tenant policy")
		}
	}
	allowed, _ := parsePrefixes("allowed_target_cidrs", p.AllowedTargetCIDRs)
	for _, prefix := range allowed {
		if prefix.Contains(address) {
			return nil
		}
	}
	return violation("target is outside the assigned target networks")
}

func CanonicalizePolicy(policy Policy) Policy {
	policy.AllowedIngressNodes = uniqueSorted(policy.AllowedIngressNodes)
	policy.AllowedExitNodes = uniqueSorted(policy.AllowedExitNodes)
	policy.AllowedListenIPs = uniqueSorted(policy.AllowedListenIPs)
	policy.AllowedTargetCIDRs = canonicalCIDRs(policy.AllowedTargetCIDRs)
	policy.DeniedTargetCIDRs = canonicalCIDRs(policy.DeniedTargetCIDRs)
	sort.Slice(policy.AllowedPortRanges, func(i, j int) bool {
		if policy.AllowedPortRanges[i].Start == policy.AllowedPortRanges[j].Start {
			return policy.AllowedPortRanges[i].End < policy.AllowedPortRanges[j].End
		}
		return policy.AllowedPortRanges[i].Start < policy.AllowedPortRanges[j].Start
	})
	sort.Slice(policy.AllowedProtocols, func(i, j int) bool { return policy.AllowedProtocols[i] < policy.AllowedProtocols[j] })
	return policy
}

func violation(message string) error {
	return fmt.Errorf("%w: %s", ErrForbidden, message)
}

func validateIdentifiers(name string, values []string) error {
	seen := make(map[string]bool)
	for index, value := range values {
		if err := ValidateInternalID(fmt.Sprintf("%s[%d]", name, index), value); err != nil {
			return err
		}
		if seen[value] {
			return fmt.Errorf("%s contains duplicate %q", name, value)
		}
		seen[value] = true
	}
	return nil
}

func validateListenIPs(values []string) error {
	seen := make(map[netip.Addr]bool)
	for index, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return fmt.Errorf("allowed_listen_ips[%d] is not a usable IPv4 address", index)
		}
		if seen[address] {
			return fmt.Errorf("allowed_listen_ips contains duplicate %q", value)
		}
		seen[address] = true
	}
	return nil
}

func parsePrefixes(name string, values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]bool)
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%s[%d] is not an IPv4 CIDR", name, index)
		}
		prefix = prefix.Masked()
		if seen[prefix] {
			return nil, fmt.Errorf("%s contains duplicate %q", name, prefix)
		}
		seen[prefix] = true
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func canonicalCIDRs(values []string) []string {
	prefixes, err := parsePrefixes("cidrs", values)
	if err != nil {
		return append([]string(nil), values...)
	}
	result := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		result = append(result, prefix.String())
	}
	sort.Strings(result)
	return result
}

func uniqueSorted(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if write == 0 || result[write-1] != value {
			result[write] = value
			write++
		}
	}
	return result[:write]
}

func protocolAllowed(allowed []spec.Protocol, candidate spec.Protocol) bool {
	for _, protocol := range allowed {
		if protocol == candidate {
			return true
		}
	}
	return false
}

func portAllowed(ranges []PortRange, port uint16) bool {
	if port == 0 {
		return false
	}
	for _, portRange := range ranges {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}
	return false
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func mustPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

func ProtectedTargetCIDRs() []string {
	result := make([]string, 0, len(protectedTargetCIDRs))
	for _, prefix := range protectedTargetCIDRs {
		result = append(result, prefix.String())
	}
	return result
}

func PolicyReason(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimPrefix(err.Error(), ErrForbidden.Error()+": ")
}
