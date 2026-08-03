package cluster

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"flux.local/flux/internal/health"
	"flux.local/flux/internal/spec"
)

var ErrNoPlacement = errors.New("no eligible cluster placement")

type nodeUsage struct {
	forwards uint32
	ingress  uint64
	egress   uint64
}

func Place(plan Plan, runtimes map[string]NodeRuntime, observations map[HealthKey]HealthObservation, previous []Placement, now time.Time) (Result, error) {
	if err := plan.Validate(); err != nil {
		return Result{}, err
	}
	plan = plan.Canonical()
	nodes := make(map[string]Node, len(plan.Nodes))
	for _, node := range plan.Nodes {
		nodes[node.ID] = node
	}
	pools := make(map[string]BackendPool, len(plan.BackendPools))
	for _, pool := range plan.BackendPools {
		pools[pool.ID] = pool
	}
	previousByForward := make(map[string]Placement, len(previous))
	for _, placement := range previous {
		previousByForward[placement.ForwardID] = placement
	}
	usage := make(map[string]nodeUsage, len(nodes))
	result := Result{Placements: make([]Placement, 0, len(plan.Forwards))}
	for _, forward := range plan.Forwards {
		pool := pools[forward.BackendPoolID]
		prior := previousByForward[forward.ID]
		ingress, err := chooseNode(plan, forward, RoleIngress, forward.Ingress, "", prior.IngressID, nodes, runtimes, usage, pool)
		if err != nil {
			return Result{}, fmt.Errorf("%w for forward %s ingress: %v", ErrNoPlacement, forward.ID, err)
		}
		placement := Placement{ForwardID: forward.ID, IngressID: ingress.ID, PathMode: forward.PathMode}
		probeNodeID := ingress.ID
		if forward.PathMode == spec.PathViaExit {
			exit, err := chooseNode(plan, forward, RoleExit, *forward.Exit, ingress.ID, prior.ExitID, nodes, runtimes, usage, pool)
			if err != nil {
				return Result{}, fmt.Errorf("%w for forward %s exit: %v", ErrNoPlacement, forward.ID, err)
			}
			inLink, outLink, ok := matchingLinks(ingress, exit)
			if !ok {
				return Result{}, fmt.Errorf("%w for forward %s: nodes %s and %s have no usable reciprocal fabric", ErrNoPlacement, forward.ID, ingress.ID, exit.ID)
			}
			placement.ExitID = exit.ID
			placement.FabricInID = inLink.ID
			placement.FabricOutID = outLink.ID
			probeNodeID = exit.ID
			consume(usage, exit, effectiveReservation(forward))
		}
		backend, alert := chooseBackend(pool, probeNodeID, prior.BackendID, observations, now)
		placement.BackendID = backend.ID
		placement.Target = backend.Target
		consume(usage, ingress, effectiveReservation(forward))
		result.Placements = append(result.Placements, placement)
		if alert != nil {
			alert.ForwardID = forward.ID
			result.Alerts = append(result.Alerts, *alert)
		}
	}
	return result, nil
}

func chooseNode(plan Plan, forward Forward, role NodeRole, selector NodeSelector, oppositeID, previousID string, nodes map[string]Node, runtimes map[string]NodeRuntime, usage map[string]nodeUsage, pool BackendPool) (Node, error) {
	reservation := effectiveReservation(forward)
	candidates := make([]Node, 0, len(nodes))
	for _, node := range nodes {
		if node.ID == oppositeID || !node.Enabled || !nodeHasRole(node, role) || !selectorMatches(selector, node) || !fits(node, usage[node.ID], reservation) {
			continue
		}
		runtime, exists := runtimes[node.ID]
		if !exists || !runtime.Available || !supports(runtime, plan, forward, role, pool) {
			continue
		}
		if oppositeID != "" {
			opposite := nodes[oppositeID]
			firstLink, secondLink, ok := matchingLinks(opposite, node)
			if !ok || !supportsFabric(runtimes[opposite.ID], firstLink.Transport) || !supportsFabric(runtime, secondLink.Transport) {
				continue
			}
			policy := effectiveFailurePolicy(forward.FailureDomainPolicy)
			if policy == FailureDomainDistinct && node.FailureDomain == opposite.FailureDomain {
				continue
			}
		}
		candidates = append(candidates, node)
	}
	if len(candidates) == 0 {
		return Node{}, errors.New("selector, health, capability, fabric, failure-domain, or capacity constraints rejected every node")
	}
	if previousID != "" {
		for _, node := range candidates {
			if node.ID == previousID {
				return node, nil
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if oppositeID != "" && effectiveFailurePolicy(forward.FailureDomainPolicy) == FailureDomainPrefer {
			opposite := nodes[oppositeID]
			iDistinct := candidates[i].FailureDomain != opposite.FailureDomain
			jDistinct := candidates[j].FailureDomain != opposite.FailureDomain
			if iDistinct != jDistinct {
				return iDistinct
			}
		}
		left := uint64(usage[candidates[i].ID].forwards) * uint64(candidates[j].Capacity.MaxForwards)
		right := uint64(usage[candidates[j].ID].forwards) * uint64(candidates[i].Capacity.MaxForwards)
		if left == right {
			return candidates[i].ID < candidates[j].ID
		}
		return left < right
	})
	return candidates[0], nil
}

func supportsFabric(runtime NodeRuntime, transport spec.FabricTransport) bool {
	if runtime.Capabilities["fabric.policy-routing"] < 1 || runtime.Capabilities["fabric.mss-clamp"] < 1 {
		return false
	}
	switch transport {
	case spec.FabricWireGuard:
		return runtime.Capabilities["fabric.wireguard"] >= 1 && runtime.WireGuardPublicKey != ""
	case spec.FabricDirectL3:
		return runtime.Capabilities["fabric.direct-l3"] >= 1
	case spec.FabricGRE:
		return runtime.Capabilities["fabric.gre"] >= 1
	default:
		return false
	}
}

func chooseBackend(pool BackendPool, nodeID, previousID string, observations map[HealthKey]HealthObservation, now time.Time) (Backend, *Alert) {
	if pool.Health == nil {
		return preferredBackend(pool.Backends, previousID), nil
	}
	var healthy, unknown []Backend
	for _, backend := range pool.Backends {
		observation, exists := observations[HealthKey{NodeID: nodeID, PoolID: pool.ID, BackendID: backend.ID}]
		fresh := exists && observation.ResourceVersion == backend.ResourceVersion && !observation.ObservedAt.IsZero() && !now.Before(observation.ObservedAt.Add(-5*time.Minute)) && now.Sub(observation.ObservedAt) <= time.Duration(pool.Health.StaleAfterSeconds)*time.Second
		if !fresh || observation.Status == health.StatusUnknown {
			unknown = append(unknown, backend)
			continue
		}
		if observation.Status == health.StatusHealthy {
			healthy = append(healthy, backend)
		}
	}
	if len(healthy) != 0 {
		return preferredBackend(healthy, previousID), nil
	}
	if len(unknown) != 0 {
		if previous, exists := backendByID(BackendPool{Backends: unknown}, previousID); exists {
			return previous, &Alert{Code: "backend_health_unknown", PoolID: pool.ID, Detail: "no fresh healthy observation; retaining the previous unknown backend"}
		}
		return preferredBackend(unknown, ""), &Alert{Code: "backend_health_unknown", PoolID: pool.ID, Detail: "no fresh healthy observation; using an unknown backend"}
	}
	backend, exists := backendByID(pool, previousID)
	if !exists {
		backend = preferredBackend(pool.Backends, "")
	}
	return backend, &Alert{Code: "backend_pool_exhausted", PoolID: pool.ID, Detail: "all backends are unhealthy; retaining a deterministic last-resort target"}
}

func preferredBackend(backends []Backend, previousID string) Backend {
	candidates := append([]Backend(nil), backends...)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority == candidates[j].Priority {
			return candidates[i].ID < candidates[j].ID
		}
		return candidates[i].Priority < candidates[j].Priority
	})
	minimumPriority := candidates[0].Priority
	for _, backend := range candidates {
		if backend.Priority == minimumPriority && backend.ID == previousID {
			return backend
		}
	}
	return candidates[0]
}

func supports(runtime NodeRuntime, plan Plan, forward Forward, role NodeRole, pool BackendPool) bool {
	required := map[string]uint32{}
	if forward.PathMode == spec.PathDirect {
		required["nft.direct"] = 2
	} else {
		required["nft.via-exit"] = 1
		required["fabric.policy-routing"] = 1
		required["fabric.mss-clamp"] = 1
	}
	if role == RoleIngress && forward.RateLimit != nil {
		required["tc.rate-limit"] = 1
	}
	if role == RoleIngress && forward.TrafficQuota != nil {
		required["usage.l3"] = 1
		required["nft.directional-counters"] = 1
	}
	if forward.SNAT.Mode == spec.SNATStatic {
		required["nft.static-snat"] = 1
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
	if role == RoleIngress {
		for _, policy := range plan.UserPolicies {
			if policy.UserID != forward.UserID {
				continue
			}
			if policy.RateLimit != nil {
				required["tc.rate-limit"] = 1
			}
			if policy.TrafficQuota != nil {
				required["usage.l3"] = 1
				required["nft.directional-counters"] = 1
			}
		}
	}
	if pool.Health != nil && (forward.PathMode == spec.PathDirect && role == RoleIngress || forward.PathMode == spec.PathViaExit && role == RoleExit) {
		required["health.tcp-connect"] = 1
	}
	for name, version := range required {
		if runtime.Capabilities[name] < version {
			return false
		}
	}
	return true
}

func fits(node Node, current nodeUsage, reservation Reservation) bool {
	if current.forwards >= node.Capacity.MaxForwards {
		return false
	}
	if node.Capacity.IngressBitsPerSecond != 0 && reservation.IngressBitsPerSecond > node.Capacity.IngressBitsPerSecond-current.ingress {
		return false
	}
	if node.Capacity.EgressBitsPerSecond != 0 && reservation.EgressBitsPerSecond > node.Capacity.EgressBitsPerSecond-current.egress {
		return false
	}
	return true
}

func consume(usages map[string]nodeUsage, node Node, reservation Reservation) {
	current := usages[node.ID]
	current.forwards++
	current.ingress += reservation.IngressBitsPerSecond
	current.egress += reservation.EgressBitsPerSecond
	usages[node.ID] = current
}

func effectiveReservation(forward Forward) Reservation {
	reservation := forward.Reservation
	if forward.RateLimit != nil {
		if reservation.IngressBitsPerSecond == 0 {
			reservation.IngressBitsPerSecond = forward.RateLimit.IngressBitsPerSecond
		}
		if reservation.EgressBitsPerSecond == 0 {
			reservation.EgressBitsPerSecond = forward.RateLimit.EgressBitsPerSecond
		}
	}
	return reservation
}

func selectorMatches(selector NodeSelector, node Node) bool {
	if len(selector.NodeIDs) != 0 {
		found := false
		for _, nodeID := range selector.NodeIDs {
			found = found || nodeID == node.ID
		}
		if !found {
			return false
		}
	}
	for key, value := range selector.MatchLabels {
		if node.Labels[key] != value {
			return false
		}
	}
	return true
}

func nodeHasRole(node Node, role NodeRole) bool {
	for _, candidate := range node.Roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func reciprocalLink(node Node, peerID string, transport spec.FabricTransport) (FabricLink, bool) {
	links := append([]FabricLink(nil), node.FabricLinks...)
	sort.Slice(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	for _, link := range links {
		if link.PeerNodeID == peerID && link.Transport == transport {
			return link, true
		}
	}
	return FabricLink{}, false
}

func matchingLinks(first, second Node) (FabricLink, FabricLink, bool) {
	links := append([]FabricLink(nil), first.FabricLinks...)
	sort.Slice(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	for _, firstLink := range links {
		if firstLink.PeerNodeID != second.ID {
			continue
		}
		secondLink, exists := reciprocalLink(second, first.ID, firstLink.Transport)
		if !exists {
			continue
		}
		if firstLink.PeerAddress.Unmap() != secondLink.LocalAddress.Addr().Unmap() || secondLink.PeerAddress.Unmap() != firstLink.LocalAddress.Addr().Unmap() {
			continue
		}
		return firstLink, secondLink, true
	}
	return FabricLink{}, FabricLink{}, false
}

func Compile(plan Plan, result Result, serviceVIPs map[string]netip.Addr, runtimes map[string]NodeRuntime) (map[string]spec.DesiredState, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	plan = plan.Canonical()
	nodes := make(map[string]Node, len(plan.Nodes))
	desired := make(map[string]spec.DesiredState, len(plan.Nodes))
	for _, node := range plan.Nodes {
		nodes[node.ID] = node
		state := spec.DesiredState{SchemaVersion: spec.CurrentSchemaVersion, NodeID: node.ID, Generation: 1, ManagementDomain: "cluster:" + plan.ID, ServiceCIDRs: append([]netip.Prefix(nil), plan.ServiceCIDRs...)}
		if node.ProtocolBlocks != nil && node.ProtocolBlocks.Any() {
			policy := *node.ProtocolBlocks
			state.ProtocolBlocks = &policy
		}
		desired[node.ID] = state
	}
	forwards := make(map[string]Forward, len(plan.Forwards))
	for _, forward := range plan.Forwards {
		forwards[forward.ID] = forward
	}
	pools := make(map[string]BackendPool, len(plan.BackendPools))
	for _, pool := range plan.BackendPools {
		pools[pool.ID] = pool
	}
	neededLinks := make(map[string]map[string]struct{}, len(nodes))
	ingressUsers := make(map[string]map[string]struct{}, len(nodes))
	healthKeys := make(map[string]map[string]struct{}, len(nodes))
	for _, placement := range result.Placements {
		forward, exists := forwards[placement.ForwardID]
		if !exists {
			return nil, fmt.Errorf("placement references unknown forward %s", placement.ForwardID)
		}
		pool := pools[forward.BackendPoolID]
		backend, exists := backendByID(pool, placement.BackendID)
		if !exists || backend.Target != placement.Target {
			return nil, fmt.Errorf("placement for %s references a stale backend", placement.ForwardID)
		}
		resolvedTarget := placement.Target
		resolvedTarget.Hostname = ""
		base := spec.ForwardSpec{
			ID: forward.ID, UserID: forward.UserID, Protocols: append([]spec.Protocol(nil), forward.Protocols...),
			IngressNodeID: placement.IngressID, ExitNodeID: placement.ExitID, Listen: forward.Listen, Target: resolvedTarget,
			PathMode: forward.PathMode, SNAT: forward.SNAT, RateLimit: forward.RateLimit, TrafficQuota: forward.TrafficQuota,
			ExpiresAt: forward.ExpiresAt, DrainDeadline: forward.DrainDeadline, Lifecycle: forward.Lifecycle, ResourceVersion: forward.ResourceVersion,
		}
		if ingressUsers[placement.IngressID] == nil {
			ingressUsers[placement.IngressID] = make(map[string]struct{})
		}
		ingressUsers[placement.IngressID][forward.UserID] = struct{}{}
		if placement.PathMode == spec.PathDirect {
			state := desired[placement.IngressID]
			state.Forwards = append(state.Forwards, base)
			desired[placement.IngressID] = state
		} else {
			vip, exists := serviceVIPs[placement.ForwardID]
			if !exists || !validIPv4Address(vip) {
				return nil, fmt.Errorf("placement for %s requires an allocated service VIP", placement.ForwardID)
			}
			base.ServiceVIP = addrPointer(vip.Unmap())
			ingressForward := base
			ingressForward.FabricLinkID = placement.FabricInID
			exitForward := base
			exitForward.FabricLinkID = placement.FabricOutID
			ingressState := desired[placement.IngressID]
			ingressState.Forwards = append(ingressState.Forwards, ingressForward)
			desired[placement.IngressID] = ingressState
			exitState := desired[placement.ExitID]
			exitState.Forwards = append(exitState.Forwards, exitForward)
			desired[placement.ExitID] = exitState
			if neededLinks[placement.IngressID] == nil {
				neededLinks[placement.IngressID] = make(map[string]struct{})
			}
			if neededLinks[placement.ExitID] == nil {
				neededLinks[placement.ExitID] = make(map[string]struct{})
			}
			neededLinks[placement.IngressID][placement.FabricInID] = struct{}{}
			neededLinks[placement.ExitID][placement.FabricOutID] = struct{}{}
		}
		if pool.Health != nil {
			probeNode := placement.IngressID
			if placement.PathMode == spec.PathViaExit {
				probeNode = placement.ExitID
			}
			if healthKeys[probeNode] == nil {
				healthKeys[probeNode] = make(map[string]struct{})
			}
			state := desired[probeNode]
			for _, candidate := range pool.Backends {
				key := pool.ID + "\x00" + candidate.ID
				if _, exists := healthKeys[probeNode][key]; exists {
					continue
				}
				healthKeys[probeNode][key] = struct{}{}
				endpoint := candidate.Target
				if candidate.ProbeEndpoint != nil {
					endpoint = *candidate.ProbeEndpoint
				}
				endpoint.Hostname = ""
				state.HealthChecks = append(state.HealthChecks, spec.HealthCheckSpec{
					PoolID: pool.ID, BackendID: candidate.ID, Endpoint: endpoint, Protocol: spec.ProtocolTCP,
					IntervalSeconds: pool.Health.IntervalSeconds, TimeoutMilliseconds: pool.Health.TimeoutMilliseconds,
					FailureThreshold: pool.Health.FailureThreshold, SuccessThreshold: pool.Health.SuccessThreshold,
					ResourceVersion: candidate.ResourceVersion,
				})
			}
			desired[probeNode] = state
		}
	}
	for nodeID, state := range desired {
		for _, policy := range plan.UserPolicies {
			if _, used := ingressUsers[nodeID][policy.UserID]; used {
				state.UserPolicies = append(state.UserPolicies, policy)
			}
		}
		for _, link := range nodes[nodeID].FabricLinks {
			if _, used := neededLinks[nodeID][link.ID]; !used {
				continue
			}
			compiled, err := compileLink(link, runtimes)
			if err != nil {
				return nil, fmt.Errorf("compile node %s fabric %s: %w", nodeID, link.ID, err)
			}
			state.FabricLinks = append(state.FabricLinks, compiled)
		}
		state = state.Canonical()
		if err := state.Validate(); err != nil {
			return nil, fmt.Errorf("compile desired state for node %s: %w", nodeID, err)
		}
		desired[nodeID] = state
	}
	return desired, nil
}

func compileLink(link FabricLink, runtimes map[string]NodeRuntime) (spec.FabricLinkSpec, error) {
	compiled := spec.FabricLinkSpec{
		ID: link.ID, PeerNodeID: link.PeerNodeID, Transport: link.Transport, Interface: link.Interface,
		LocalAddress: link.LocalAddress, PeerAddress: link.PeerAddress, MTU: link.MTU, RoutingID: link.RoutingID,
		Trusted: link.Trusted, GRE: link.GRE, ResourceVersion: link.ResourceVersion,
	}
	if link.Transport == spec.FabricWireGuard {
		if link.WireGuard == nil {
			return spec.FabricLinkSpec{}, errors.New("wireguard settings are missing")
		}
		peer, exists := runtimes[link.PeerNodeID]
		if !exists || peer.WireGuardPublicKey == "" {
			return spec.FabricLinkSpec{}, errors.New("peer WireGuard public key is unavailable")
		}
		compiled.WireGuard = &spec.WireGuardPeerSpec{
			PeerPublicKey: peer.WireGuardPublicKey, Endpoint: link.WireGuard.Endpoint,
			ListenPort: link.WireGuard.ListenPort, PersistentKeepaliveSeconds: link.WireGuard.PersistentKeepaliveSeconds,
		}
	}
	return compiled, nil
}

func backendByID(pool BackendPool, backendID string) (Backend, bool) {
	for _, backend := range pool.Backends {
		if backend.ID == backendID {
			return backend, true
		}
	}
	return Backend{}, false
}

func addrPointer(value netip.Addr) *netip.Addr {
	return &value
}
