package store

import (
	"context"
	"net/netip"

	"flux.local/flux/internal/cluster"
	"flux.local/flux/internal/controller/iam"
)

// resolvePlanTargets produces the concrete-IP plan used by placement and
// Desired State compilation. The durable plan keeps the hostname and its
// last saved address, so DNS failure never clears a working dataplane.
func (s *Store) resolvePlanTargets(ctx context.Context, source queryer, plan cluster.Plan) (cluster.Plan, error) {
	result := plan.Canonical()
	usersByPool := make(map[string]map[string]struct{}, len(result.BackendPools))
	for _, forward := range result.Forwards {
		if usersByPool[forward.BackendPoolID] == nil {
			usersByPool[forward.BackendPoolID] = make(map[string]struct{})
		}
		usersByPool[forward.BackendPoolID][forward.UserID] = struct{}{}
	}
	policies := make(map[string]iam.Policy)

	for poolIndex := range result.BackendPools {
		pool := &result.BackendPools[poolIndex]
		for backendIndex := range pool.Backends {
			endpoint := &pool.Backends[backendIndex].Target
			if endpoint.Hostname == "" {
				continue
			}
			fallback := endpoint.Address.Unmap()
			candidate, _ := s.targetDNS.Resolve(ctx, endpoint.Hostname, fallback)
			if !candidateAllowedForUsers(ctx, source, candidate, usersByPool[pool.ID], policies) {
				candidate = fallback
			}
			endpoint.Address = candidate.Unmap()
			endpoint.Hostname = ""
		}
	}
	return result, nil
}

func candidateAllowedForUsers(ctx context.Context, source queryer, address netip.Addr, users map[string]struct{}, policies map[string]iam.Policy) bool {
	for userID := range users {
		if userID == "owner" {
			continue
		}
		policy, exists := policies[userID]
		if !exists {
			var err error
			policy, err = scanPolicy(source.QueryRow(ctx, `
SELECT tenant_id,allowed_ingress_nodes,allowed_exit_nodes,allowed_listen_ips,allowed_port_ranges,
       allowed_protocols,allow_via_exit,max_forwards,ingress_rate_limit_bps,egress_rate_limit_bps,
       traffic_quota_bytes,allowed_target_cidrs,denied_target_cidrs,resource_version,created_at,updated_at
FROM tenant_policies WHERE tenant_id=$1`, userID))
			if err != nil {
				return false
			}
			policies[userID] = policy
		}
		if err := policy.AuthorizeTarget(address); err != nil {
			return false
		}
	}
	return true
}
