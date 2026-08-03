package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"flux.local/flux/internal/cluster"
	"flux.local/flux/internal/controller/iam"
	"flux.local/flux/internal/spec"
)

// EnforceTenantForwardPolicies turns non-compliant tenant traffic into a hard
// pause. It never resumes traffic automatically: after an Owner relaxes a
// policy, the tenant must explicitly review and resume each affected forward.
func (s *Store) EnforceTenantForwardPolicies(ctx context.Context, actor string, limit int, now time.Time) (int, error) {
	if err := validateActor(actor); err != nil {
		return 0, err
	}
	if limit < 1 || limit > 100 {
		return 0, errors.New("tenant policy enforcement limit must be between 1 and 100")
	}
	rows, err := s.pool.Query(ctx, `
SELECT p.id
FROM cluster_plans p
WHERE p.paused_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM cluster_rollouts r
      WHERE r.plan_id=p.id AND r.status IN ('publishing','awaiting_ack','baking','rollback_pending','rolling_back')
  )
ORDER BY p.id
LIMIT $1`, limit)
	if err != nil {
		return 0, fmt.Errorf("list plans for tenant policy enforcement: %w", err)
	}
	var planIDs []string
	for rows.Next() {
		var planID string
		if err := rows.Scan(&planID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan tenant policy plan: %w", err)
		}
		planIDs = append(planIDs, planID)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close tenant policy plans: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate tenant policy plans: %w", err)
	}

	paused := 0
	for _, planID := range planIDs {
		record, err := s.ActiveClusterPlan(ctx, planID)
		if err != nil {
			return paused, err
		}
		plan := record.Plan.Canonical()
		pools := make(map[string]cluster.BackendPool, len(plan.BackendPools))
		for _, pool := range plan.BackendPools {
			pools[pool.ID] = pool
		}
		type tenantPolicy struct {
			tenant iam.Tenant
			policy iam.Policy
		}
		policies := make(map[string]tenantPolicy)
		missing := make(map[string]bool)
		seen := make(map[string]uint32)
		type enforcementReason struct {
			tenantID string
			reason   string
		}
		reasons := make(map[string]enforcementReason)
		changed := false
		for index := range plan.Forwards {
			forward := &plan.Forwards[index]
			if forward.UserID == "owner" || forward.Lifecycle == spec.LifecycleForceDeleting {
				continue
			}
			currentCount := seen[forward.UserID]
			seen[forward.UserID] = currentCount + 1
			assigned, exists := policies[forward.UserID]
			if !exists && !missing[forward.UserID] {
				tenant, tenantErr := s.TenantByID(ctx, forward.UserID)
				if errors.Is(tenantErr, iam.ErrNotFound) {
					missing[forward.UserID] = true
					continue
				}
				if tenantErr != nil {
					return paused, tenantErr
				}
				policy, policyErr := s.TenantPolicy(ctx, forward.UserID)
				if policyErr != nil {
					return paused, policyErr
				}
				assigned = tenantPolicy{tenant: tenant, policy: policy}
				policies[forward.UserID] = assigned
			}
			if missing[forward.UserID] {
				continue
			}
			if forward.Lifecycle == spec.LifecyclePaused {
				continue
			}
			reason := ""
			if assigned.tenant.Status != iam.StatusActive || assigned.tenant.ExpiresAt != nil && !now.UTC().Before(assigned.tenant.ExpiresAt.UTC()) {
				reason = "tenant is disabled or expired"
			} else {
				pool, exists := pools[forward.BackendPoolID]
				if !exists || len(pool.Backends) == 0 {
					reason = "backend pool is missing"
				} else {
					for _, backend := range pool.Backends {
						resolved := resolvedTenantForward(*forward, backend.Target)
						if policyErr := assigned.policy.AuthorizeForward(resolved, currentCount, assigned.tenant.ExpiresAt, now.UTC()); policyErr != nil {
							reason = iam.PolicyReason(policyErr)
							break
						}
					}
				}
			}
			if reason == "" {
				continue
			}
			forward.Lifecycle = spec.LifecyclePaused
			forward.DrainDeadline = nil
			forward.ResourceVersion++
			reasons[forward.ID] = enforcementReason{tenantID: forward.UserID, reason: reason}
			changed = true
		}
		for tenantID, assigned := range policies {
			expected, err := assigned.policy.DataPlanePolicy()
			if err != nil {
				return paused, err
			}
			if synchronizeTenantUserPolicy(&plan, tenantID, expected) {
				changed = true
			}
		}
		if !changed {
			continue
		}
		plan.Revision = record.MaximumRevision + 1
		if _, err := s.ApplyClusterPlan(ctx, plan, actor); err != nil {
			if errors.Is(err, ErrRolloutInProgress) || errors.Is(err, ErrPlanRevisionConflict) {
				continue
			}
			return paused, fmt.Errorf("apply tenant policy enforcement to plan %s: %w", planID, err)
		}
		for forwardID, enforcement := range reasons {
			if err := s.RecordManagementAudit(ctx, iam.AuditEvent{
				ActorUsername: actor, ActorRole: iam.Role("system"), TenantID: enforcement.tenantID,
				Action: "tenant.policy.enforce", ResourceType: "forward", ResourceID: forwardID, Outcome: "success",
				Detail: map[string]any{"reason": enforcement.reason, "plan_id": plan.ID, "plan_revision": plan.Revision},
			}); err != nil {
				return paused, err
			}
			paused++
		}
	}
	return paused, nil
}

func synchronizeTenantUserPolicy(plan *cluster.Plan, tenantID string, expected *spec.UserPolicySpec) bool {
	index := -1
	for i := range plan.UserPolicies {
		if plan.UserPolicies[i].UserID == tenantID {
			index = i
			break
		}
	}
	if expected == nil {
		if index < 0 {
			return false
		}
		plan.UserPolicies = append(plan.UserPolicies[:index], plan.UserPolicies[index+1:]...)
		return true
	}
	if index >= 0 && userPoliciesEqual(plan.UserPolicies[index], *expected) {
		return false
	}
	if index >= 0 {
		plan.UserPolicies[index] = *expected
	} else {
		plan.UserPolicies = append(plan.UserPolicies, *expected)
	}
	return true
}

func userPoliciesEqual(first, second spec.UserPolicySpec) bool {
	if first.UserID != second.UserID || first.TrafficClassID != second.TrafficClassID || first.ResourceVersion != second.ResourceVersion {
		return false
	}
	if first.RateLimit == nil != (second.RateLimit == nil) || first.TrafficQuota == nil != (second.TrafficQuota == nil) {
		return false
	}
	if first.RateLimit != nil && *first.RateLimit != *second.RateLimit {
		return false
	}
	return first.TrafficQuota == nil || *first.TrafficQuota == *second.TrafficQuota
}

func resolvedTenantForward(forward cluster.Forward, target spec.Endpoint) spec.ForwardSpec {
	resolved := spec.ForwardSpec{
		ID: forward.ID, UserID: forward.UserID, Protocols: forward.Protocols, Listen: forward.Listen, Target: target,
		PathMode: forward.PathMode, SNAT: forward.SNAT, RateLimit: forward.RateLimit, TrafficQuota: forward.TrafficQuota,
		ExpiresAt: forward.ExpiresAt, Lifecycle: forward.Lifecycle, ResourceVersion: forward.ResourceVersion,
	}
	if len(forward.Ingress.NodeIDs) == 1 {
		resolved.IngressNodeID = forward.Ingress.NodeIDs[0]
	}
	if forward.Exit != nil && len(forward.Exit.NodeIDs) == 1 {
		resolved.ExitNodeID = forward.Exit.NodeIDs[0]
	}
	return resolved
}
