package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"

	"flux.local/flux/internal/controller/iam"
	"flux.local/flux/internal/spec"
)

// EnforceTrafficQuotas promotes node-local runtime quota pauses into the
// durable cluster plan. This keeps management reads, later reconciles, and the
// node Desired State on the same lifecycle intent.
func (s *Store) EnforceTrafficQuotas(ctx context.Context, actor string, limit int, now time.Time) (int, error) {
	if err := validateActor(actor); err != nil {
		return 0, err
	}
	if limit < 1 || limit > 100 {
		return 0, errors.New("traffic quota enforcement limit must be between 1 and 100")
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
		return 0, fmt.Errorf("list plans for traffic quota enforcement: %w", err)
	}
	var planIDs []string
	for rows.Next() {
		var planID string
		if err := rows.Scan(&planID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan traffic quota plan: %w", err)
		}
		planIDs = append(planIDs, planID)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close traffic quota plans: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate traffic quota plans: %w", err)
	}

	paused := 0
	for _, planID := range planIDs {
		record, err := s.ActiveClusterPlan(ctx, planID)
		if err != nil {
			return paused, err
		}
		plan := record.Plan.Canonical()

		type exceededQuota struct {
			used  string
			limit uint64
			scope string
		}
		exceededUsers := make(map[string]exceededQuota)
		for _, policy := range plan.UserPolicies {
			if policy.TrafficQuota == nil {
				continue
			}
			exceeded, used, err := clusterQuotaUsage(ctx, s.pool, `
SELECT CAST(COALESCE(SUM(bytes),0) AS TEXT)
FROM usage_rollups
WHERE user_id=$1
`, policy.UserID, policy.TrafficQuota.Bytes)
			if err != nil {
				return paused, err
			}
			if exceeded {
				exceededUsers[policy.UserID] = exceededQuota{
					used: used, limit: policy.TrafficQuota.Bytes, scope: "user",
				}
			}
		}

		reasons := make(map[string]exceededQuota)
		changed := false
		for index := range plan.Forwards {
			forward := &plan.Forwards[index]
			if forward.Lifecycle == spec.LifecyclePaused || forward.Lifecycle == spec.LifecycleForceDeleting {
				continue
			}
			reason, exceeded := exceededUsers[forward.UserID]
			if !exceeded && forward.TrafficQuota != nil {
				var used string
				exceeded, used, err = clusterQuotaUsage(ctx, s.pool, `
SELECT CAST(COALESCE(SUM(bytes),0) AS TEXT)
FROM usage_rollups
WHERE forward_id=$1
`, forward.ID, forward.TrafficQuota.Bytes)
				if err != nil {
					return paused, err
				}
				if exceeded {
					reason = exceededQuota{
						used: used, limit: forward.TrafficQuota.Bytes, scope: "forward",
					}
				}
			}
			if !exceeded {
				continue
			}
			forward.Lifecycle = spec.LifecyclePaused
			forward.DrainDeadline = nil
			forward.ResourceVersion++
			reasons[forward.ID] = reason
			changed = true
		}
		if !changed {
			continue
		}

		plan.Revision = record.MaximumRevision + 1
		if _, err := s.ApplyClusterPlan(ctx, plan, actor); err != nil {
			if errors.Is(err, ErrRolloutInProgress) || errors.Is(err, ErrPlanRevisionConflict) {
				continue
			}
			return paused, fmt.Errorf("apply traffic quota enforcement to plan %s: %w", planID, err)
		}
		for forwardID, reason := range reasons {
			if err := s.RecordManagementAudit(ctx, iam.AuditEvent{
				ActorUsername: actor, ActorRole: iam.Role("system"),
				Action: "traffic.quota.enforce", ResourceType: "forward", ResourceID: forwardID, Outcome: "success",
				Detail: map[string]any{
					"scope": reason.scope, "used_bytes": reason.used,
					"quota_bytes": reason.limit, "plan_id": plan.ID, "plan_revision": plan.Revision,
					"evaluated_at": now.UTC(),
				},
			}); err != nil {
				return paused, err
			}
			paused++
		}
	}
	return paused, nil
}

func clusterQuotaUsage(ctx context.Context, source queryer, query, subjectID string, quota uint64) (bool, string, error) {
	var total string
	if err := source.QueryRow(ctx, query, subjectID).Scan(&total); errors.Is(err, sql.ErrNoRows) {
		return false, "0", nil
	} else if err != nil {
		return false, "", fmt.Errorf("read cluster traffic quota total: %w", err)
	}
	value, ok := new(big.Int).SetString(total, 10)
	if !ok {
		return false, "", errors.New("cluster traffic quota total is invalid")
	}
	limit := new(big.Int).SetUint64(quota)
	return value.Cmp(limit) >= 0, total, nil
}
