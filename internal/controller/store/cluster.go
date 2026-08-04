package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/cluster"
	"flux.local/flux/internal/health"
	"flux.local/flux/internal/spec"
)

var (
	ErrPlanRevisionConflict = errors.New("cluster plan revision conflicts with stored history")
	ErrClusterPlanNotFound  = errors.New("cluster plan does not exist")
	ErrHealthProbeMissing   = errors.New("backend health report does not match its desired generation")
	ErrServiceVIPCapacity   = errors.New("service CIDR capacity is exhausted")
	ErrServiceVIPMigration  = errors.New("service VIP is outside the active service CIDRs")
	ErrRolloutInProgress    = errors.New("cluster plan has an active rollout")
)

type ClusterApplyResult struct {
	PlanID           string              `json:"plan_id"`
	Revision         uint64              `json:"revision"`
	Checksum         string              `json:"checksum"`
	Scheduled        bool                `json:"scheduled"`
	RolloutID        int64               `json:"rollout_id,omitempty"`
	Published        []SnapshotRecord    `json:"published,omitempty"`
	Placements       []cluster.Placement `json:"placements,omitempty"`
	Alerts           []cluster.Alert     `json:"alerts,omitempty"`
	LastError        string              `json:"last_error,omitempty"`
	RolledBack       bool                `json:"rolled_back,omitempty"`
	PreviousRevision uint64              `json:"previous_revision,omitempty"`
}

type ClusterStatus struct {
	PlanID                 string              `json:"plan_id"`
	ActiveRevision         uint64              `json:"active_revision"`
	Checksum               string              `json:"checksum"`
	LastScheduledAt        *time.Time          `json:"last_scheduled_at,omitempty"`
	LastError              string              `json:"last_error,omitempty"`
	ActiveAlerts           int                 `json:"active_alerts"`
	Paused                 bool                `json:"paused"`
	LatestRollout          string              `json:"latest_rollout_status,omitempty"`
	LatestRolloutID        int64               `json:"latest_rollout_id,omitempty"`
	LatestRolloutStage     int                 `json:"latest_rollout_stage,omitempty"`
	LatestRolloutWave      string              `json:"latest_rollout_wave,omitempty"`
	LatestRolloutPhase     string              `json:"latest_rollout_phase,omitempty"`
	LatestRolloutBakeUntil *time.Time          `json:"latest_rollout_bake_until,omitempty"`
	RolloutFailure         string              `json:"rollout_failure,omitempty"`
	Placements             []cluster.Placement `json:"placements"`
}

// ActiveClusterPlan contains the active plan and the highest revision ever
// stored for it. MaximumRevision can be greater than Plan.Revision after a
// rollback, so callers must use it when allocating the next immutable revision.
type ActiveClusterPlan struct {
	Plan            cluster.Plan `json:"plan"`
	MaximumRevision uint64       `json:"maximum_revision"`
}

type clusterRolloutDetail struct {
	Version          uint32                `json:"version"`
	CommitPlacements bool                  `json:"commit_placements"`
	Placements       []cluster.Placement   `json:"placements,omitempty"`
	ServiceVIPs      map[string]netip.Addr `json:"service_vips,omitempty"`
	RetiredNodeIDs   []string              `json:"retired_node_ids,omitempty"`
	CanaryForwardIDs []string              `json:"canary_forward_ids,omitempty"`
}

func (s *Store) ApplyClusterPlan(ctx context.Context, plan cluster.Plan, actor string) (ClusterApplyResult, error) {
	if err := plan.Validate(); err != nil {
		return ClusterApplyResult{}, err
	}
	if err := validateActor(actor); err != nil {
		return ClusterApplyResult{}, err
	}
	plan = plan.Canonical()
	encoded, err := cluster.EncodePlanJSON(plan)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	checksum, err := plan.Checksum()
	if err != nil {
		return ClusterApplyResult{}, fmt.Errorf("checksum cluster plan: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ClusterApplyResult{}, fmt.Errorf("begin cluster plan transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := lockClusterPlan(ctx, tx, plan.ID); err != nil {
		return ClusterApplyResult{}, err
	}
	if err := ensureNoActiveClusterRollout(ctx, tx, plan.ID); err != nil {
		return ClusterApplyResult{}, err
	}
	var previousRevision int64
	var exists bool
	err = tx.QueryRow(ctx, `SELECT active_revision FROM cluster_plans WHERE id=$1 FOR UPDATE`, plan.ID).Scan(&previousRevision)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.Exec(ctx, `INSERT INTO cluster_plans(id,active_revision,active_checksum) VALUES ($1,$2,$3)`, plan.ID, int64(plan.Revision), checksum); err != nil {
			return ClusterApplyResult{}, fmt.Errorf("insert cluster plan: %w", err)
		}
	} else if err != nil {
		return ClusterApplyResult{}, fmt.Errorf("lock cluster plan: %w", err)
	} else {
		exists = true
		var maximum int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0) FROM cluster_plan_revisions WHERE plan_id=$1`, plan.ID).Scan(&maximum); err != nil {
			return ClusterApplyResult{}, fmt.Errorf("read cluster plan history: %w", err)
		}
		if int64(plan.Revision) <= maximum {
			var storedChecksum string
			err := tx.QueryRow(ctx, `SELECT checksum FROM cluster_plan_revisions WHERE plan_id=$1 AND revision=$2`, plan.ID, int64(plan.Revision)).Scan(&storedChecksum)
			if errors.Is(err, sql.ErrNoRows) || err == nil && storedChecksum != checksum {
				return ClusterApplyResult{}, ErrPlanRevisionConflict
			}
			if err != nil {
				return ClusterApplyResult{}, fmt.Errorf("read matching cluster revision: %w", err)
			}
			if uint64(previousRevision) != plan.Revision {
				return ClusterApplyResult{}, errors.New("historical cluster revision must be activated with plan-rollback")
			}
		} else if _, err := tx.Exec(ctx, `INSERT INTO cluster_plan_revisions(plan_id,revision,checksum,plan,actor) VALUES ($1,$2,$3,$4,$5)`, plan.ID, int64(plan.Revision), checksum, encoded, actor); err != nil {
			return ClusterApplyResult{}, fmt.Errorf("insert cluster plan revision: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE cluster_plans SET active_revision=$2,active_checksum=$3,reconcile_after=now(),paused_at=NULL,updated_at=now() WHERE id=$1`, plan.ID, int64(plan.Revision), checksum); err != nil {
			return ClusterApplyResult{}, fmt.Errorf("activate cluster plan revision: %w", err)
		}
	}
	if !exists {
		if _, err := tx.Exec(ctx, `INSERT INTO cluster_plan_revisions(plan_id,revision,checksum,plan,actor) VALUES ($1,$2,$3,$4,$5)`, plan.ID, int64(plan.Revision), checksum, encoded, actor); err != nil {
			return ClusterApplyResult{}, fmt.Errorf("insert initial cluster plan revision: %w", err)
		}
	}
	if err := syncNodeProfiles(ctx, tx, plan); err != nil {
		return ClusterApplyResult{}, err
	}
	result := ClusterApplyResult{PlanID: plan.ID, Revision: plan.Revision, Checksum: checksum, PreviousRevision: uint64(previousRevision)}
	if _, err := tx.Exec(ctx, `SAVEPOINT flux_cluster_schedule`); err != nil {
		return ClusterApplyResult{}, fmt.Errorf("create cluster schedule savepoint: %w", err)
	}
	forcePublish := !exists || uint64(previousRevision) != plan.Revision
	scheduled, err := s.schedulePlanTx(ctx, tx, plan, actor, "apply", forcePublish, uint64(previousRevision), time.Now().UTC())
	if err != nil {
		if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT flux_cluster_schedule`); rollbackErr != nil {
			return ClusterApplyResult{}, fmt.Errorf("rollback failed cluster schedule: %v (original: %w)", rollbackErr, err)
		}
		if !deferrableScheduleError(err) {
			return ClusterApplyResult{}, err
		}
		result.LastError = truncateClusterError(err)
		if _, updateErr := tx.Exec(ctx, `UPDATE cluster_plans SET last_error=$2,reconcile_after=$3,updated_at=now() WHERE id=$1`, plan.ID, result.LastError, time.Now().UTC().Add(5*time.Second)); updateErr != nil {
			return ClusterApplyResult{}, fmt.Errorf("record blocked cluster schedule: %w", updateErr)
		}
		if auditErr := insertClusterAudit(ctx, tx, plan.ID, plan.Revision, actor, "plan_schedule_blocked", plan.ID, map[string]any{"error": result.LastError}); auditErr != nil {
			return ClusterApplyResult{}, auditErr
		}
	} else {
		result = scheduled
		result.Checksum = checksum
		result.PreviousRevision = uint64(previousRevision)
	}
	if err := tx.Commit(ctx); err != nil {
		return ClusterApplyResult{}, fmt.Errorf("commit cluster plan: %w", err)
	}
	return result, nil
}

func (s *Store) RollbackClusterPlan(ctx context.Context, planID string, revision uint64, actor string) (ClusterApplyResult, error) {
	if err := spec.ValidateIdentifier("plan_id", planID); err != nil {
		return ClusterApplyResult{}, err
	}
	if revision == 0 {
		return ClusterApplyResult{}, errors.New("rollback revision must be greater than zero")
	}
	if err := validateActor(actor); err != nil {
		return ClusterApplyResult{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ClusterApplyResult{}, fmt.Errorf("begin cluster rollback: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := lockClusterPlan(ctx, tx, planID); err != nil {
		return ClusterApplyResult{}, err
	}
	if err := ensureNoActiveClusterRollout(ctx, tx, planID); err != nil {
		return ClusterApplyResult{}, err
	}
	var previous int64
	if err := tx.QueryRow(ctx, `SELECT active_revision FROM cluster_plans WHERE id=$1 FOR UPDATE`, planID).Scan(&previous); errors.Is(err, sql.ErrNoRows) {
		return ClusterApplyResult{}, errors.New("cluster plan does not exist")
	} else if err != nil {
		return ClusterApplyResult{}, fmt.Errorf("lock rollback plan: %w", err)
	}
	var encoded []byte
	var checksum string
	if err := tx.QueryRow(ctx, `SELECT plan,checksum FROM cluster_plan_revisions WHERE plan_id=$1 AND revision=$2`, planID, int64(revision)).Scan(&encoded, &checksum); errors.Is(err, sql.ErrNoRows) {
		return ClusterApplyResult{}, errors.New("rollback revision does not exist")
	} else if err != nil {
		return ClusterApplyResult{}, fmt.Errorf("read rollback revision: %w", err)
	}
	plan, err := cluster.DecodePlanJSON(encoded)
	if err != nil {
		return ClusterApplyResult{}, fmt.Errorf("decode rollback plan: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE cluster_plans SET active_revision=$2,active_checksum=$3,reconcile_after=now(),paused_at=NULL,updated_at=now() WHERE id=$1`, planID, int64(revision), checksum); err != nil {
		return ClusterApplyResult{}, fmt.Errorf("activate rollback revision: %w", err)
	}
	if err := syncNodeProfiles(ctx, tx, plan); err != nil {
		return ClusterApplyResult{}, err
	}
	result, err := s.schedulePlanTx(ctx, tx, plan, actor, "rollback", true, uint64(previous), time.Now().UTC())
	if err != nil {
		return ClusterApplyResult{}, err
	}
	result.Checksum = checksum
	result.RolledBack = true
	result.PreviousRevision = uint64(previous)
	if err := tx.Commit(ctx); err != nil {
		return ClusterApplyResult{}, fmt.Errorf("commit cluster rollback: %w", err)
	}
	return result, nil
}

func (s *Store) ReconcileClusterPlans(ctx context.Context, owner string, limit int, now time.Time) (int, error) {
	if owner == "" || limit < 1 || limit > 100 {
		return 0, errors.New("invalid cluster reconciler arguments")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin cluster reconciliation: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
SELECT r.plan
FROM cluster_plans p
JOIN cluster_plan_revisions r ON r.plan_id=p.id AND r.revision=p.active_revision
WHERE p.paused_at IS NULL AND p.reconcile_after <= $1
ORDER BY p.reconcile_after,p.id
LIMIT $2`, now.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("claim cluster plans: %w", err)
	}
	var plans []cluster.Plan
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan cluster plan: %w", err)
		}
		plan, err := cluster.DecodePlanJSON(encoded)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("decode active cluster plan: %w", err)
		}
		plans = append(plans, plan)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate cluster plans: %w", err)
	}
	rows.Close()
	published := 0
	actor := "system:" + owner
	if len(actor) > 256 {
		actor = actor[:256]
	}
	for index, plan := range plans {
		savepoint := fmt.Sprintf("flux_cluster_reconcile_%d", index)
		if _, err := tx.Exec(ctx, "SAVEPOINT "+savepoint); err != nil {
			return published, fmt.Errorf("create cluster reconcile savepoint: %w", err)
		}
		result, err := s.schedulePlanTx(ctx, tx, plan, actor, "health_reconcile", false, plan.Revision, now.UTC())
		if err != nil {
			if _, rollbackErr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); rollbackErr != nil {
				return published, fmt.Errorf("rollback cluster reconcile: %v (original: %w)", rollbackErr, err)
			}
			message := truncateClusterError(err)
			if _, updateErr := tx.Exec(ctx, `UPDATE cluster_plans SET last_error=$2,reconcile_after=$3,updated_at=now() WHERE id=$1`, plan.ID, message, now.UTC().Add(5*time.Second)); updateErr != nil {
				return published, fmt.Errorf("record cluster reconcile failure: %w", updateErr)
			}
			continue
		}
		if result.Scheduled {
			published++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return published, fmt.Errorf("commit cluster reconciliation: %w", err)
	}
	return published, nil
}

func (s *Store) RecordBackendHealth(ctx context.Context, report health.Report) error {
	if err := spec.ValidateIdentifier("node_id", report.NodeID); err != nil {
		return err
	}
	if report.Generation == 0 || report.ResourceVersion == 0 || report.ObservedAt.IsZero() {
		return errors.New("backend health identity or version is invalid")
	}
	if report.Status != health.StatusUnknown && report.Status != health.StatusHealthy && report.Status != health.StatusUnhealthy {
		return errors.New("backend health status is invalid")
	}
	if report.Latency < 0 {
		return errors.New("backend health latency must not be negative")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin backend health transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	var desiredJSON []byte
	if err := tx.QueryRow(ctx, `SELECT desired_state FROM node_generations WHERE node_id=$1 AND generation=$2`, report.NodeID, int64(report.Generation)).Scan(&desiredJSON); errors.Is(err, sql.ErrNoRows) {
		return ErrGenerationMissing
	} else if err != nil {
		return fmt.Errorf("read health generation: %w", err)
	}
	desired, err := spec.DecodeDesiredJSON(desiredJSON)
	if err != nil {
		return fmt.Errorf("decode health generation: %w", err)
	}
	matched := false
	for _, check := range desired.HealthChecks {
		if check.PoolID == report.PoolID && check.BackendID == report.BackendID && check.ResourceVersion == report.ResourceVersion {
			matched = true
			break
		}
	}
	if !matched || !strings.HasPrefix(desired.ManagementDomain, "cluster:") {
		return ErrHealthProbeMissing
	}
	planID := strings.TrimPrefix(desired.ManagementDomain, "cluster:")
	var previousStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM backend_health_observations WHERE plan_id=$1 AND node_id=$2 AND pool_id=$3 AND backend_id=$4 FOR UPDATE`, planID, report.NodeID, report.PoolID, report.BackendID).Scan(&previousStatus); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("lock previous backend health: %w", err)
	}
	command, err := tx.Exec(ctx, `
INSERT INTO backend_health_observations(plan_id,node_id,pool_id,backend_id,generation,resource_version,status,latency_milliseconds,error_message,observed_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (plan_id,node_id,pool_id,backend_id) DO UPDATE SET
  generation=EXCLUDED.generation,resource_version=EXCLUDED.resource_version,status=EXCLUDED.status,
  latency_milliseconds=EXCLUDED.latency_milliseconds,error_message=EXCLUDED.error_message,
  observed_at=EXCLUDED.observed_at,received_at=now()
WHERE backend_health_observations.observed_at <= EXCLUDED.observed_at`, planID, report.NodeID, report.PoolID, report.BackendID,
		int64(report.Generation), int64(report.ResourceVersion), string(report.Status), report.Latency.Milliseconds(), truncateHealthError(report.Error), report.ObservedAt.UTC())
	if err != nil {
		return fmt.Errorf("upsert backend health: %w", err)
	}
	if command.RowsAffected() != 0 && previousStatus != string(report.Status) {
		if _, err := tx.Exec(ctx, `UPDATE cluster_plans SET reconcile_after=MIN(reconcile_after,CURRENT_TIMESTAMP),updated_at=CURRENT_TIMESTAMP WHERE id=$1`, planID); err != nil {
			return fmt.Errorf("request health reconciliation: %w", err)
		}
		if err := insertClusterAudit(ctx, tx, planID, 0, "system:agent:"+report.NodeID, "backend_health_transition", report.PoolID+"/"+report.BackendID, map[string]any{"previous": previousStatus, "status": report.Status, "generation": report.Generation}); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit backend health: %w", err)
	}
	return nil
}

func (s *Store) ClusterStatus(ctx context.Context, planID string) (ClusterStatus, error) {
	if err := spec.ValidateIdentifier("plan_id", planID); err != nil {
		return ClusterStatus{}, err
	}
	var status ClusterStatus
	var revision int64
	var scheduled *time.Time
	err := s.pool.QueryRow(ctx, `
SELECT p.id,p.active_revision,p.active_checksum,p.last_scheduled_at,COALESCE(p.last_error,''),
       (SELECT count(*) FROM cluster_alerts a WHERE a.plan_id=p.id AND a.status='active'),
       p.paused_at IS NOT NULL,
       COALESCE((SELECT r.status FROM cluster_rollouts r WHERE r.plan_id=p.id ORDER BY r.id DESC LIMIT 1),'')
FROM cluster_plans p WHERE p.id=$1`, planID).Scan(&status.PlanID, &revision, &status.Checksum, &scheduled, &status.LastError, &status.ActiveAlerts, &status.Paused, &status.LatestRollout)
	if errors.Is(err, sql.ErrNoRows) {
		return ClusterStatus{}, errors.New("cluster plan does not exist")
	}
	if err != nil {
		return ClusterStatus{}, fmt.Errorf("read cluster status: %w", err)
	}
	status.ActiveRevision = uint64(revision)
	status.LastScheduledAt = scheduled
	if status.LatestRollout != "" {
		if err := s.pool.QueryRow(ctx, `
SELECT r.id,r.current_stage,COALESCE(s.wave,''),COALESCE(s.phase,''),r.bake_until,r.failure_message
FROM cluster_rollouts r
LEFT JOIN cluster_rollout_stages s ON s.rollout_id=r.id AND s.stage_order=r.current_stage
WHERE r.plan_id=$1 ORDER BY r.id DESC LIMIT 1`, planID).Scan(&status.LatestRolloutID, &status.LatestRolloutStage, &status.LatestRolloutWave, &status.LatestRolloutPhase, &status.LatestRolloutBakeUntil, &status.RolloutFailure); err != nil {
			return ClusterStatus{}, fmt.Errorf("read latest cluster rollout stage: %w", err)
		}
	}
	placements, err := loadPlacements(ctx, s.pool, planID)
	if err != nil {
		return ClusterStatus{}, err
	}
	status.Placements = placements
	return status, nil
}

func (s *Store) ActiveClusterPlan(ctx context.Context, planID string) (ActiveClusterPlan, error) {
	if err := spec.ValidateIdentifier("plan_id", planID); err != nil {
		return ActiveClusterPlan{}, err
	}
	var encoded []byte
	var maximum int64
	err := s.pool.QueryRow(ctx, `
SELECT r.plan,(SELECT COALESCE(MAX(history.revision),p.active_revision)
               FROM cluster_plan_revisions history WHERE history.plan_id=p.id)
FROM cluster_plans p
JOIN cluster_plan_revisions r ON r.plan_id=p.id AND r.revision=p.active_revision
WHERE p.id=$1`, planID).Scan(&encoded, &maximum)
	if errors.Is(err, sql.ErrNoRows) {
		return ActiveClusterPlan{}, ErrClusterPlanNotFound
	}
	if err != nil {
		return ActiveClusterPlan{}, fmt.Errorf("read active cluster plan: %w", err)
	}
	plan, err := cluster.DecodePlanJSON(encoded)
	if err != nil {
		return ActiveClusterPlan{}, fmt.Errorf("decode active cluster plan: %w", err)
	}
	if maximum < 1 {
		return ActiveClusterPlan{}, errors.New("active cluster plan has invalid revision history")
	}
	return ActiveClusterPlan{Plan: plan, MaximumRevision: uint64(maximum)}, nil
}

// FinalizeClusterDeletes removes forwards from the durable plan only after
// every node in their committed placement has acknowledged a generation that
// no longer contains the forward. Agent-side force deletion therefore gets a
// chance to clear conntrack before the intent itself disappears.
func (s *Store) FinalizeClusterDeletes(ctx context.Context, actor string, limit int, now time.Time) (int, error) {
	if err := validateActor(actor); err != nil {
		return 0, err
	}
	if limit < 1 || limit > 100 {
		return 0, errors.New("cluster delete finalizer limit must be between 1 and 100")
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
		return 0, fmt.Errorf("list cluster plans for delete finalization: %w", err)
	}
	var planIDs []string
	for rows.Next() {
		var planID string
		if err := rows.Scan(&planID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan delete finalizer plan: %w", err)
		}
		planIDs = append(planIDs, planID)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close delete finalizer plans: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate delete finalizer plans: %w", err)
	}

	finalized := 0
	for _, planID := range planIDs {
		record, err := s.ActiveClusterPlan(ctx, planID)
		if err != nil {
			return finalized, err
		}
		removeIDs := make(map[string]struct{})
		for _, forward := range record.Plan.Forwards {
			eligible := forward.Lifecycle == spec.LifecycleForceDeleting ||
				forward.Lifecycle == spec.LifecycleDraining && forward.DrainDeadline != nil && !now.UTC().Before(forward.DrainDeadline.UTC())
			if !eligible {
				continue
			}
			ready, err := s.clusterForwardAbsentFromLatestDesired(ctx, planID, forward.ID)
			if err != nil {
				return finalized, err
			}
			if ready {
				removeIDs[forward.ID] = struct{}{}
			}
		}
		if len(removeIDs) == 0 {
			continue
		}
		plan := record.Plan.Canonical()
		keptForwards := plan.Forwards[:0]
		removedPools := make(map[string]struct{}, len(removeIDs))
		for _, forward := range plan.Forwards {
			if _, remove := removeIDs[forward.ID]; remove {
				removedPools[forward.BackendPoolID] = struct{}{}
				continue
			}
			keptForwards = append(keptForwards, forward)
		}
		plan.Forwards = keptForwards
		usedPools := make(map[string]struct{}, len(plan.Forwards))
		for _, forward := range plan.Forwards {
			usedPools[forward.BackendPoolID] = struct{}{}
		}
		keptPools := plan.BackendPools[:0]
		for _, pool := range plan.BackendPools {
			_, wasRemoved := removedPools[pool.ID]
			_, stillUsed := usedPools[pool.ID]
			if !wasRemoved || stillUsed {
				keptPools = append(keptPools, pool)
			}
		}
		plan.BackendPools = keptPools
		plan.Revision = record.MaximumRevision + 1
		if _, err := s.ApplyClusterPlan(ctx, plan, actor); err != nil {
			if errors.Is(err, ErrRolloutInProgress) || errors.Is(err, ErrPlanRevisionConflict) {
				continue
			}
			return finalized, fmt.Errorf("finalize deleted forwards in plan %s: %w", planID, err)
		}
		finalized += len(removeIDs)
	}
	return finalized, nil
}

func (s *Store) clusterForwardAbsentFromLatestDesired(ctx context.Context, planID, forwardID string) (bool, error) {
	rows, err := s.pool.Query(ctx, `
SELECT ingress_node_id FROM cluster_forward_placements WHERE plan_id=$1 AND forward_id=$2
UNION
SELECT exit_node_id FROM cluster_forward_placements WHERE plan_id=$1 AND forward_id=$2 AND exit_node_id IS NOT NULL`, planID, forwardID)
	if err != nil {
		return false, fmt.Errorf("read delete placement for %s: %w", forwardID, err)
	}
	var nodeIDs []string
	for rows.Next() {
		var nodeID string
		if err := rows.Scan(&nodeID); err != nil {
			rows.Close()
			return false, fmt.Errorf("scan delete placement for %s: %w", forwardID, err)
		}
		nodeIDs = append(nodeIDs, nodeID)
	}
	if err := rows.Close(); err != nil {
		return false, fmt.Errorf("close delete placements for %s: %w", forwardID, err)
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate delete placements for %s: %w", forwardID, err)
	}
	for _, nodeID := range nodeIDs {
		var encoded []byte
		err := s.pool.QueryRow(ctx, `
SELECT g.desired_state
FROM nodes n
JOIN node_generations g ON g.node_id=n.id AND g.generation=n.desired_generation
WHERE n.id=$1 AND n.desired_generation>0`, nodeID).Scan(&encoded)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("read latest desired state for delete on %s: %w", nodeID, err)
		}
		desired, err := spec.DecodeDesiredJSON(encoded)
		if err != nil {
			return false, fmt.Errorf("decode latest desired state for delete on %s: %w", nodeID, err)
		}
		for _, forward := range desired.Forwards {
			if forward.ID == forwardID {
				return false, nil
			}
		}
	}
	return true, nil
}

func loadPlacements(ctx context.Context, query queryer, planID string) ([]cluster.Placement, error) {
	rows, err := query.Query(ctx, `SELECT forward_id,ingress_node_id,COALESCE(exit_node_id,''),backend_id,target,target_port,COALESCE(fabric_in_id,''),COALESCE(fabric_out_id,'') FROM cluster_forward_placements WHERE plan_id=$1 ORDER BY forward_id`, planID)
	if err != nil {
		return nil, fmt.Errorf("read cluster placements: %w", err)
	}
	defer rows.Close()
	var placements []cluster.Placement
	for rows.Next() {
		var placement cluster.Placement
		var target string
		var port int
		if err := rows.Scan(&placement.ForwardID, &placement.IngressID, &placement.ExitID, &placement.BackendID, &target, &port, &placement.FabricInID, &placement.FabricOutID); err != nil {
			return nil, fmt.Errorf("scan cluster placement: %w", err)
		}
		address, err := netip.ParseAddr(target)
		if err != nil {
			return nil, fmt.Errorf("parse stored placement target: %w", err)
		}
		placement.Target = spec.Endpoint{Address: address.Unmap(), Port: uint16(port)}
		if placement.ExitID == "" {
			placement.PathMode = spec.PathDirect
		} else {
			placement.PathMode = spec.PathViaExit
		}
		placements = append(placements, placement)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cluster placements: %w", err)
	}
	return placements, nil
}

func (s *Store) schedulePlanTx(ctx context.Context, tx *transaction, plan cluster.Plan, actor, action string, force bool, previousRevision uint64, now time.Time) (ClusterApplyResult, error) {
	var inFlightID int64
	err := tx.QueryRow(ctx, `SELECT id FROM cluster_rollouts WHERE plan_id=$1 AND status IN ('publishing','awaiting_ack','baking','rollback_pending','rolling_back') ORDER BY id LIMIT 1 FOR UPDATE`, plan.ID).Scan(&inFlightID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ClusterApplyResult{}, fmt.Errorf("check in-flight cluster rollouts: %w", err)
	}
	if err == nil {
		if _, err := tx.Exec(ctx, `UPDATE cluster_plans SET reconcile_after=$2,updated_at=now() WHERE id=$1`, plan.ID, now.Add(time.Second)); err != nil {
			return ClusterApplyResult{}, fmt.Errorf("defer cluster schedule behind in-flight rollout: %w", err)
		}
		return ClusterApplyResult{PlanID: plan.ID, Revision: plan.Revision, Scheduled: false, LastError: "waiting for the previous rollout ACKs", PreviousRevision: previousRevision}, nil
	}
	runtimes, currents, err := loadNodeRuntimes(ctx, tx, plan, now)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	retired, err := loadRetiredClusterNodes(ctx, tx, plan)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	for nodeID, generation := range retired {
		currents[nodeID] = generation
	}
	previous, err := loadPlacements(ctx, tx, plan.ID)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	observations, err := loadHealthObservations(ctx, tx, plan.ID)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	operationalPlan, err := s.resolvePlanTargets(ctx, tx, plan)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	placed, err := cluster.Place(operationalPlan, runtimes, observations, previous, now)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	vips, err := allocateServiceVIPs(ctx, tx, operationalPlan, placed.Placements)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	compiled, err := cluster.Compile(operationalPlan, placed, vips, runtimes)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	for nodeID := range retired {
		compiled[nodeID] = spec.DesiredState{
			SchemaVersion: spec.CurrentSchemaVersion, NodeID: nodeID, Generation: 1,
		}
	}
	changed := force || len(retired) != 0 || !placementsEqual(previous, placed.Placements)
	metadataChanged := action != "health_reconcile" || len(retired) != 0 || !placementsEqual(previous, placed.Placements)
	result := ClusterApplyResult{PlanID: plan.ID, Revision: plan.Revision, Placements: placed.Placements, Alerts: placed.Alerts, PreviousRevision: previousRevision}
	if err := syncClusterAlerts(ctx, tx, plan, actor, placed.Alerts); err != nil {
		return ClusterApplyResult{}, err
	}
	if !changed {
		if _, err := tx.Exec(ctx, `UPDATE cluster_plans SET last_scheduled_at=$2,last_error=NULL,reconcile_after=$3,updated_at=now() WHERE id=$1`, plan.ID, now, now.Add(5*time.Second)); err != nil {
			return ClusterApplyResult{}, fmt.Errorf("record unchanged cluster schedule: %w", err)
		}
		return result, nil
	}
	currentStates, err := loadCurrentDesiredStates(ctx, tx, currents)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	preserveRuntimeLifecycles(currentStates, compiled)
	rolloutStrategy := plan.EffectiveRolloutStrategy()
	stages, canaryForwards, err := cluster.BuildRolloutStages(plan.ID, rolloutStrategy, currentStates, compiled)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	if len(stages) == 0 {
		if metadataChanged {
			if err := replacePlacements(ctx, tx, plan, placed.Placements, vips); err != nil {
				return ClusterApplyResult{}, err
			}
			if err := removeRetiredNodeProfiles(ctx, tx, plan); err != nil {
				return ClusterApplyResult{}, err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE cluster_plans SET last_scheduled_at=$2,last_error=NULL,reconcile_after=$3,updated_at=now() WHERE id=$1`, plan.ID, now, now.Add(5*time.Second)); err != nil {
			return ClusterApplyResult{}, fmt.Errorf("record metadata-only cluster schedule: %w", err)
		}
		if metadataChanged {
			if err := insertClusterAudit(ctx, tx, plan.ID, plan.Revision, actor, "cluster_"+action+"_metadata", plan.ID, map[string]any{"placements": len(placed.Placements)}); err != nil {
				return ClusterApplyResult{}, err
			}
		}
		return result, nil
	}
	var rolloutID int64
	retiredNodeIDs := make([]string, 0, len(retired))
	for nodeID := range retired {
		retiredNodeIDs = append(retiredNodeIDs, nodeID)
	}
	sort.Strings(retiredNodeIDs)
	detail, err := json.Marshal(clusterRolloutDetail{
		Version: 1, CommitPlacements: true, Placements: placed.Placements, ServiceVIPs: vips,
		RetiredNodeIDs: retiredNodeIDs, CanaryForwardIDs: canaryForwards,
	})
	if err != nil {
		return ClusterApplyResult{}, fmt.Errorf("encode cluster rollout detail: %w", err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO cluster_rollouts(plan_id,revision,previous_revision,actor,action,status,detail,current_stage,auto_rollback) VALUES ($1,$2,NULLIF($3,0),$4,$5,'publishing',$6,1,true) RETURNING id`, plan.ID, int64(plan.Revision), int64(previousRevision), actor, action, detail).Scan(&rolloutID); err != nil {
		return ClusterApplyResult{}, fmt.Errorf("create cluster rollout: %w", err)
	}
	for index, stage := range stages {
		stageOrder := index + 1
		if _, err := tx.Exec(ctx, `INSERT INTO cluster_rollout_stages(rollout_id,stage_order,wave,phase,bake_seconds) VALUES ($1,$2,$3,$4,$5)`, rolloutID, stageOrder, string(stage.Wave), string(stage.Phase), int(stage.BakeSeconds)); err != nil {
			return ClusterApplyResult{}, fmt.Errorf("record cluster rollout stage %d: %w", stageOrder, err)
		}
		nodeIDs := make([]string, 0, len(stage.Desired))
		for nodeID := range stage.Desired {
			nodeIDs = append(nodeIDs, nodeID)
		}
		sort.Strings(nodeIDs)
		for _, nodeID := range nodeIDs {
			encoded, err := spec.EncodeDesiredJSON(stage.Desired[nodeID])
			if err != nil {
				return ClusterApplyResult{}, fmt.Errorf("encode rollout stage %d target for %s: %w", stageOrder, nodeID, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO cluster_rollout_nodes(rollout_id,stage_order,node_id,previous_generation,generation,desired_checksum,status,desired_state) VALUES ($1,$2,$3,0,NULL,NULL,'queued',$4)`, rolloutID, stageOrder, nodeID, encoded); err != nil {
				return ClusterApplyResult{}, fmt.Errorf("record cluster rollout stage %d target for %s: %w", stageOrder, nodeID, err)
			}
		}
	}
	baselineNodeIDs := make([]string, 0, len(currentStates))
	for nodeID := range currentStates {
		baselineNodeIDs = append(baselineNodeIDs, nodeID)
	}
	sort.Strings(baselineNodeIDs)
	for _, nodeID := range baselineNodeIDs {
		encoded, err := spec.EncodeDesiredJSON(currentStates[nodeID])
		if err != nil {
			return ClusterApplyResult{}, fmt.Errorf("encode rollout baseline for %s: %w", nodeID, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cluster_rollout_baselines(rollout_id,node_id,desired_state) VALUES ($1,$2,$3)`, rolloutID, nodeID, encoded); err != nil {
			return ClusterApplyResult{}, fmt.Errorf("record rollout baseline for %s: %w", nodeID, err)
		}
	}
	result.Published, err = s.publishClusterStageTx(ctx, tx, rolloutID, 1, now)
	if err != nil {
		return ClusterApplyResult{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE cluster_plans SET last_scheduled_at=$2,last_error=NULL,reconcile_after=$3,updated_at=now() WHERE id=$1`, plan.ID, now, now.Add(5*time.Second)); err != nil {
		return ClusterApplyResult{}, fmt.Errorf("complete cluster schedule: %w", err)
	}
	if err := insertClusterAudit(ctx, tx, plan.ID, plan.Revision, actor, "cluster_"+action, plan.ID, map[string]any{"rollout_id": rolloutID, "stages": len(stages), "first_stage_nodes": len(result.Published), "placements": len(placed.Placements), "canary_forwards": canaryForwards}); err != nil {
		return ClusterApplyResult{}, err
	}
	result.RolloutID = rolloutID
	result.Scheduled = true
	return result, nil
}

func loadCurrentDesiredStates(ctx context.Context, tx *transaction, generations map[string]int64) (map[string]spec.DesiredState, error) {
	result := make(map[string]spec.DesiredState, len(generations))
	nodeIDs := make([]string, 0, len(generations))
	for nodeID := range generations {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	for _, nodeID := range nodeIDs {
		generation := generations[nodeID]
		if generation == 0 {
			result[nodeID] = spec.DesiredState{SchemaVersion: spec.CurrentSchemaVersion, NodeID: nodeID, Generation: 1}
			continue
		}
		var encoded []byte
		if err := tx.QueryRow(ctx, `SELECT desired_state FROM node_generations WHERE node_id=$1 AND generation=$2`, nodeID, generation).Scan(&encoded); err != nil {
			return nil, fmt.Errorf("read current desired state for node %s: %w", nodeID, err)
		}
		desired, err := spec.DecodeDesiredJSON(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode current desired state for node %s: %w", nodeID, err)
		}
		desired.Generation = 1
		result[nodeID] = desired.Canonical()
	}
	return result, nil
}

func preserveRuntimeLifecycles(current, target map[string]spec.DesiredState) {
	type runtimeLifecycle struct {
		lifecycle     spec.Lifecycle
		drainDeadline *time.Time
		version       uint64
	}
	latest := make(map[string]runtimeLifecycle)
	severity := func(value spec.Lifecycle) int {
		switch value {
		case spec.LifecycleForceDeleting:
			return 4
		case spec.LifecyclePaused:
			return 3
		case spec.LifecycleDraining:
			return 2
		default:
			return 1
		}
	}
	for _, state := range current {
		for _, forward := range state.Forwards {
			candidate := runtimeLifecycle{lifecycle: forward.Lifecycle, drainDeadline: forward.DrainDeadline, version: forward.ResourceVersion}
			existing, exists := latest[forward.ID]
			if !exists || candidate.version > existing.version || candidate.version == existing.version && severity(candidate.lifecycle) > severity(existing.lifecycle) {
				latest[forward.ID] = candidate
			}
		}
	}
	for nodeID, state := range target {
		for index := range state.Forwards {
			forward := &state.Forwards[index]
			runtime, exists := latest[forward.ID]
			if !exists || runtime.version <= forward.ResourceVersion {
				continue
			}
			forward.Lifecycle = runtime.lifecycle
			forward.DrainDeadline = runtime.drainDeadline
			forward.ResourceVersion = runtime.version
		}
		target[nodeID] = state.Canonical()
	}
}

func (s *Store) publishClusterStageTx(ctx context.Context, tx *transaction, rolloutID int64, stageOrder int, now time.Time) ([]SnapshotRecord, error) {
	var phase, status string
	var bakeSeconds int
	if err := tx.QueryRow(ctx, `SELECT phase,status,bake_seconds FROM cluster_rollout_stages WHERE rollout_id=$1 AND stage_order=$2 FOR UPDATE`, rolloutID, stageOrder).Scan(&phase, &status, &bakeSeconds); err != nil {
		return nil, fmt.Errorf("lock cluster rollout stage %d: %w", stageOrder, err)
	}
	if status == "completed" || status == "awaiting_ack" || status == "baking" {
		return nil, nil
	}
	if status != "pending" {
		return nil, fmt.Errorf("cluster rollout stage %d cannot publish from status %s", stageOrder, status)
	}
	if phase == string(cluster.RolloutPhaseBake) {
		bakeUntil := now.UTC().Add(time.Duration(bakeSeconds) * time.Second)
		if _, err := tx.Exec(ctx, `UPDATE cluster_rollout_stages SET status='baking',started_at=$3 WHERE rollout_id=$1 AND stage_order=$2`, rolloutID, stageOrder, now.UTC()); err != nil {
			return nil, fmt.Errorf("start cluster rollout bake stage: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE cluster_rollouts SET status='baking',current_stage=$2,bake_until=$3 WHERE id=$1`, rolloutID, stageOrder, bakeUntil); err != nil {
			return nil, fmt.Errorf("mark cluster rollout baking: %w", err)
		}
		return nil, nil
	}

	rows, err := tx.Query(ctx, `SELECT node_id,desired_state FROM cluster_rollout_nodes WHERE rollout_id=$1 AND stage_order=$2 AND status='queued' ORDER BY node_id`, rolloutID, stageOrder)
	if err != nil {
		return nil, fmt.Errorf("read cluster rollout stage targets: %w", err)
	}
	type target struct {
		nodeID  string
		desired []byte
	}
	var targets []target
	for rows.Next() {
		var value target
		if err := rows.Scan(&value.nodeID, &value.desired); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan cluster rollout stage target: %w", err)
		}
		targets = append(targets, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate cluster rollout stage targets: %w", err)
	}
	rows.Close()

	records := make([]SnapshotRecord, 0, len(targets))
	for _, target := range targets {
		var current int64
		if err := tx.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1 FOR UPDATE`, target.nodeID).Scan(&current); err != nil {
			return nil, fmt.Errorf("lock node %s for rollout stage: %w", target.nodeID, err)
		}
		desired, err := spec.DecodeDesiredJSON(target.desired)
		if err != nil {
			return nil, fmt.Errorf("decode rollout stage target for %s: %w", target.nodeID, err)
		}
		record, err := s.publishDesiredTx(ctx, tx, target.nodeID, current, desired, nil)
		if err != nil {
			return nil, fmt.Errorf("publish rollout %d stage %d target for %s: %w", rolloutID, stageOrder, target.nodeID, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE cluster_rollout_nodes SET previous_generation=$4,generation=$5,desired_checksum=$6,status='pending',error_message='',applied_at=NULL,desired_state=$7 WHERE rollout_id=$1 AND stage_order=$2 AND node_id=$3`, rolloutID, stageOrder, target.nodeID, current, int64(record.Generation), record.DesiredChecksum, record.DesiredStateJSON); err != nil {
			return nil, fmt.Errorf("record rollout %d stage %d publication for %s: %w", rolloutID, stageOrder, target.nodeID, err)
		}
		records = append(records, record)
	}
	if len(targets) == 0 {
		if _, err := tx.Exec(ctx, `UPDATE cluster_rollout_stages SET status='completed',started_at=$3,completed_at=$3 WHERE rollout_id=$1 AND stage_order=$2`, rolloutID, stageOrder, now.UTC()); err != nil {
			return nil, fmt.Errorf("complete empty cluster rollout stage: %w", err)
		}
		return records, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE cluster_rollout_stages SET status='awaiting_ack',started_at=$3 WHERE rollout_id=$1 AND stage_order=$2`, rolloutID, stageOrder, now.UTC()); err != nil {
		return nil, fmt.Errorf("mark cluster rollout stage awaiting ACK: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE cluster_rollouts SET status='awaiting_ack',current_stage=$2,bake_until=NULL WHERE id=$1`, rolloutID, stageOrder); err != nil {
		return nil, fmt.Errorf("mark cluster rollout awaiting ACK: %w", err)
	}
	return records, nil
}

func loadRetiredClusterNodes(ctx context.Context, tx *transaction, plan cluster.Plan) (map[string]int64, error) {
	active := make([]string, 0, len(plan.Nodes))
	for _, node := range plan.Nodes {
		active = append(active, node.ID)
	}
	var rows rows
	var err error
	if len(active) == 0 {
		rows, err = tx.Query(ctx, `SELECT n.id,n.desired_generation FROM node_scheduling_profiles p JOIN nodes n ON n.id=p.node_id WHERE p.plan_id=$1 ORDER BY n.id FOR UPDATE OF n`, plan.ID)
	} else {
		encodedActive, encodeErr := json.Marshal(active)
		if encodeErr != nil {
			return nil, fmt.Errorf("encode active cluster nodes: %w", encodeErr)
		}
		rows, err = tx.Query(ctx, `SELECT n.id,n.desired_generation FROM node_scheduling_profiles p JOIN nodes n ON n.id=p.node_id WHERE p.plan_id=$1 AND n.id NOT IN (SELECT value FROM json_each($2)) ORDER BY n.id FOR UPDATE OF n`, plan.ID, string(encodedActive))
	}
	if err != nil {
		return nil, fmt.Errorf("lock retired cluster nodes: %w", err)
	}
	retired := make(map[string]int64)
	var retiredIDs []string
	for rows.Next() {
		var nodeID string
		var generation int64
		if err := rows.Scan(&nodeID, &generation); err != nil {
			return nil, fmt.Errorf("scan retired cluster node: %w", err)
		}
		retired[nodeID] = generation
		retiredIDs = append(retiredIDs, nodeID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate retired cluster nodes: %w", err)
	}
	rows.Close()
	for _, nodeID := range retiredIDs {
		generation := retired[nodeID]
		if generation == 0 {
			continue
		}
		var encoded []byte
		if err := tx.QueryRow(ctx, `SELECT desired_state FROM node_generations WHERE node_id=$1 AND generation=$2`, nodeID, generation).Scan(&encoded); err != nil {
			return nil, fmt.Errorf("read retired node desired state: %w", err)
		}
		desired, err := spec.DecodeDesiredJSON(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode retired node desired state: %w", err)
		}
		if desired.ManagementDomain != "cluster:"+plan.ID {
			return nil, fmt.Errorf("%w: retired node %s is owned by %q", ErrManagementConflict, nodeID, desired.ManagementDomain)
		}
	}
	return retired, nil
}

func removeRetiredNodeProfiles(ctx context.Context, tx *transaction, plan cluster.Plan) error {
	active := make([]string, 0, len(plan.Nodes))
	for _, node := range plan.Nodes {
		active = append(active, node.ID)
	}
	if len(active) == 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM node_scheduling_profiles WHERE plan_id=$1`, plan.ID); err != nil {
			return fmt.Errorf("remove retired scheduling profiles: %w", err)
		}
		return nil
	}
	encodedActive, err := json.Marshal(active)
	if err != nil {
		return fmt.Errorf("encode retained scheduling profiles: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM node_scheduling_profiles WHERE plan_id=$1 AND node_id NOT IN (SELECT value FROM json_each($2))`, plan.ID, string(encodedActive)); err != nil {
		return fmt.Errorf("remove retired scheduling profiles: %w", err)
	}
	return nil
}

const clusterRolloutACKTimeout = 10 * time.Minute

func (s *Store) AdvanceClusterRollouts(ctx context.Context, owner string, limit int, now time.Time) (int, error) {
	if owner == "" || limit < 1 || limit > 100 {
		return 0, errors.New("invalid cluster rollout advancer arguments")
	}
	actor := "system:" + owner
	if len(actor) > 256 {
		actor = actor[:256]
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin cluster rollout advancement: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
SELECT p.id
FROM cluster_plans p
WHERE EXISTS (
  SELECT 1 FROM cluster_rollouts r
  WHERE r.plan_id=p.id AND r.status IN ('publishing','awaiting_ack','baking','rollback_pending','rolling_back')
)
ORDER BY p.id
LIMIT $1`, limit)
	if err != nil {
		return 0, fmt.Errorf("claim active cluster rollout plans: %w", err)
	}
	var planIDs []string
	for rows.Next() {
		var planID string
		if err := rows.Scan(&planID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan active cluster rollout plan: %w", err)
		}
		planIDs = append(planIDs, planID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate active cluster rollout plans: %w", err)
	}
	rows.Close()

	advanced := 0
	for _, planID := range planIDs {
		var rolloutID int64
		if err := tx.QueryRow(ctx, `SELECT id FROM cluster_rollouts WHERE plan_id=$1 AND status IN ('publishing','awaiting_ack','baking','rollback_pending','rolling_back') ORDER BY id LIMIT 1 FOR UPDATE`, planID).Scan(&rolloutID); errors.Is(err, sql.ErrNoRows) {
			continue
		} else if err != nil {
			return advanced, fmt.Errorf("lock active cluster rollout: %w", err)
		}
		changed, err := s.advanceClusterRolloutTx(ctx, tx, rolloutID, now.UTC(), actor)
		if err != nil {
			return advanced, err
		}
		if changed {
			advanced++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return advanced, fmt.Errorf("commit cluster rollout advancement: %w", err)
	}
	return advanced, nil
}

func (s *Store) advanceClusterRolloutTx(ctx context.Context, tx *transaction, rolloutID int64, now time.Time, actor string) (bool, error) {
	var planID, status string
	var revision int64
	var currentStage int
	var autoRollback bool
	var bakeUntil *time.Time
	var detailJSON []byte
	if err := tx.QueryRow(ctx, `SELECT plan_id,revision,status,current_stage,auto_rollback,bake_until,detail FROM cluster_rollouts WHERE id=$1 FOR UPDATE`, rolloutID).Scan(&planID, &revision, &status, &currentStage, &autoRollback, &bakeUntil, &detailJSON); err != nil {
		return false, fmt.Errorf("read active cluster rollout: %w", err)
	}
	if status == "rollback_pending" {
		stageOrder, err := ensureCompensationStage(ctx, tx, rolloutID)
		if err != nil {
			return false, err
		}
		if _, err := s.publishClusterStageTx(ctx, tx, rolloutID, stageOrder, now); err != nil {
			return false, err
		}
		return true, nil
	}

	var phase, stageStatus string
	var startedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT phase,status,started_at FROM cluster_rollout_stages WHERE rollout_id=$1 AND stage_order=$2 FOR UPDATE`, rolloutID, currentStage).Scan(&phase, &stageStatus, &startedAt); err != nil {
		return false, fmt.Errorf("read current cluster rollout stage: %w", err)
	}
	if status == "publishing" || status == "rolling_back" {
		if stageStatus == "completed" {
			return true, s.completeClusterStageTx(ctx, tx, rolloutID, planID, uint64(revision), currentStage, phase, detailJSON, now, actor)
		}
		if _, err := s.publishClusterStageTx(ctx, tx, rolloutID, currentStage, now); err != nil {
			return false, err
		}
		return true, nil
	}
	if status == "awaiting_ack" {
		var pending int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM cluster_rollout_nodes WHERE rollout_id=$1 AND stage_order=$2 AND status<>'applied'`, rolloutID, currentStage).Scan(&pending); err != nil {
			return false, fmt.Errorf("count pending cluster rollout stage ACKs: %w", err)
		}
		if pending == 0 {
			return true, s.completeClusterStageTx(ctx, tx, rolloutID, planID, uint64(revision), currentStage, phase, detailJSON, now, actor)
		}
		if startedAt != nil && now.Sub(startedAt.UTC()) >= clusterRolloutACKTimeout {
			message := fmt.Sprintf("rollout %d stage %d did not receive all Agent ACKs within %s", rolloutID, currentStage, clusterRolloutACKTimeout)
			if err := requestClusterRollbackTx(ctx, tx, rolloutID, planID, uint64(revision), currentStage, phase, autoRollback, message, actor, now); err != nil {
				return false, err
			}
			return true, nil
		}
		return false, nil
	}
	if status == "baking" {
		failedForward, err := canaryBakeFailure(ctx, tx, planID, uint64(revision), detailJSON, now)
		if err != nil {
			return false, err
		}
		if failedForward != "" {
			message := fmt.Sprintf("canary forward %s has no fresh healthy backend during bake", failedForward)
			if err := requestClusterRollbackTx(ctx, tx, rolloutID, planID, uint64(revision), currentStage, phase, autoRollback, message, actor, now); err != nil {
				return false, err
			}
			return true, nil
		}
		if bakeUntil != nil && now.Before(bakeUntil.UTC()) {
			return false, nil
		}
		return true, s.completeClusterStageTx(ctx, tx, rolloutID, planID, uint64(revision), currentStage, phase, detailJSON, now, actor)
	}
	return false, fmt.Errorf("cluster rollout %d has unsupported active status %s", rolloutID, status)
}

func (s *Store) completeClusterStageTx(ctx context.Context, tx *transaction, rolloutID int64, planID string, revision uint64, stageOrder int, phase string, detailJSON []byte, now time.Time, actor string) error {
	if _, err := tx.Exec(ctx, `UPDATE cluster_rollout_stages SET status='completed',completed_at=$3 WHERE rollout_id=$1 AND stage_order=$2`, rolloutID, stageOrder, now.UTC()); err != nil {
		return fmt.Errorf("complete cluster rollout stage: %w", err)
	}
	if phase == string(cluster.RolloutPhaseCompensate) {
		if _, err := tx.Exec(ctx, `UPDATE cluster_rollouts SET status='rolled_back',completed_at=$2,bake_until=NULL WHERE id=$1`, rolloutID, now.UTC()); err != nil {
			return fmt.Errorf("complete cluster rollout compensation: %w", err)
		}
		if err := insertClusterAudit(ctx, tx, planID, revision, actor, "cluster_rollout_compensated", fmt.Sprintf("%d", rolloutID), map[string]any{"stage": stageOrder}); err != nil {
			return err
		}
		return nil
	}
	var nextStage int
	err := tx.QueryRow(ctx, `SELECT stage_order FROM cluster_rollout_stages WHERE rollout_id=$1 AND stage_order>$2 AND status='pending' ORDER BY stage_order LIMIT 1`, rolloutID, stageOrder).Scan(&nextStage)
	if err == nil {
		if _, err := tx.Exec(ctx, `UPDATE cluster_rollouts SET status='publishing',current_stage=$2,bake_until=NULL WHERE id=$1`, rolloutID, nextStage); err != nil {
			return fmt.Errorf("advance cluster rollout stage pointer: %w", err)
		}
		_, err = s.publishClusterStageTx(ctx, tx, rolloutID, nextStage, now)
		return err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read next cluster rollout stage: %w", err)
	}

	var detail clusterRolloutDetail
	if len(detailJSON) != 0 {
		if err := json.Unmarshal(detailJSON, &detail); err != nil {
			return fmt.Errorf("decode cluster rollout completion detail: %w", err)
		}
	}
	if detail.CommitPlacements {
		var encodedPlan []byte
		if err := tx.QueryRow(ctx, `SELECT plan FROM cluster_plan_revisions WHERE plan_id=$1 AND revision=$2`, planID, int64(revision)).Scan(&encodedPlan); err != nil {
			return fmt.Errorf("read completed cluster rollout plan: %w", err)
		}
		plan, err := cluster.DecodePlanJSON(encodedPlan)
		if err != nil {
			return fmt.Errorf("decode completed cluster rollout plan: %w", err)
		}
		if err := replacePlacements(ctx, tx, plan, detail.Placements, detail.ServiceVIPs); err != nil {
			return err
		}
		if err := removeRetiredNodeProfiles(ctx, tx, plan); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE cluster_rollouts SET status='completed',completed_at=$2,bake_until=NULL WHERE id=$1`, rolloutID, now.UTC()); err != nil {
		return fmt.Errorf("complete cluster rollout: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE cluster_plans SET last_error=NULL,reconcile_after=$2,updated_at=now() WHERE id=$1`, planID, now.UTC()); err != nil {
		return fmt.Errorf("wake completed cluster plan: %w", err)
	}
	return insertClusterAudit(ctx, tx, planID, revision, actor, "cluster_rollout_applied", fmt.Sprintf("%d", rolloutID), map[string]any{"stages": stageOrder})
}

func ensureCompensationStage(ctx context.Context, tx *transaction, rolloutID int64) (int, error) {
	var existing int
	err := tx.QueryRow(ctx, `SELECT stage_order FROM cluster_rollout_stages WHERE rollout_id=$1 AND phase='compensate' ORDER BY stage_order DESC LIMIT 1 FOR UPDATE`, rolloutID).Scan(&existing)
	if err == nil {
		if _, err := tx.Exec(ctx, `UPDATE cluster_rollouts SET status='rolling_back',current_stage=$2,bake_until=NULL WHERE id=$1`, rolloutID, existing); err != nil {
			return 0, fmt.Errorf("resume cluster compensation stage: %w", err)
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("read cluster compensation stage: %w", err)
	}
	var stageOrder int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(stage_order),0)+1 FROM cluster_rollout_stages WHERE rollout_id=$1`, rolloutID).Scan(&stageOrder); err != nil {
		return 0, fmt.Errorf("allocate cluster compensation stage: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO cluster_rollout_stages(rollout_id,stage_order,wave,phase) VALUES ($1,$2,'compensation','compensate')`, rolloutID, stageOrder); err != nil {
		return 0, fmt.Errorf("create cluster compensation stage: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO cluster_rollout_nodes(rollout_id,stage_order,node_id,previous_generation,generation,desired_checksum,status,desired_state)
SELECT $1,$2,b.node_id,0,NULL,NULL,'queued',b.desired_state
FROM cluster_rollout_baselines b
WHERE b.rollout_id=$1
  AND EXISTS (SELECT 1 FROM cluster_rollout_nodes n WHERE n.rollout_id=$1 AND n.node_id=b.node_id AND n.generation IS NOT NULL)
ORDER BY b.node_id`, rolloutID, stageOrder); err != nil {
		return 0, fmt.Errorf("create cluster compensation targets: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE cluster_rollouts SET status='rolling_back',current_stage=$2,bake_until=NULL WHERE id=$1`, rolloutID, stageOrder); err != nil {
		return 0, fmt.Errorf("start cluster compensation: %w", err)
	}
	return stageOrder, nil
}

func requestClusterRollbackTx(ctx context.Context, tx *transaction, rolloutID int64, planID string, revision uint64, stageOrder int, phase string, autoRollback bool, message, actor string, now time.Time) error {
	message = truncateClusterError(errors.New(message))
	if _, err := tx.Exec(ctx, `UPDATE cluster_rollout_stages SET status='failed',completed_at=$3 WHERE rollout_id=$1 AND stage_order=$2`, rolloutID, stageOrder, now.UTC()); err != nil {
		return fmt.Errorf("fail cluster rollout stage: %w", err)
	}
	terminal := phase == string(cluster.RolloutPhaseCompensate) || !autoRollback
	status := "rollback_pending"
	var completed any
	if terminal {
		status = "failed"
		completed = now.UTC()
	}
	if _, err := tx.Exec(ctx, `UPDATE cluster_rollouts SET status=$2,failure_message=$3,completed_at=$4,bake_until=NULL WHERE id=$1`, rolloutID, status, message, completed); err != nil {
		return fmt.Errorf("record cluster rollout failure: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE cluster_plans SET paused_at=COALESCE(paused_at,$2),last_error=$3,updated_at=now() WHERE id=$1`, planID, now.UTC(), message); err != nil {
		return fmt.Errorf("pause failed cluster plan: %w", err)
	}
	action := "cluster_rollout_compensation_requested"
	if terminal {
		action = "cluster_rollout_failed"
	}
	return insertClusterAudit(ctx, tx, planID, revision, actor, action, fmt.Sprintf("%d", rolloutID), map[string]any{"stage": stageOrder, "phase": phase, "error": message})
}

func canaryBakeFailure(ctx context.Context, tx *transaction, planID string, revision uint64, detailJSON []byte, now time.Time) (string, error) {
	var detail clusterRolloutDetail
	if err := json.Unmarshal(detailJSON, &detail); err != nil {
		return "", fmt.Errorf("decode canary rollout detail: %w", err)
	}
	if len(detail.CanaryForwardIDs) == 0 {
		return "", nil
	}
	var encodedPlan []byte
	if err := tx.QueryRow(ctx, `SELECT plan FROM cluster_plan_revisions WHERE plan_id=$1 AND revision=$2`, planID, int64(revision)).Scan(&encodedPlan); err != nil {
		return "", fmt.Errorf("read canary cluster plan: %w", err)
	}
	plan, err := cluster.DecodePlanJSON(encodedPlan)
	if err != nil {
		return "", fmt.Errorf("decode canary cluster plan: %w", err)
	}
	observations, err := loadHealthObservations(ctx, tx, planID)
	if err != nil {
		return "", err
	}
	forwards := make(map[string]cluster.Forward, len(plan.Forwards))
	for _, forward := range plan.Forwards {
		forwards[forward.ID] = forward
	}
	pools := make(map[string]cluster.BackendPool, len(plan.BackendPools))
	for _, pool := range plan.BackendPools {
		pools[pool.ID] = pool
	}
	placements := make(map[string]cluster.Placement, len(detail.Placements))
	for _, placement := range detail.Placements {
		placements[placement.ForwardID] = placement
	}
	for _, forwardID := range detail.CanaryForwardIDs {
		forward, exists := forwards[forwardID]
		if !exists {
			continue
		}
		pool := pools[forward.BackendPoolID]
		if pool.Health == nil || len(pool.Backends) == 0 {
			continue
		}
		placement := placements[forwardID]
		probeNode := placement.IngressID
		if placement.PathMode == spec.PathViaExit {
			probeNode = placement.ExitID
		}
		if backendPoolExplicitlyUnhealthy(pool, probeNode, observations, now) {
			return forwardID, nil
		}
	}
	return "", nil
}

func backendPoolExplicitlyUnhealthy(pool cluster.BackendPool, probeNode string, observations map[cluster.HealthKey]cluster.HealthObservation, now time.Time) bool {
	if pool.Health == nil || len(pool.Backends) == 0 {
		return false
	}
	freshUnhealthy := 0
	for _, backend := range pool.Backends {
		observation, exists := observations[cluster.HealthKey{NodeID: probeNode, PoolID: pool.ID, BackendID: backend.ID}]
		if !exists || observation.ResourceVersion != backend.ResourceVersion || observation.ObservedAt.After(now.Add(5*time.Minute)) || now.Sub(observation.ObservedAt) > time.Duration(pool.Health.StaleAfterSeconds)*time.Second {
			continue
		}
		if observation.Status == health.StatusUnhealthy {
			freshUnhealthy++
		}
	}
	return freshUnhealthy == len(pool.Backends)
}

func recordClusterRolloutACKTx(ctx context.Context, tx *transaction, record ApplyRecord) error {
	rows, err := tx.Query(ctx, `
UPDATE cluster_rollout_nodes
SET status=CASE WHEN status='applied' AND $3<>'applied' THEN status ELSE $3 END,
    error_message=CASE WHEN status='applied' AND $3<>'applied' THEN error_message ELSE $4 END,
    applied_at=CASE WHEN $3='applied' THEN $5 ELSE applied_at END
WHERE node_id=$1 AND generation=$2 AND (status<>'applied' OR $3='applied')
RETURNING rollout_id,stage_order`, record.NodeID, int64(record.Generation), record.Status, truncateClusterError(errors.New(record.ErrorMessage)), record.ObservedAt)
	if err != nil {
		return fmt.Errorf("update cluster rollout ACK: %w", err)
	}
	type rolloutStage struct {
		rolloutID int64
		stage     int
	}
	var matches []rolloutStage
	for rows.Next() {
		var match rolloutStage
		if err := rows.Scan(&match.rolloutID, &match.stage); err != nil {
			rows.Close()
			return fmt.Errorf("scan cluster rollout ACK: %w", err)
		}
		matches = append(matches, match)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate cluster rollout ACK: %w", err)
	}
	rows.Close()
	for _, match := range matches {
		var planID, rolloutStatus string
		var revision int64
		var autoRollback bool
		if err := tx.QueryRow(ctx, `SELECT plan_id,revision,status,auto_rollback FROM cluster_rollouts WHERE id=$1 FOR UPDATE`, match.rolloutID).Scan(&planID, &revision, &rolloutStatus, &autoRollback); err != nil {
			return fmt.Errorf("lock cluster rollout ACK: %w", err)
		}
		if rolloutStatus == "completed" || rolloutStatus == "rolled_back" || rolloutStatus == "failed" {
			continue
		}
		if record.Status == "permanent_error" {
			message := truncateClusterError(fmt.Errorf("node %s generation %d: %s", record.NodeID, record.Generation, record.ErrorMessage))
			var phase string
			if err := tx.QueryRow(ctx, `SELECT phase FROM cluster_rollout_stages WHERE rollout_id=$1 AND stage_order=$2`, match.rolloutID, match.stage).Scan(&phase); err != nil {
				return fmt.Errorf("read failed cluster rollout stage: %w", err)
			}
			if err := requestClusterRollbackTx(ctx, tx, match.rolloutID, planID, uint64(revision), match.stage, phase, autoRollback, message, "system:controller", record.ObservedAt); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadNodeRuntimes(ctx context.Context, tx *transaction, plan cluster.Plan, now time.Time) (map[string]cluster.NodeRuntime, map[string]int64, error) {
	ids := make([]string, 0, len(plan.Nodes))
	for _, node := range plan.Nodes {
		ids = append(ids, node.ID)
	}
	sort.Strings(ids)
	encodedIDs, err := json.Marshal(ids)
	if err != nil {
		return nil, nil, fmt.Errorf("encode scheduled node IDs: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT id,desired_generation,last_seen_at,capabilities,wireguard_public_key,revoked_at FROM nodes WHERE id IN (SELECT value FROM json_each($1)) ORDER BY id FOR UPDATE`, string(encodedIDs))
	if err != nil {
		return nil, nil, fmt.Errorf("lock scheduled nodes: %w", err)
	}
	runtimes := make(map[string]cluster.NodeRuntime, len(ids))
	currents := make(map[string]int64, len(ids))
	for rows.Next() {
		var nodeID string
		var generation int64
		var lastSeen, revoked *time.Time
		var encodedCapabilities []byte
		var publicKey *string
		if err := rows.Scan(&nodeID, &generation, &lastSeen, &encodedCapabilities, &publicKey, &revoked); err != nil {
			return nil, nil, fmt.Errorf("scan scheduled node: %w", err)
		}
		var capabilities []*controlv1.Capability
		if err := json.Unmarshal(encodedCapabilities, &capabilities); err != nil {
			return nil, nil, fmt.Errorf("decode node %s capabilities: %w", nodeID, err)
		}
		capabilityMap := make(map[string]uint32, len(capabilities))
		for _, capability := range capabilities {
			if capability != nil && capability.Version > capabilityMap[capability.Name] {
				capabilityMap[capability.Name] = capability.Version
			}
		}
		runtime := cluster.NodeRuntime{ID: nodeID, Capabilities: capabilityMap}
		if lastSeen != nil {
			runtime.LastSeen = lastSeen.UTC()
			runtime.Available = revoked == nil && now.Sub(runtime.LastSeen) <= time.Duration(plan.NodeOfflineAfterSeconds)*time.Second && now.Sub(runtime.LastSeen) >= -5*time.Minute
		}
		if publicKey != nil {
			runtime.WireGuardPublicKey = *publicKey
		}
		runtimes[nodeID] = runtime
		currents[nodeID] = generation
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, fmt.Errorf("iterate scheduled nodes: %w", err)
	}
	rows.Close()
	if len(runtimes) != len(ids) {
		return nil, nil, errors.New("cluster plan references a node that has not been enrolled")
	}
	for _, nodeID := range ids {
		generation := currents[nodeID]
		if generation == 0 {
			continue
		}
		var currentJSON []byte
		if err := tx.QueryRow(ctx, `SELECT desired_state FROM node_generations WHERE node_id=$1 AND generation=$2`, nodeID, generation).Scan(&currentJSON); err != nil {
			return nil, nil, fmt.Errorf("read current desired state for node %s: %w", nodeID, err)
		}
		current, err := spec.DecodeDesiredJSON(currentJSON)
		if err != nil {
			return nil, nil, fmt.Errorf("decode current desired state for node %s: %w", nodeID, err)
		}
		expectedDomain := "cluster:" + plan.ID
		if current.ManagementDomain != expectedDomain && (current.ManagementDomain != "" || desiredHasManagedResources(current)) {
			return nil, nil, fmt.Errorf("%w: node %s is owned by %q", ErrManagementConflict, nodeID, current.ManagementDomain)
		}
	}
	return runtimes, currents, nil
}

func desiredHasManagedResources(desired spec.DesiredState) bool {
	return len(desired.Forwards) != 0 || len(desired.FabricLinks) != 0 || len(desired.HealthChecks) != 0 || len(desired.UserPolicies) != 0 || len(desired.ServiceCIDRs) != 0
}

func loadHealthObservations(ctx context.Context, tx *transaction, planID string) (map[cluster.HealthKey]cluster.HealthObservation, error) {
	rows, err := tx.Query(ctx, `SELECT node_id,pool_id,backend_id,status,resource_version,observed_at FROM backend_health_observations WHERE plan_id=$1`, planID)
	if err != nil {
		return nil, fmt.Errorf("read backend health observations: %w", err)
	}
	defer rows.Close()
	result := make(map[cluster.HealthKey]cluster.HealthObservation)
	for rows.Next() {
		var key cluster.HealthKey
		var observation cluster.HealthObservation
		var status string
		var resourceVersion int64
		if err := rows.Scan(&key.NodeID, &key.PoolID, &key.BackendID, &status, &resourceVersion, &observation.ObservedAt); err != nil {
			return nil, fmt.Errorf("scan backend health observation: %w", err)
		}
		observation.Status = health.Status(status)
		observation.ResourceVersion = uint64(resourceVersion)
		result[key] = observation
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate backend health observations: %w", err)
	}
	return result, nil
}

func allocateServiceVIPs(ctx context.Context, tx *transaction, plan cluster.Plan, placements []cluster.Placement) (map[string]netip.Addr, error) {
	rows, err := tx.Query(ctx, `SELECT service_vip,forward_id FROM service_vip_allocations ORDER BY service_vip FOR UPDATE`)
	if err != nil {
		return nil, fmt.Errorf("lock service VIP allocations: %w", err)
	}
	used := make(map[netip.Addr]string)
	byForward := make(map[string]netip.Addr)
	for rows.Next() {
		var encoded, forwardID string
		if err := rows.Scan(&encoded, &forwardID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan service VIP allocation: %w", err)
		}
		address, err := netip.ParseAddr(encoded)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("parse service VIP allocation: %w", err)
		}
		address = address.Unmap()
		used[address] = forwardID
		byForward[forwardID] = address
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate service VIP allocations: %w", err)
	}
	rows.Close()
	result := make(map[string]netip.Addr)
	cursors := make(map[string]uint64)
	ordered := append([]cluster.Placement(nil), placements...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ForwardID < ordered[j].ForwardID })
	for _, placement := range ordered {
		if placement.PathMode != spec.PathViaExit {
			continue
		}
		if existing, exists := byForward[placement.ForwardID]; exists {
			if !prefixContainsAny(plan.ServiceCIDRs, existing) {
				return nil, fmt.Errorf("%w: forward %s VIP %s; retain its old CIDR during migration", ErrServiceVIPMigration, placement.ForwardID, existing)
			}
			result[placement.ForwardID] = existing
			continue
		}
		allocated, ok := nextAvailableVIP(plan.ServiceCIDRs, used, cursors)
		if !ok {
			return nil, ErrServiceVIPCapacity
		}
		used[allocated] = placement.ForwardID
		byForward[placement.ForwardID] = allocated
		result[placement.ForwardID] = allocated
	}
	return result, nil
}

func nextAvailableVIP(prefixes []netip.Prefix, used map[netip.Addr]string, cursors map[string]uint64) (netip.Addr, bool) {
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		rawBase := prefix.Addr().As4()
		base := uint64(binary.BigEndian.Uint32(rawBase[:]))
		size := uint64(1) << uint(32-prefix.Bits())
		first := uint64(0)
		last := size
		if size > 2 {
			first = 1
			last = size - 1
		}
		key := prefix.String()
		cursor := cursors[key]
		if cursor < first {
			cursor = first
		}
		for cursor < last {
			value := uint32(base + cursor)
			var raw [4]byte
			binary.BigEndian.PutUint32(raw[:], value)
			candidate := netip.AddrFrom4(raw)
			cursor++
			cursors[key] = cursor
			if _, exists := used[candidate]; !exists {
				return candidate, true
			}
		}
	}
	return netip.Addr{}, false
}

func replacePlacements(ctx context.Context, tx *transaction, plan cluster.Plan, placements []cluster.Placement, vips map[string]netip.Addr) error {
	ids := make([]string, 0, len(placements))
	for _, placement := range placements {
		ids = append(ids, placement.ForwardID)
		var exitID, vip, fabricIn, fabricOut any
		if placement.ExitID != "" {
			exitID = placement.ExitID
			vip = vips[placement.ForwardID].String()
			fabricIn = placement.FabricInID
			fabricOut = placement.FabricOutID
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO cluster_forward_placements(plan_id,forward_id,revision,ingress_node_id,exit_node_id,backend_id,target,target_port,service_vip,fabric_in_id,fabric_out_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (plan_id,forward_id) DO UPDATE SET revision=EXCLUDED.revision,ingress_node_id=EXCLUDED.ingress_node_id,
 exit_node_id=EXCLUDED.exit_node_id,backend_id=EXCLUDED.backend_id,target=EXCLUDED.target,target_port=EXCLUDED.target_port,
 service_vip=EXCLUDED.service_vip,fabric_in_id=EXCLUDED.fabric_in_id,fabric_out_id=EXCLUDED.fabric_out_id,updated_at=now()`,
			plan.ID, placement.ForwardID, int64(plan.Revision), placement.IngressID, exitID, placement.BackendID,
			placement.Target.Address.String(), int(placement.Target.Port), vip, fabricIn, fabricOut); err != nil {
			return fmt.Errorf("store cluster placement %s: %w", placement.ForwardID, err)
		}
	}
	if len(ids) == 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM cluster_forward_placements WHERE plan_id=$1`, plan.ID); err != nil {
			return fmt.Errorf("remove stale cluster placements: %w", err)
		}
	} else if encodedIDs, encodeErr := json.Marshal(ids); encodeErr != nil {
		return fmt.Errorf("encode retained cluster placements: %w", encodeErr)
	} else if _, err := tx.Exec(ctx, `DELETE FROM cluster_forward_placements WHERE plan_id=$1 AND forward_id NOT IN (SELECT value FROM json_each($2))`, plan.ID, string(encodedIDs)); err != nil {
		return fmt.Errorf("remove stale cluster placements: %w", err)
	}
	return nil
}

func placementsEqual(first, second []cluster.Placement) bool {
	if len(first) != len(second) {
		return false
	}
	left := append([]cluster.Placement(nil), first...)
	right := append([]cluster.Placement(nil), second...)
	sort.Slice(left, func(i, j int) bool { return left[i].ForwardID < left[j].ForwardID })
	sort.Slice(right, func(i, j int) bool { return right[i].ForwardID < right[j].ForwardID })
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func syncNodeProfiles(ctx context.Context, tx *transaction, plan cluster.Plan) error {
	for _, node := range plan.Nodes {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id=$1)`, node.ID).Scan(&exists); err != nil {
			return fmt.Errorf("check scheduling node %s: %w", node.ID, err)
		}
		if !exists {
			return fmt.Errorf("cluster node %s has not been registered", node.ID)
		}
		var profileOwner string
		if err := tx.QueryRow(ctx, `SELECT plan_id FROM node_scheduling_profiles WHERE node_id=$1 FOR UPDATE`, node.ID).Scan(&profileOwner); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read scheduling ownership for %s: %w", node.ID, err)
		} else if err == nil && profileOwner != plan.ID {
			return fmt.Errorf("%w: node %s scheduling profile belongs to cluster plan %s", ErrManagementConflict, node.ID, profileOwner)
		}
		roles, _ := json.Marshal(node.Roles)
		labels, _ := json.Marshal(node.Labels)
		capacity, _ := json.Marshal(node.Capacity)
		if _, err := tx.Exec(ctx, `
INSERT INTO node_scheduling_profiles(node_id,plan_id,revision,enabled,roles,labels,failure_domain,capacity)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (node_id) DO UPDATE SET plan_id=EXCLUDED.plan_id,revision=EXCLUDED.revision,enabled=EXCLUDED.enabled,
 roles=EXCLUDED.roles,labels=EXCLUDED.labels,failure_domain=EXCLUDED.failure_domain,capacity=EXCLUDED.capacity,updated_at=now()`,
			node.ID, plan.ID, int64(plan.Revision), node.Enabled, roles, labels, node.FailureDomain, capacity); err != nil {
			return fmt.Errorf("store scheduling profile for %s: %w", node.ID, err)
		}
	}
	return nil
}

func syncClusterAlerts(ctx context.Context, tx *transaction, plan cluster.Plan, actor string, alerts []cluster.Alert) error {
	active := make(map[string]cluster.Alert, len(alerts))
	for _, alert := range alerts {
		key := alert.ForwardID + "\x00" + alert.Code
		active[key] = alert
		detail, _ := json.Marshal(map[string]any{"pool_id": alert.PoolID, "detail": alert.Detail})
		if _, err := tx.Exec(ctx, `
INSERT INTO cluster_alerts(plan_id,forward_id,code,status,detail)
VALUES ($1,$2,$3,'active',$4)
ON CONFLICT (plan_id,forward_id,code) DO UPDATE SET status='active',detail=EXCLUDED.detail,updated_at=now(),resolved_at=NULL`, plan.ID, alert.ForwardID, alert.Code, detail); err != nil {
			return fmt.Errorf("upsert cluster alert: %w", err)
		}
	}
	rows, err := tx.Query(ctx, `SELECT forward_id,code FROM cluster_alerts WHERE plan_id=$1 AND status='active' FOR UPDATE`, plan.ID)
	if err != nil {
		return fmt.Errorf("read active cluster alerts: %w", err)
	}
	var resolve [][2]string
	for rows.Next() {
		var forwardID, code string
		if err := rows.Scan(&forwardID, &code); err != nil {
			rows.Close()
			return fmt.Errorf("scan active cluster alert: %w", err)
		}
		if _, remains := active[forwardID+"\x00"+code]; !remains {
			resolve = append(resolve, [2]string{forwardID, code})
		}
	}
	rows.Close()
	for _, item := range resolve {
		if _, err := tx.Exec(ctx, `UPDATE cluster_alerts SET status='resolved',resolved_at=now(),updated_at=now() WHERE plan_id=$1 AND forward_id=$2 AND code=$3`, plan.ID, item[0], item[1]); err != nil {
			return fmt.Errorf("resolve cluster alert: %w", err)
		}
		if err := insertClusterAudit(ctx, tx, plan.ID, plan.Revision, actor, "cluster_alert_resolved", item[0], map[string]any{"code": item[1]}); err != nil {
			return err
		}
	}
	return nil
}

func insertClusterAudit(ctx context.Context, tx *transaction, planID string, revision uint64, actor, action, subject string, detail any) error {
	encoded, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("encode cluster audit detail: %w", err)
	}
	var revisionValue any
	if revision != 0 {
		revisionValue = int64(revision)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO cluster_audit_events(plan_id,revision,actor,action,subject_id,detail) VALUES (NULLIF($1,''),$2,$3,$4,$5,$6)`, planID, revisionValue, actor, action, subject, encoded); err != nil {
		return fmt.Errorf("insert cluster audit: %w", err)
	}
	return nil
}

func lockClusterPlan(ctx context.Context, tx *transaction, planID string) error {
	// SQLite writes are serialized through the single Controller connection;
	// the surrounding transaction is the cluster-plan scheduler lock.
	_ = ctx
	_ = tx
	_ = planID
	return nil
}

func ensureNoActiveClusterRollout(ctx context.Context, tx *transaction, planID string) error {
	var rolloutID int64
	err := tx.QueryRow(ctx, `SELECT id FROM cluster_rollouts WHERE plan_id=$1 AND status IN ('publishing','awaiting_ack','baking','rollback_pending','rolling_back') ORDER BY id LIMIT 1 FOR UPDATE`, planID).Scan(&rolloutID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check active cluster rollout: %w", err)
	}
	return fmt.Errorf("%w: %d", ErrRolloutInProgress, rolloutID)
}

func validateActor(actor string) error {
	if strings.TrimSpace(actor) == "" || len(actor) > 256 || strings.ContainsRune(actor, '\x00') {
		return errors.New("actor must contain between 1 and 256 safe characters")
	}
	return nil
}

func prefixContainsAny(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func truncateClusterError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.ReplaceAll(err.Error(), "\x00", "")
	if len(value) > 2048 {
		value = value[:2048]
	}
	return value
}

func truncateHealthError(value string) string {
	value = strings.ReplaceAll(value, "\x00", "")
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func deferrableScheduleError(err error) bool {
	if errors.Is(err, cluster.ErrNoPlacement) || errors.Is(err, ErrManagementConflict) || errors.Is(err, ErrServiceVIPConflict) || errors.Is(err, ErrServiceVIPCapacity) || errors.Is(err, ErrServiceVIPMigration) {
		return true
	}
	var clusterValidation *cluster.ValidationError
	var desiredValidation *spec.ValidationError
	return errors.As(err, &clusterValidation) || errors.As(err, &desiredValidation)
}
