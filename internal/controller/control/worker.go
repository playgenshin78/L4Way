package control

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"flux.local/flux/internal/controller/store"
)

type OutboxRepository interface {
	ClaimOutbox(context.Context, string, int, time.Duration) ([]store.OutboxEvent, error)
	MarkOutboxDelivered(context.Context, string, int64) error
	ReleaseOutbox(context.Context, string, int64, string) error
}

type PolicyRepository interface {
	EnforcePolicies(context.Context, int, time.Time) (int, error)
}

type ClusterRepository interface {
	AdvanceClusterRollouts(context.Context, string, int, time.Time) (int, error)
	ReconcileClusterPlans(context.Context, string, int, time.Time) (int, error)
}

type ClusterDeleteRepository interface {
	FinalizeClusterDeletes(context.Context, string, int, time.Time) (int, error)
}

type TenantPolicyEnforcementRepository interface {
	EnforceTenantForwardPolicies(context.Context, string, int, time.Time) (int, error)
}

type TrafficQuotaEnforcementRepository interface {
	EnforceTrafficQuotas(context.Context, string, int, time.Time) (int, error)
}

type Worker struct {
	repository OutboxRepository
	notifier   *Notifier
	owner      string
	logger     *slog.Logger
	interval   time.Duration
}

func NewWorker(repository OutboxRepository, notifier *Notifier, owner string, logger *slog.Logger) (*Worker, error) {
	if repository == nil || notifier == nil || owner == "" {
		return nil, errors.New("outbox worker requires repository, notifier, and owner")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{repository: repository, notifier: notifier, owner: owner, logger: logger, interval: time.Second}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		if clusters, ok := w.repository.(ClusterRepository); ok {
			if advanced, err := clusters.AdvanceClusterRollouts(ctx, w.owner, 10, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
				w.logger.Error("cluster rollout advancement failed", "error", err)
			} else if advanced != 0 {
				w.logger.Info("cluster rollout barriers advanced", "count", advanced)
			}
			if finalizer, ok := w.repository.(ClusterDeleteRepository); ok {
				if finalized, err := finalizer.FinalizeClusterDeletes(ctx, "system:"+w.owner, 10, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
					w.logger.Error("cluster delete finalization failed", "error", err)
				} else if finalized != 0 {
					w.logger.Info("cluster forwards finalized", "count", finalized)
				}
			}
			if enforcement, ok := w.repository.(TenantPolicyEnforcementRepository); ok {
				if paused, err := enforcement.EnforceTenantForwardPolicies(ctx, "system:"+w.owner, 10, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
					w.logger.Error("tenant forward policy enforcement failed", "error", err)
				} else if paused != 0 {
					w.logger.Info("tenant forwards paused by policy", "count", paused)
				}
			}
			if enforcement, ok := w.repository.(TrafficQuotaEnforcementRepository); ok {
				if paused, err := enforcement.EnforceTrafficQuotas(ctx, "system:"+w.owner, 10, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
					w.logger.Error("traffic quota enforcement failed", "error", err)
				} else if paused != 0 {
					w.logger.Info("forwards paused by traffic quota", "count", paused)
				}
			}
			if published, err := clusters.ReconcileClusterPlans(ctx, w.owner, 10, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
				w.logger.Error("cluster reconciliation failed", "error", err)
			} else if published != 0 {
				w.logger.Info("cluster generations published", "count", published)
			}
		}
		if policy, ok := w.repository.(PolicyRepository); ok {
			if published, err := policy.EnforcePolicies(ctx, 100, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
				w.logger.Error("policy enforcement failed", "error", err)
			} else if published != 0 {
				w.logger.Info("policy generations published", "count", published)
			}
		}
		if err := w.drain(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("outbox dispatch failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (w *Worker) drain(ctx context.Context) error {
	events, err := w.repository.ClaimOutbox(ctx, w.owner, 100, 15*time.Second)
	if err != nil {
		return err
	}
	for _, event := range events {
		if event.Topic != "node.snapshot.ready" {
			_ = w.repository.ReleaseOutbox(ctx, w.owner, event.ID, "unsupported outbox topic")
			continue
		}
		w.notifier.Notify(event.AggregateID)
		if err := w.repository.MarkOutboxDelivered(ctx, w.owner, event.ID); err != nil {
			return err
		}
	}
	return nil
}
