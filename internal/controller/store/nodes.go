package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"flux.local/flux/internal/spec"
)

type NodeSummary struct {
	ID                 string          `json:"id"`
	DesiredGeneration  uint64          `json:"desired_generation"`
	AppliedGeneration  uint64          `json:"applied_generation"`
	AgentVersion       string          `json:"agent_version,omitempty"`
	Capabilities       json.RawMessage `json:"capabilities"`
	WireGuardPublicKey string          `json:"wireguard_public_key,omitempty"`
	LastSeenAt         *time.Time      `json:"last_seen_at,omitempty"`
	RevokedAt          *time.Time      `json:"revoked_at,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// EnsurePendingNode creates the minimal node record needed to include a node
// in a Cluster Plan before its Agent has enrolled. It is intentionally
// idempotent so installer retries do not create additional state. A revoked
// node ID can never be reintroduced this way.
func (s *Store) EnsurePendingNode(ctx context.Context, nodeID string) (bool, error) {
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		return false, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin pending node transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	created, err := ensurePendingNodeTx(ctx, tx, nodeID)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit pending node transaction: %w", err)
	}
	return created, nil
}

func ensurePendingNodeTx(ctx context.Context, tx *transaction, nodeID string) (bool, error) {
	result, err := tx.Exec(ctx, `INSERT INTO nodes(id) VALUES ($1) ON CONFLICT (id) DO NOTHING`, nodeID)
	if err != nil {
		return false, fmt.Errorf("ensure pending node: %w", err)
	}
	var nodeRevoked bool
	if err := tx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM nodes WHERE id=$1`, nodeID).Scan(&nodeRevoked); err != nil {
		return false, fmt.Errorf("check pending node status: %w", err)
	}
	if nodeRevoked {
		return false, ErrNodeRevoked
	}
	return result.RowsAffected() == 1, nil
}

func (s *Store) ListNodes(ctx context.Context, limit, offset int) ([]NodeSummary, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.pool.Query(ctx, `
SELECT id,desired_generation,applied_generation,agent_version,capabilities,wireguard_public_key,
       last_seen_at,revoked_at,created_at,updated_at
FROM nodes ORDER BY created_at DESC,id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()
	result := make([]NodeSummary, 0)
	for rows.Next() {
		var node NodeSummary
		var desired, applied int64
		var agentVersion, wireGuardPublicKey sql.NullString
		var lastSeen, revoked sql.NullTime
		var capabilities []byte
		if err := rows.Scan(&node.ID, &desired, &applied, &agentVersion, &capabilities, &wireGuardPublicKey,
			&lastSeen, &revoked, &node.CreatedAt, &node.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan node summary: %w", err)
		}
		node.DesiredGeneration = uint64(desired)
		node.AppliedGeneration = uint64(applied)
		node.AgentVersion = agentVersion.String
		node.WireGuardPublicKey = wireGuardPublicKey.String
		node.Capabilities = append(json.RawMessage(nil), capabilities...)
		if lastSeen.Valid {
			value := lastSeen.Time.UTC()
			node.LastSeenAt = &value
		}
		if revoked.Valid {
			value := revoked.Time.UTC()
			node.RevokedAt = &value
		}
		result = append(result, node)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node summaries: %w", err)
	}
	return result, nil
}

// DeletePendingNode removes an installation placeholder that has never
// enrolled, received desired state, or reported from an Agent. Enrollment
// tokens are removed by the nodes foreign-key cascade.
func (s *Store) DeletePendingNode(ctx context.Context, nodeID string) error {
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin pending node deletion: %w", err)
	}
	defer tx.Rollback(ctx)

	var desired, applied int64
	var hasLastSeen, hasIdentity bool
	err = tx.QueryRow(ctx, `
SELECT desired_generation,applied_generation,last_seen_at IS NOT NULL,
       EXISTS(SELECT 1 FROM node_keys WHERE node_id=nodes.id)
FROM nodes WHERE id=$1`, nodeID).Scan(&desired, &applied, &hasLastSeen, &hasIdentity)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeNotFound
	}
	if err != nil {
		return fmt.Errorf("read pending node for deletion: %w", err)
	}
	if desired != 0 || applied != 0 || hasLastSeen || hasIdentity {
		return ErrNodeDeletionConflict
	}
	result, err := tx.Exec(ctx, `DELETE FROM nodes WHERE id=$1`, nodeID)
	if err != nil {
		return fmt.Errorf("delete pending node: %w", err)
	}
	if affected := result.RowsAffected(); affected != 1 {
		return ErrNodeNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit pending node deletion: %w", err)
	}
	return nil
}

// RevokeNode permanently invalidates the node identity and every outstanding
// enrollment token for that node ID. Connected Agents are rejected by the
// control channel's periodic authorization check.
func (s *Store) RevokeNode(ctx context.Context, nodeID string, now time.Time) error {
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		return err
	}
	if now.IsZero() {
		return errors.New("node revocation time is required")
	}
	now = now.UTC()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin node revocation: %w", err)
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1)`, nodeID).Scan(&exists); err != nil {
		return fmt.Errorf("read node for revocation: %w", err)
	}
	if !exists {
		return ErrNodeNotFound
	}
	if _, err := tx.Exec(ctx, `
UPDATE nodes SET revoked_at=COALESCE(revoked_at,$2),updated_at=$2 WHERE id=$1`, nodeID, now); err != nil {
		return fmt.Errorf("revoke node: %w", err)
	}
	if _, err := tx.Exec(ctx, `
UPDATE node_keys SET revoked_at=COALESCE(revoked_at,$2) WHERE node_id=$1`, nodeID, now); err != nil {
		return fmt.Errorf("revoke node keys: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM enrollment_tokens WHERE node_id=$1 AND used_at IS NULL`, nodeID); err != nil {
		return fmt.Errorf("invalidate node enrollment tokens: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit node revocation: %w", err)
	}
	return nil
}
