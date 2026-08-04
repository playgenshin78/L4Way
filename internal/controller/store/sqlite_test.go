package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/cluster"
	shared "flux.local/flux/internal/control"
	"flux.local/flux/internal/securechannel"
	"flux.local/flux/internal/spec"
	"flux.local/flux/internal/usage"
)

func TestSQLiteQueryRewritePreservesNumberedParameterReuse(t *testing.T) {
	query := `UPDATE sample SET first=$2,second=$2 WHERE id=$1 AND version=$3`
	want := `UPDATE sample SET first=?2,second=?2 WHERE id=?1 AND version=?3`
	if actual := rewriteQuery(query); actual != want {
		t.Fatalf("rewritten query = %q, want %q", actual, want)
	}
}

func TestSQLiteStoreEnrollmentPublishUsageAndBackup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	databasePath := filepath.Join(t.TempDir(), "flux.db")
	repository, err := Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := repository.Migrate(ctx); err != nil {
		t.Fatalf("migration is not idempotent: %v", err)
	}
	token, _, err := repository.CreateEnrollmentToken(ctx, "node-a", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyRecord, err := repository.CompleteEnrollment(ctx, "node-a", token, identity.Public)
	if err != nil {
		t.Fatal(err)
	}
	if keyRecord.Fingerprint != securechannel.Fingerprint(identity.Public) {
		t.Fatalf("unexpected key fingerprint: %s", keyRecord.Fingerprint)
	}
	if _, _, err := repository.CreateEnrollmentToken(ctx, "node-a", 10*time.Minute); !errors.Is(err, ErrNodeAlreadyEnrolled) {
		t.Fatalf("second enrollment token error=%v, want ErrNodeAlreadyEnrolled", err)
	}
	if err := repository.AuthorizeNodeKey(ctx, "node-a", identity.Public, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	capabilities, _ := json.Marshal(shared.DefaultCapabilities())
	if err := repository.RecordHello(ctx, HelloRecord{
		NodeID: "node-a", KeyFingerprint: keyRecord.Fingerprint, AgentVersion: "test",
		Capabilities: capabilities, ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	desired := sqliteTestDesired()
	snapshot, err := repository.PublishDesired(ctx, "node-a", desired, nil)
	if err != nil {
		t.Fatal(err)
	}
	latest, exists, err := repository.LatestSnapshot(ctx, "node-a")
	if err != nil || !exists || latest.Generation != snapshot.Generation || latest.DesiredChecksum != snapshot.DesiredChecksum {
		t.Fatalf("latest snapshot=%+v exists=%v err=%v", latest, exists, err)
	}
	programChecksum := strings.Repeat("b", 64)
	if err := repository.RecordApplyResult(ctx, ApplyRecord{
		NodeID: "node-a", Generation: snapshot.Generation, DesiredChecksum: snapshot.DesiredChecksum,
		ProgramChecksum: programChecksum, Status: "applied", ErrorCode: controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NONE.String(),
		ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	batch := usage.Batch{
		NodeID: "node-a", Epoch: strings.Repeat("c", 64), Sequence: 1,
		Generation: snapshot.Generation, ObservedAt: time.Now().UTC(),
		Deltas: []usage.Delta{{ForwardID: "web", Protocol: spec.ProtocolTCP, Direction: spec.DirectionUpload, ResourceVersion: 1, Packets: 2, Bytes: 200}},
	}
	if err := repository.RecordUsageBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordUsageBatch(ctx, batch); err != nil {
		t.Fatalf("duplicate usage batch is not idempotent: %v", err)
	}
	summary, err := repository.ReadUsageSummary(ctx, "user-a", batch.ObservedAt.Add(-time.Hour), batch.ObservedAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalBytes != 200 || len(summary.Series) != 1 || summary.Series[0].Bytes != 200 ||
		len(summary.ByForward) != 1 || summary.ByForward[0].ForwardID != "web" {
		t.Fatalf("usage summary = %+v", summary)
	}
	events, err := repository.ClaimOutbox(ctx, "single-controller", 10, 15*time.Second)
	if err != nil || len(events) == 0 {
		t.Fatalf("claim outbox events=%+v err=%v", events, err)
	}
	for _, event := range events {
		if err := repository.MarkOutboxDelivered(ctx, "single-controller", event.ID); err != nil {
			t.Fatal(err)
		}
	}
	backupPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := repository.BackupTo(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	backupStore, err := Open(ctx, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	defer backupStore.Close()
	if err := backupStore.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	backupSnapshot, exists, err := backupStore.LatestSnapshot(ctx, "node-a")
	if err != nil || !exists || backupSnapshot.DesiredChecksum != snapshot.DesiredChecksum {
		t.Fatalf("backup snapshot=%+v exists=%v err=%v", backupSnapshot, exists, err)
	}
}

func TestSQLiteStoreNodeRevocationInvalidatesIdentityAndEnrollment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "revocation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	token, _, err := repository.CreateEnrollmentToken(ctx, "node-revoked", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CompleteEnrollment(ctx, "node-revoked", token, identity.Public); err != nil {
		t.Fatal(err)
	}
	if err := repository.AuthorizeNodeKey(ctx, "node-revoked", identity.Public, time.Now().UTC()); err != nil {
		t.Fatalf("authorize enrolled node: %v", err)
	}

	revokedAt := time.Now().UTC()
	if err := repository.RevokeNode(ctx, "node-revoked", revokedAt); err != nil {
		t.Fatalf("revoke node: %v", err)
	}
	if err := repository.RevokeNode(ctx, "node-revoked", revokedAt.Add(time.Minute)); err != nil {
		t.Fatalf("repeat node revocation is not idempotent: %v", err)
	}
	if err := repository.AuthorizeNodeKey(ctx, "node-revoked", identity.Public, time.Now().UTC()); !errors.Is(err, ErrNodeRevoked) {
		t.Fatalf("revoked node authorization error = %v, want ErrNodeRevoked", err)
	}
	if _, _, err := repository.CreateEnrollmentToken(ctx, "node-revoked", 10*time.Minute); !errors.Is(err, ErrNodeRevoked) {
		t.Fatalf("revoked node enrollment error = %v, want ErrNodeRevoked", err)
	}
}

func TestSQLiteClusterPlanScheduling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "cluster.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	capabilities, _ := json.Marshal(shared.DefaultCapabilities())
	for index, nodeID := range []string{"node-a", "node-b"} {
		token, _, err := repository.CreateEnrollmentToken(ctx, nodeID, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		identity, _ := securechannel.GenerateKeyPair()
		record, err := repository.CompleteEnrollment(ctx, nodeID, token, identity.Public)
		if err != nil {
			t.Fatal(err)
		}
		wireGuardKey := "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
		if index == 1 {
			wireGuardKey = "AgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICE="
		}
		if err := repository.RecordHello(ctx, HelloRecord{
			NodeID: nodeID, KeyFingerprint: record.Fingerprint, AgentVersion: "test",
			Capabilities: capabilities, WireGuardPublicKey: wireGuardKey, ObservedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "cluster-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := cluster.DecodePlanJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	result, err := repository.ApplyClusterPlan(ctx, plan, "owner:test")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Scheduled || result.RolloutID == 0 || len(result.Placements) != 1 {
		t.Fatalf("cluster plan was not scheduled: %+v", result)
	}
	status, err := repository.ClusterStatus(ctx, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.ActiveRevision != plan.Revision || status.LatestRolloutID != result.RolloutID {
		t.Fatalf("unexpected cluster status: %+v", status)
	}
	for attempt := 0; attempt < 12 && status.LatestRollout != "completed"; attempt++ {
		pending, err := repository.pool.Query(ctx, `SELECT node_id,generation,desired_checksum FROM cluster_rollout_nodes WHERE rollout_id=$1 AND status='pending' ORDER BY stage_order,node_id`, result.RolloutID)
		if err != nil {
			t.Fatal(err)
		}
		type pendingACK struct {
			nodeID     string
			generation int64
			checksum   string
		}
		var acknowledgements []pendingACK
		for pending.Next() {
			var acknowledgement pendingACK
			if err := pending.Scan(&acknowledgement.nodeID, &acknowledgement.generation, &acknowledgement.checksum); err != nil {
				pending.Close()
				t.Fatal(err)
			}
			acknowledgements = append(acknowledgements, acknowledgement)
		}
		pending.Close()
		for _, acknowledgement := range acknowledgements {
			if err := repository.RecordApplyResult(ctx, ApplyRecord{
				NodeID: acknowledgement.nodeID, Generation: uint64(acknowledgement.generation),
				DesiredChecksum: acknowledgement.checksum, ProgramChecksum: strings.Repeat("d", 64),
				Status: "applied", ErrorCode: controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NONE.String(), ObservedAt: time.Now().UTC(),
			}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := repository.AdvanceClusterRollouts(ctx, "single-controller", 10, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		status, err = repository.ClusterStatus(ctx, plan.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if status.LatestRollout != "completed" {
		t.Fatalf("SQLite rollout did not complete: %+v", status)
	}
}

func TestSQLitePendingNodeCanBootstrapInitialClusterPlan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "bootstrap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	created, err := repository.EnsurePendingNode(ctx, "node-a")
	if err != nil || !created {
		t.Fatalf("ensure pending node created=%v err=%v", created, err)
	}
	created, err = repository.EnsurePendingNode(ctx, "node-a")
	if err != nil || created {
		t.Fatalf("second ensure pending node created=%v err=%v", created, err)
	}
	plan := cluster.Plan{
		SchemaVersion: 1,
		ID:            "default",
		Revision:      1,
		Nodes: []cluster.Node{{
			ID: "node-a", Enabled: true,
			Roles:         []cluster.NodeRole{cluster.RoleIngress, cluster.RoleExit},
			ListenIPs:     []netip.Addr{netip.MustParseAddr("192.0.2.10")},
			FailureDomain: "default",
			Capacity:      cluster.Capacity{MaxForwards: 100},
		}},
	}
	if _, err := repository.ApplyClusterPlan(ctx, plan, "installer"); err != nil {
		t.Fatalf("apply initial plan with pending node: %v", err)
	}
}

func TestTrafficQuotaPauseUpdatesActiveClusterPlan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "quota.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	capabilities, _ := json.Marshal(shared.DefaultCapabilities())
	for index, nodeID := range []string{"node-a", "node-b"} {
		token, _, err := repository.CreateEnrollmentToken(ctx, nodeID, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		identity, _ := securechannel.GenerateKeyPair()
		record, err := repository.CompleteEnrollment(ctx, nodeID, token, identity.Public)
		if err != nil {
			t.Fatal(err)
		}
		wireGuardKey := "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
		if index == 1 {
			wireGuardKey = "AgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICE="
		}
		if err := repository.RecordHello(ctx, HelloRecord{
			NodeID: nodeID, KeyFingerprint: record.Fingerprint, AgentVersion: "test",
			Capabilities: capabilities, WireGuardPublicKey: wireGuardKey, ObservedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "cluster-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := cluster.DecodePlanJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	plan.Forwards[0].TrafficQuota = &spec.TrafficQuotaSpec{Bytes: 100, Policy: spec.QuotaPolicyPause}
	result, err := repository.ApplyClusterPlan(ctx, plan, "owner:test")
	if err != nil {
		t.Fatal(err)
	}
	completeStoreTestRollout(t, ctx, repository, result.RolloutID)

	var generation int64
	if err := repository.pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id='node-a'`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	batch := usage.Batch{
		NodeID: "node-a", Epoch: strings.Repeat("e", 64), Sequence: 1,
		Generation: uint64(generation), ObservedAt: time.Now().UTC(),
		Deltas: []usage.Delta{{
			ForwardID: "web", Protocol: spec.ProtocolTCP, Direction: spec.DirectionUpload,
			ResourceVersion: 1, Packets: 1, Bytes: 60,
		}},
	}
	if err := repository.RecordUsageBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.pool.Exec(ctx, `
INSERT INTO usage_rollups(node_id,forward_id,user_id,protocol,direction,packets,bytes)
VALUES ('node-b','web','user-a','tcp','upload',1,40)`); err != nil {
		t.Fatal(err)
	}
	paused, err := repository.EnforceTrafficQuotas(ctx, "system:test", 10, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if paused != 1 {
		t.Fatalf("paused forwards = %d, want 1", paused)
	}
	active, err := repository.ActiveClusterPlan(ctx, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active.Plan.Revision != 2 || active.MaximumRevision != 2 {
		t.Fatalf("quota enforcement did not create revision 2: %+v", active)
	}
	forward := active.Plan.Forwards[0]
	if forward.Lifecycle != spec.LifecyclePaused || forward.ResourceVersion != 2 {
		t.Fatalf("active plan did not persist the quota pause: %+v", forward)
	}
}

func completeStoreTestRollout(t *testing.T, ctx context.Context, repository *Store, rolloutID int64) {
	t.Helper()
	for attempt := 0; attempt < 12; attempt++ {
		status := ""
		if err := repository.pool.QueryRow(ctx, `SELECT status FROM cluster_rollouts WHERE id=$1`, rolloutID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "completed" {
			return
		}
		rows, err := repository.pool.Query(ctx, `
SELECT node_id,generation,desired_checksum
FROM cluster_rollout_nodes
WHERE rollout_id=$1 AND status='pending'
ORDER BY stage_order,node_id`, rolloutID)
		if err != nil {
			t.Fatal(err)
		}
		type pendingACK struct {
			nodeID     string
			generation int64
			checksum   string
		}
		var acknowledgements []pendingACK
		for rows.Next() {
			var acknowledgement pendingACK
			if err := rows.Scan(&acknowledgement.nodeID, &acknowledgement.generation, &acknowledgement.checksum); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			acknowledgements = append(acknowledgements, acknowledgement)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		for _, acknowledgement := range acknowledgements {
			if err := repository.RecordApplyResult(ctx, ApplyRecord{
				NodeID: acknowledgement.nodeID, Generation: uint64(acknowledgement.generation),
				DesiredChecksum: acknowledgement.checksum, ProgramChecksum: strings.Repeat("f", 64),
				Status: "applied", ErrorCode: controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NONE.String(),
				ObservedAt: time.Now().UTC(),
			}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := repository.AdvanceClusterRollouts(ctx, "single-controller", 10, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatalf("rollout %d did not complete", rolloutID)
}

func sqliteTestDesired() spec.DesiredState {
	return spec.DesiredState{
		SchemaVersion: spec.SchemaVersionV1, NodeID: "node-a", Generation: 1,
		Forwards: []spec.ForwardSpec{{
			ID: "web", UserID: "user-a", Protocols: []spec.Protocol{spec.ProtocolTCP}, IngressNodeID: "node-a",
			Listen:   spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
			Target:   spec.Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
			PathMode: spec.PathDirect, SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade},
			Lifecycle: spec.LifecycleActive, ResourceVersion: 1,
		}},
	}
}
