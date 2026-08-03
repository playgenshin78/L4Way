package controlclient

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/agent"
	"flux.local/flux/internal/securechannel"
	"flux.local/flux/internal/spec"
	"flux.local/flux/internal/usage"

	"google.golang.org/grpc/credentials"
)

type recordingReconciler struct {
	desired spec.DesiredState
	err     error
}

func (r *recordingReconciler) Apply(_ context.Context, desired spec.DesiredState) (agent.Result, error) {
	r.desired = desired
	return agent.Result{Generation: desired.Generation}, r.err
}

type emptyStateStore struct{}

func (emptyStateStore) Load() (agent.StateRecord, error) { return agent.EmptyStateRecord(), nil }

type fixedStateStore struct{ record agent.StateRecord }

func (s fixedStateStore) Load() (agent.StateRecord, error) { return s.record, nil }

type maintenanceReconciler struct {
	refresh chan struct{}
	audit   chan struct{}
	usage   chan struct{}
}

func (*maintenanceReconciler) Apply(context.Context, spec.DesiredState) (agent.Result, error) {
	return agent.Result{}, nil
}

func (r *maintenanceReconciler) Refresh(context.Context) (agent.Result, error) {
	select {
	case r.refresh <- struct{}{}:
	default:
	}
	return agent.Result{Generation: 1, Checksum: "desired", ProgramChecksum: "program", Changed: true}, nil
}

func (r *maintenanceReconciler) Audit(context.Context) (agent.Result, error) {
	select {
	case r.audit <- struct{}{}:
	default:
	}
	return agent.Result{}, nil
}

func (r *maintenanceReconciler) CollectUsage(context.Context) ([]usage.Batch, error) {
	select {
	case r.usage <- struct{}{}:
	default:
	}
	return []usage.Batch{{Sequence: 1}}, nil
}

func (*maintenanceReconciler) PendingUsage() ([]usage.Batch, error) { return nil, nil }
func (*maintenanceReconciler) AckUsage(string, uint64) error        { return nil }

func TestApplySnapshotValidatesEnvelopeAndReconciles(t *testing.T) {
	reconciler := &recordingReconciler{}
	runner, err := New(Config{
		Target: "controller:9443", NodeID: "node-a", AgentVersion: "test",
		Credentials: testCredentials(t, "node-a"),
	}, reconciler, emptyStateStore{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	desired := directDesired()
	encoded, _ := spec.EncodeDesiredJSON(desired)
	checksum, _ := desired.Checksum()
	snapshot := &controlv1.DesiredSnapshot{
		ProtocolVersion: 1, SchemaVersion: 1, NodeId: "node-a", Generation: 1,
		DesiredChecksum: checksum, DesiredStateJson: encoded,
		RequiredCapabilities: []*controlv1.Capability{{Name: "nft.direct", Version: 1}},
	}
	result := runner.applySnapshot(context.Background(), snapshot)
	if result.Status != controlv1.ApplyStatus_APPLY_STATUS_APPLIED || reconciler.desired.Generation != 1 {
		t.Fatalf("result=%+v desired=%+v", result, reconciler.desired)
	}
	snapshot.DesiredChecksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	result = runner.applySnapshot(context.Background(), snapshot)
	if result.ErrorCode != controlv1.ApplyErrorCode_APPLY_ERROR_CODE_CHECKSUM_MISMATCH || result.Status != controlv1.ApplyStatus_APPLY_STATUS_PERMANENT_ERROR {
		t.Fatalf("checksum mismatch result=%+v", result)
	}
}

func TestHelloReadvertisesDurableACK(t *testing.T) {
	desired := directDesired()
	checksum, _ := desired.Checksum()
	record := agent.StateRecord{
		Version: 1,
		Applied: &agent.Snapshot{Desired: desired, Checksum: checksum, PreparedAt: time.Now().UTC()},
	}
	runner, err := New(Config{
		Target: "controller:9443", NodeID: "node-a", AgentVersion: "test",
		Credentials:        testCredentials(t, "node-a"),
		WireGuardPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	}, &recordingReconciler{}, fixedStateStore{record: record}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hello, ack, err := runner.buildHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.AppliedGeneration != 1 || hello.AppliedDesiredChecksum != checksum || hello.WireguardPublicKey == "" {
		t.Fatalf("hello did not advertise applied state: %+v", hello)
	}
	if ack == nil || ack.Status != controlv1.ApplyStatus_APPLY_STATUS_APPLIED || ack.DesiredChecksum != checksum {
		t.Fatalf("durable ACK was not rebuilt: %+v", ack)
	}
}

func testCredentials(t *testing.T, nodeID string) credentials.TransportCredentials {
	t.Helper()
	node, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	controller, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	transport, err := securechannel.NewClientCredentials(nodeID, node, controller.Public)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func TestLocalMaintenanceRunsWithoutAControllerSession(t *testing.T) {
	reconciler := &maintenanceReconciler{refresh: make(chan struct{}, 1), audit: make(chan struct{}, 1), usage: make(chan struct{}, 1)}
	runner := &Runner{
		config:     Config{ApplyTimeout: time.Second, PolicyInterval: 5 * time.Millisecond, UsageInterval: 5 * time.Millisecond, ReconcileInterval: 5 * time.Millisecond, HealthInterval: 5 * time.Millisecond},
		reconciler: reconciler, store: emptyStateStore{}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	results := make(chan agent.Result, 4)
	usageReady := make(chan struct{}, 1)
	go runner.runLocalMaintenance(ctx, results, usageReady, make(chan struct{}, 1))
	for name, channel := range map[string]<-chan struct{}{"refresh": reconciler.refresh, "audit": reconciler.audit, "usage": reconciler.usage, "usage signal": usageReady} {
		select {
		case <-channel:
		case <-ctx.Done():
			t.Fatalf("%s did not run without a controller session", name)
		}
	}
	select {
	case result := <-results:
		if !result.Changed || result.Generation != 1 {
			t.Fatalf("local result = %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("local lifecycle result was not queued")
	}
}

func directDesired() spec.DesiredState {
	return spec.DesiredState{
		SchemaVersion: 1, NodeID: "node-a", Generation: 1,
		Forwards: []spec.ForwardSpec{{
			ID: "web", UserID: "user-a", Protocols: []spec.Protocol{spec.ProtocolTCP},
			IngressNodeID: "node-a", Listen: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
			Target:   spec.Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
			PathMode: spec.PathDirect, SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade},
			Lifecycle: spec.LifecycleActive, ResourceVersion: 1,
		}},
	}
}
