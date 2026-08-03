package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	shared "flux.local/flux/internal/control"
	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/health"
	"flux.local/flux/internal/securechannel"
	"flux.local/flux/internal/spec"
	"flux.local/flux/internal/usage"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type fakeRepository struct {
	publicKey []byte
	snapshot  store.SnapshotRecord
	ack       chan store.ApplyRecord
	usage     chan usage.Batch
	health    chan health.Report
}

func (r *fakeRepository) AuthorizeNodeKey(_ context.Context, nodeID string, publicKey []byte, _ time.Time) error {
	if nodeID != "node-a" || !equalTestBytes(publicKey, r.publicKey) {
		return store.ErrCredentialRevoked
	}
	return nil
}
func (r *fakeRepository) RecordHello(context.Context, store.HelloRecord) error { return nil }
func (r *fakeRepository) LatestSnapshot(context.Context, string) (store.SnapshotRecord, bool, error) {
	return r.snapshot, true, nil
}
func (r *fakeRepository) RecordApplyResult(_ context.Context, record store.ApplyRecord) error {
	r.ack <- record
	return nil
}
func (r *fakeRepository) RecordHeartbeat(context.Context, string, time.Time) error { return nil }
func (r *fakeRepository) RecordUsageBatch(_ context.Context, batch usage.Batch) error {
	if r.usage != nil {
		r.usage <- batch
	}
	return nil
}
func (r *fakeRepository) RecordBackendHealth(_ context.Context, report health.Report) error {
	if r.health != nil {
		r.health <- report
	}
	return nil
}

func TestNoiseAESStreamDeliversSnapshotAndRecordsACK(t *testing.T) {
	now := time.Now().UTC()
	controllerIdentity, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nodeIdentity, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	desired := testDesired()
	desiredJSON, _ := spec.EncodeDesiredJSON(desired)
	checksum, _ := desired.Checksum()
	repository := &fakeRepository{
		publicKey: nodeIdentity.Public, ack: make(chan store.ApplyRecord, 1), usage: make(chan usage.Batch, 1), health: make(chan health.Report, 1),
		snapshot: store.SnapshotRecord{
			NodeID: "node-a", Generation: 1, SchemaVersion: 1, DesiredChecksum: checksum,
			DesiredStateJSON: desiredJSON, RequiredCapabilities: json.RawMessage(`[]`), CreatedAt: now,
		},
	}
	commands := NewCommandBroker()
	service, err := NewServerWithConfig(repository, NewNotifier(), nil, ServerConfig{Commands: commands})
	if err != nil {
		t.Fatal(err)
	}
	serverCredentials, err := securechannel.NewServerCredentials(controllerIdentity, func(ctx context.Context, nodeID string, publicKey []byte) error {
		return repository.AuthorizeNodeKey(ctx, nodeID, publicKey, time.Now().UTC())
	})
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer(grpc.Creds(serverCredentials))
	controlv1.RegisterAgentControlServer(grpcServer, service)
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientCredentials, err := securechannel.NewClientCredentials("node-a", nodeIdentity, controllerIdentity.Public)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(clientCredentials))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	stream, err := controlv1.NewAgentControlClient(connection).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := shared.SessionNonce()
	err = stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_Hello{Hello: &controlv1.AgentHello{
		ProtocolVersion: 1, NodeId: "node-a", AgentVersion: "test", SupportedSchemaVersions: spec.SupportedSchemaVersions(),
		Capabilities: shared.DefaultCapabilities(), SessionNonce: nonce,
		WireguardPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if event.GetSnapshot() == nil || event.GetSnapshot().DesiredChecksum != checksum {
		t.Fatalf("unexpected controller event: %+v", event)
	}
	programChecksum := strings.Repeat("b", 64)
	err = stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_ApplyResult{ApplyResult: &controlv1.ApplyResult{
		NodeId: "node-a", Generation: 1, DesiredChecksum: checksum, ProgramChecksum: programChecksum,
		Status: controlv1.ApplyStatus_APPLY_STATUS_APPLIED, ErrorCode: controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NONE,
		ObservedAtUnix: now.Unix(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ack := <-repository.ack:
		if ack.Generation != 1 || ack.Status != "applied" || ack.ProgramChecksum != programChecksum {
			t.Fatalf("unexpected ACK: %+v", ack)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for ACK")
	}
	err = stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_UsageBatch{UsageBatch: &controlv1.UsageBatch{
		NodeId: "node-a", CounterEpoch: programChecksum, Sequence: 1, Generation: 1, ObservedAtUnix: now.Unix(),
		Deltas: []*controlv1.UsageDelta{{ForwardId: "web", Protocol: "tcp", Direction: controlv1.UsageDirection_USAGE_DIRECTION_UPLOAD, ResourceVersion: 1, Packets: 2, Bytes: 200}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	usageEvent, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if usageEvent.GetUsageAck() == nil || usageEvent.GetUsageAck().Sequence != 1 || usageEvent.GetUsageAck().CounterEpoch != programChecksum {
		t.Fatalf("unexpected usage ACK: %+v", usageEvent)
	}
	select {
	case recorded := <-repository.usage:
		if len(recorded.Deltas) != 1 || recorded.Deltas[0].Direction != spec.DirectionUpload || recorded.Deltas[0].Bytes != 200 {
			t.Fatalf("unexpected recorded usage: %+v", recorded)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for usage record")
	}
	err = stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_BackendHealth{BackendHealth: &controlv1.BackendHealthReport{
		NodeId: "node-a", Generation: 1, PoolId: "pool-a", BackendId: "backend-a", ResourceVersion: 2,
		Status: controlv1.BackendHealthStatus_BACKEND_HEALTH_STATUS_HEALTHY, LatencyMilliseconds: 7, ObservedAtUnix: now.Unix(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case recorded := <-repository.health:
		if recorded.Status != health.StatusHealthy || recorded.Latency != 7*time.Millisecond || recorded.ResourceVersion != 2 {
			t.Fatalf("unexpected recorded health: %+v", recorded)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for health report")
	}
	commandFinished := make(chan error, 1)
	go func() {
		result, err := commands.Dispatch(ctx, "node-a", CommandRequest{
			Kind:     controlv1.NodeCommandKind_NODE_COMMAND_KIND_TCP_CHECK,
			Deadline: time.Now().UTC().Add(2 * time.Second),
			Address:  "192.0.2.25",
			Port:     443,
		})
		if err == nil && (result == nil || !result.Success) {
			err = fmt.Errorf("unexpected command result: %+v", result)
		}
		commandFinished <- err
	}()
	commandEvent, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	command := commandEvent.GetCommand()
	if command == nil || command.Address != "192.0.2.25" || command.Port != 443 {
		t.Fatalf("unexpected node command: %+v", commandEvent)
	}
	if err := stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_CommandResult{CommandResult: &controlv1.NodeCommandResult{
		RequestId: command.RequestId, Kind: command.Kind, Success: true, CompletedAtUnix: time.Now().UTC().Unix(),
	}}}); err != nil {
		t.Fatal(err)
	}
	ackEvent, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if ack := ackEvent.GetCommandAck(); ack == nil || ack.RequestId != command.RequestId || ack.Kind != command.Kind {
		t.Fatalf("unexpected node command acknowledgement: %+v", ackEvent)
	}
	select {
	case err := <-commandFinished:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for node command result")
	}
}

func equalTestBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func testDesired() spec.DesiredState {
	return spec.DesiredState{
		SchemaVersion: 1, NodeID: "node-a", Generation: 1,
		Forwards: []spec.ForwardSpec{{
			ID: "web", UserID: "user-a", Protocols: []spec.Protocol{spec.ProtocolTCP}, IngressNodeID: "node-a",
			Listen:   spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
			Target:   spec.Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
			PathMode: spec.PathDirect, SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade}, Lifecycle: spec.LifecycleActive, ResourceVersion: 1,
		}},
	}
}
