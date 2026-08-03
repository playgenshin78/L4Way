package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strings"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	shared "flux.local/flux/internal/control"
	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/health"
	"flux.local/flux/internal/securechannel"
	"flux.local/flux/internal/spec"
	"flux.local/flux/internal/usage"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type Repository interface {
	AuthorizeNodeKey(context.Context, string, []byte, time.Time) error
	RecordHello(context.Context, store.HelloRecord) error
	LatestSnapshot(context.Context, string) (store.SnapshotRecord, bool, error)
	RecordApplyResult(context.Context, store.ApplyRecord) error
	RecordHeartbeat(context.Context, string, time.Time) error
	RecordUsageBatch(context.Context, usage.Batch) error
	RecordBackendHealth(context.Context, health.Report) error
}

type Server struct {
	controlv1.UnimplementedAgentControlServer
	repository        Repository
	notifier          *Notifier
	commands          *CommandBroker
	logger            *slog.Logger
	now               func() time.Time
	pollInterval      time.Duration
	pingInterval      time.Duration
	authorizeInterval time.Duration
	heartbeatTimeout  time.Duration
	retryDelay        time.Duration
}

type ServerConfig struct {
	PollInterval      time.Duration
	PingInterval      time.Duration
	AuthorizeInterval time.Duration
	HeartbeatTimeout  time.Duration
	RetryDelay        time.Duration
	Commands          *CommandBroker
}

func NewServer(repository Repository, notifier *Notifier, logger *slog.Logger) (*Server, error) {
	return NewServerWithConfig(repository, notifier, logger, ServerConfig{})
}

func NewServerWithConfig(repository Repository, notifier *Notifier, logger *slog.Logger, config ServerConfig) (*Server, error) {
	if repository == nil {
		return nil, errors.New("control repository must not be nil")
	}
	if notifier == nil {
		notifier = NewNotifier()
	}
	if logger == nil {
		logger = slog.Default()
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 5 * time.Second
	}
	if config.PingInterval <= 0 {
		config.PingInterval = 30 * time.Second
	}
	if config.AuthorizeInterval <= 0 {
		config.AuthorizeInterval = 30 * time.Second
	}
	if config.HeartbeatTimeout <= 0 {
		config.HeartbeatTimeout = 95 * time.Second
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = 5 * time.Second
	}
	if config.Commands == nil {
		config.Commands = NewCommandBroker()
	}
	return &Server{
		repository: repository, notifier: notifier, commands: config.Commands, logger: logger, now: time.Now,
		pollInterval: config.PollInterval, pingInterval: config.PingInterval,
		authorizeInterval: config.AuthorizeInterval,
		heartbeatTimeout:  config.HeartbeatTimeout, retryDelay: config.RetryDelay,
	}, nil
}

func (s *Server) Connect(stream controlv1.AgentControl_ConnectServer) error {
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "receive hello: %v", err)
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first agent event must be hello")
	}
	nodeID, peerPublicKey, keyFingerprint, err := peerNodeIdentity(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if err := validateHello(hello, nodeID); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.repository.AuthorizeNodeKey(stream.Context(), nodeID, peerPublicKey, s.now().UTC()); err != nil {
		return status.Error(codes.PermissionDenied, "node Noise identity is not authorized")
	}
	capabilities, err := json.Marshal(hello.Capabilities)
	if err != nil {
		return status.Error(codes.InvalidArgument, "capabilities cannot be encoded")
	}
	if err := s.repository.RecordHello(stream.Context(), store.HelloRecord{
		NodeID: nodeID, KeyFingerprint: keyFingerprint, AgentVersion: hello.AgentVersion,
		Capabilities: capabilities, WireGuardPublicKey: hello.WireguardPublicKey, ObservedAt: s.now().UTC(),
	}); err != nil {
		return status.Errorf(codes.Unavailable, "record hello: %v", err)
	}

	notifications, unsubscribe := s.notifier.Subscribe(nodeID)
	defer unsubscribe()
	commands, unregisterCommands := s.commands.Register(nodeID)
	defer unregisterCommands()
	state := connectionState{
		appliedGeneration: hello.AppliedGeneration,
		appliedChecksum:   hello.AppliedDesiredChecksum,
		supported:         hello.Capabilities,
		supportedSchemas:  schemaSet(hello.SupportedSchemaVersions),
		lastActivity:      s.now(),
	}
	if err := s.sendLatest(stream, nodeID, &state); err != nil {
		return err
	}

	incoming := make(chan receiveResult, 1)
	go receiveEvents(stream, incoming)
	poll := time.NewTicker(s.pollInterval)
	defer poll.Stop()
	ping := time.NewTicker(s.pingInterval)
	defer ping.Stop()
	authorization := time.NewTicker(s.authorizeInterval)
	defer authorization.Stop()
	watchdog := time.NewTicker(time.Second)
	defer watchdog.Stop()

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case received := <-incoming:
			if received.err != nil {
				if errors.Is(received.err, io.EOF) {
					return nil
				}
				return received.err
			}
			state.lastActivity = s.now()
			if err := s.handleEvent(stream, nodeID, received.event, &state); err != nil {
				return err
			}
			go receiveEvents(stream, incoming)
		case <-notifications:
			if err := s.sendLatest(stream, nodeID, &state); err != nil {
				return err
			}
		case command := <-commands:
			if command == nil {
				continue
			}
			if err := stream.Send(&controlv1.ControllerEvent{Payload: &controlv1.ControllerEvent_Command{Command: command}}); err != nil {
				return err
			}
		case <-poll.C:
			if err := s.sendLatest(stream, nodeID, &state); err != nil {
				return err
			}
		case <-ping.C:
			nonce, err := shared.SessionNonce()
			if err != nil {
				return status.Error(codes.Internal, "cannot generate ping nonce")
			}
			if err := stream.Send(&controlv1.ControllerEvent{Payload: &controlv1.ControllerEvent_Ping{Ping: &controlv1.ControllerPing{Nonce: nonce, SentAtUnix: s.now().Unix()}}}); err != nil {
				return err
			}
		case <-authorization.C:
			if err := s.repository.AuthorizeNodeKey(stream.Context(), nodeID, peerPublicKey, s.now().UTC()); err != nil {
				return status.Error(codes.PermissionDenied, "node Noise identity is no longer authorized")
			}
		case <-watchdog.C:
			if s.now().Sub(state.lastActivity) > s.heartbeatTimeout {
				return status.Error(codes.DeadlineExceeded, "agent heartbeat timed out")
			}
		}
	}
}

type connectionState struct {
	appliedGeneration  uint64
	appliedChecksum    string
	lastSentGeneration uint64
	lastSentChecksum   string
	blockedGeneration  uint64
	retryAfter         time.Time
	supported          []*controlv1.Capability
	supportedSchemas   map[uint32]struct{}
	lastActivity       time.Time
}

type receiveResult struct {
	event *controlv1.AgentEvent
	err   error
}

func receiveEvents(stream controlv1.AgentControl_ConnectServer, target chan<- receiveResult) {
	event, err := stream.Recv()
	target <- receiveResult{event: event, err: err}
}

func (s *Server) sendLatest(stream controlv1.AgentControl_ConnectServer, nodeID string, state *connectionState) error {
	record, exists, err := s.repository.LatestSnapshot(stream.Context(), nodeID)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read desired snapshot: %v", err)
	}
	if !exists {
		return nil
	}
	if _, supported := state.supportedSchemas[record.SchemaVersion]; !supported {
		return status.Errorf(codes.FailedPrecondition, "agent does not support desired schema version %d", record.SchemaVersion)
	}
	if record.Generation < state.appliedGeneration {
		return status.Error(codes.DataLoss, "agent applied generation is ahead of controller")
	}
	if record.Generation == state.appliedGeneration {
		if record.DesiredChecksum != state.appliedChecksum {
			return status.Error(codes.DataLoss, "agent and controller disagree on applied generation checksum")
		}
		return nil
	}
	if state.blockedGeneration == record.Generation {
		return nil
	}
	if state.lastSentGeneration == record.Generation && state.lastSentChecksum == record.DesiredChecksum {
		if state.retryAfter.IsZero() || s.now().Before(state.retryAfter) {
			return nil
		}
	}
	required, err := decodeCapabilities(record.RequiredCapabilities)
	if err != nil {
		return status.Error(codes.Internal, "stored required capabilities are invalid")
	}
	if missing := shared.MissingCapabilities(state.supported, required); len(missing) != 0 {
		_ = stream.Send(&controlv1.ControllerEvent{Payload: &controlv1.ControllerEvent_Disconnect{Disconnect: &controlv1.Disconnect{Reason: "missing capabilities: " + strings.Join(missing, ","), Retryable: false}}})
		return status.Error(codes.FailedPrecondition, "agent lacks required capabilities")
	}
	event := &controlv1.ControllerEvent{Payload: &controlv1.ControllerEvent_Snapshot{Snapshot: &controlv1.DesiredSnapshot{
		ProtocolVersion: shared.ProtocolVersion, SchemaVersion: record.SchemaVersion, NodeId: record.NodeID,
		Generation: record.Generation, DesiredChecksum: record.DesiredChecksum,
		DesiredStateJson: append([]byte(nil), record.DesiredStateJSON...), RequiredCapabilities: required,
		IssuedAtUnix: record.CreatedAt.Unix(),
	}}}
	if err := stream.Send(event); err != nil {
		return err
	}
	state.lastSentGeneration = record.Generation
	state.lastSentChecksum = record.DesiredChecksum
	state.retryAfter = time.Time{}
	return nil
}

func (s *Server) handleEvent(stream controlv1.AgentControl_ConnectServer, nodeID string, event *controlv1.AgentEvent, state *connectionState) error {
	ctx := stream.Context()
	if event == nil {
		return status.Error(codes.InvalidArgument, "agent event must not be nil")
	}
	switch payload := event.Payload.(type) {
	case *controlv1.AgentEvent_ApplyResult:
		result := payload.ApplyResult
		if err := validateApplyResult(result, nodeID); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		observedAt := time.Unix(result.ObservedAtUnix, 0).UTC()
		if delta := s.now().UTC().Sub(observedAt); delta > 10*time.Minute || delta < -10*time.Minute {
			return status.Error(codes.InvalidArgument, "apply result clock differs from controller by more than ten minutes")
		}
		statusName := applyStatusName(result.Status)
		err := s.repository.RecordApplyResult(ctx, store.ApplyRecord{
			NodeID: nodeID, Generation: result.Generation, DesiredChecksum: result.DesiredChecksum,
			ProgramChecksum: result.ProgramChecksum, Status: statusName,
			ErrorCode: result.ErrorCode.String(), ErrorMessage: sanitize(result.ErrorMessage, 2048),
			ObservedAt: observedAt,
		})
		if errors.Is(err, store.ErrGenerationMissing) || errors.Is(err, store.ErrChecksumMismatch) || errors.Is(err, store.ErrProgramMismatch) {
			return status.Error(codes.DataLoss, err.Error())
		}
		if err != nil {
			return status.Errorf(codes.Unavailable, "record apply result: %v", err)
		}
		switch result.Status {
		case controlv1.ApplyStatus_APPLY_STATUS_APPLIED:
			state.appliedGeneration = result.Generation
			state.appliedChecksum = result.DesiredChecksum
			state.blockedGeneration = 0
		case controlv1.ApplyStatus_APPLY_STATUS_RETRYABLE_ERROR:
			state.retryAfter = s.now().Add(s.retryDelay)
		case controlv1.ApplyStatus_APPLY_STATUS_PERMANENT_ERROR:
			state.blockedGeneration = result.Generation
		}
		return nil
	case *controlv1.AgentEvent_Heartbeat:
		if payload.Heartbeat == nil || payload.Heartbeat.NodeId != nodeID {
			return status.Error(codes.InvalidArgument, "heartbeat node identity mismatch")
		}
		if payload.Heartbeat.ObservedAtUnix <= 0 {
			return status.Error(codes.InvalidArgument, "heartbeat observed time is invalid")
		}
		if err := s.repository.RecordHeartbeat(ctx, nodeID, s.now().UTC()); err != nil {
			return status.Errorf(codes.Unavailable, "record heartbeat: %v", err)
		}
		return nil
	case *controlv1.AgentEvent_UsageBatch:
		encoded := payload.UsageBatch
		if encoded == nil || encoded.NodeId != nodeID || encoded.Sequence == 0 || encoded.Generation == 0 || !shared.ValidChecksum(encoded.CounterEpoch) || len(encoded.Deltas) > spec.MaxForwardsPerSnapshot*4 {
			return status.Error(codes.InvalidArgument, "usage batch envelope is invalid")
		}
		observedAt := time.Unix(encoded.ObservedAtUnix, 0).UTC()
		if delta := s.now().UTC().Sub(observedAt); delta > 10*time.Minute || delta < -10*time.Minute {
			return status.Error(codes.InvalidArgument, "usage batch clock differs from controller by more than ten minutes")
		}
		batch := usage.Batch{NodeID: nodeID, Epoch: encoded.CounterEpoch, Sequence: encoded.Sequence, Generation: encoded.Generation, ObservedAt: observedAt}
		for _, encodedDelta := range encoded.Deltas {
			if encodedDelta == nil {
				return status.Error(codes.InvalidArgument, "usage delta must not be nil")
			}
			direction := spec.DirectionUpload
			switch encodedDelta.Direction {
			case controlv1.UsageDirection_USAGE_DIRECTION_UPLOAD:
			case controlv1.UsageDirection_USAGE_DIRECTION_DOWNLOAD:
				direction = spec.DirectionDownload
			default:
				return status.Error(codes.InvalidArgument, "usage direction is invalid")
			}
			batch.Deltas = append(batch.Deltas, usage.Delta{ForwardID: encodedDelta.ForwardId, Protocol: spec.Protocol(encodedDelta.Protocol), Direction: direction, ResourceVersion: encodedDelta.ResourceVersion, Packets: encodedDelta.Packets, Bytes: encodedDelta.Bytes, Reset: encodedDelta.Reset_})
		}
		if err := batch.Validate(); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if err := s.repository.RecordUsageBatch(ctx, batch); errors.Is(err, store.ErrGenerationMissing) {
			return status.Error(codes.DataLoss, err.Error())
		} else if err != nil {
			return status.Errorf(codes.Unavailable, "record usage batch: %v", err)
		}
		if err := stream.Send(&controlv1.ControllerEvent{Payload: &controlv1.ControllerEvent_UsageAck{UsageAck: &controlv1.UsageAck{CounterEpoch: batch.Epoch, Sequence: batch.Sequence}}}); err != nil {
			return err
		}
		return nil
	case *controlv1.AgentEvent_BackendHealth:
		encoded := payload.BackendHealth
		if encoded == nil || encoded.NodeId != nodeID || encoded.Generation == 0 || encoded.ResourceVersion == 0 || encoded.ObservedAtUnix <= 0 {
			return status.Error(codes.InvalidArgument, "backend health envelope is invalid")
		}
		if err := spec.ValidateIdentifier("pool_id", encoded.PoolId); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if err := spec.ValidateIdentifier("backend_id", encoded.BackendId); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		healthStatus := health.StatusUnknown
		switch encoded.Status {
		case controlv1.BackendHealthStatus_BACKEND_HEALTH_STATUS_UNKNOWN:
		case controlv1.BackendHealthStatus_BACKEND_HEALTH_STATUS_HEALTHY:
			healthStatus = health.StatusHealthy
		case controlv1.BackendHealthStatus_BACKEND_HEALTH_STATUS_UNHEALTHY:
			healthStatus = health.StatusUnhealthy
		default:
			return status.Error(codes.InvalidArgument, "backend health status is invalid")
		}
		observedAt := time.Unix(encoded.ObservedAtUnix, 0).UTC()
		if delta := s.now().UTC().Sub(observedAt); delta > 10*time.Minute || delta < -10*time.Minute {
			return status.Error(codes.InvalidArgument, "backend health clock differs from controller by more than ten minutes")
		}
		report := health.Report{
			NodeID: nodeID, Generation: encoded.Generation, PoolID: encoded.PoolId, BackendID: encoded.BackendId,
			ResourceVersion: encoded.ResourceVersion, Status: healthStatus,
			Latency: time.Duration(encoded.LatencyMilliseconds) * time.Millisecond,
			Error:   sanitize(encoded.ErrorMessage, 512), ObservedAt: observedAt,
		}
		if err := s.repository.RecordBackendHealth(ctx, report); errors.Is(err, store.ErrGenerationMissing) || errors.Is(err, store.ErrHealthProbeMissing) {
			return status.Error(codes.FailedPrecondition, err.Error())
		} else if err != nil {
			return status.Errorf(codes.Unavailable, "record backend health: %v", err)
		}
		return nil
	case *controlv1.AgentEvent_CommandResult:
		result := payload.CommandResult
		if result == nil || result.RequestId == "" || len(result.RequestId) > 128 || result.Kind == controlv1.NodeCommandKind_NODE_COMMAND_KIND_UNSPECIFIED || result.CompletedAtUnix <= 0 || len(result.ErrorCode) > 128 || len(result.ErrorMessage) > 1024 {
			return status.Error(codes.InvalidArgument, "command result is invalid")
		}
		completedAt := time.Unix(result.CompletedAtUnix, 0).UTC()
		if delta := s.now().UTC().Sub(completedAt); delta > 10*time.Minute || delta < -10*time.Minute {
			return status.Error(codes.InvalidArgument, "command result clock differs from controller by more than ten minutes")
		}
		if result.Success && (result.ErrorCode != "" || result.ErrorMessage != "") {
			return status.Error(codes.InvalidArgument, "successful command result must not include an error")
		}
		if !result.Success && result.ErrorCode == "" {
			return status.Error(codes.InvalidArgument, "failed command result must include an error code")
		}
		if err := s.commands.Complete(nodeID, result); err != nil {
			// A browser request may time out just before the Agent replies. The
			// late response is harmless and must not tear down the node stream.
			// It is still acknowledged so an Agent reconnecting after an ACK-loss
			// can finish its already-approved local maintenance action.
			s.logger.Warn("ignored unmatched node command result", "node_id", nodeID, "request_id", result.RequestId, "error", err)
		}
		if err := stream.Send(&controlv1.ControllerEvent{Payload: &controlv1.ControllerEvent_CommandAck{CommandAck: &controlv1.NodeCommandAck{
			RequestId: result.RequestId, Kind: result.Kind,
		}}}); err != nil {
			return err
		}
		return nil
	case *controlv1.AgentEvent_Hello:
		return status.Error(codes.InvalidArgument, "hello may only be sent once")
	default:
		return status.Error(codes.InvalidArgument, "agent event payload is required")
	}
}

func peerNodeIdentity(ctx context.Context) (string, []byte, string, error) {
	remote, ok := peer.FromContext(ctx)
	if !ok {
		return "", nil, "", errors.New("peer information is missing")
	}
	noiseInfo, ok := remote.AuthInfo.(securechannel.AuthInfo)
	if !ok {
		if pointer, pointerOK := remote.AuthInfo.(*securechannel.AuthInfo); pointerOK && pointer != nil {
			noiseInfo = *pointer
			ok = true
		}
	}
	if !ok || noiseInfo.NodeID == "" || len(noiseInfo.PeerPublicKey) != securechannel.KeySize {
		return "", nil, "", errors.New("authenticated Noise client identity is missing")
	}
	return noiseInfo.NodeID, append([]byte(nil), noiseInfo.PeerPublicKey...), noiseInfo.PeerFingerprint, nil
}

func validateHello(hello *controlv1.AgentHello, authenticatedNodeID string) error {
	if hello.ProtocolVersion != shared.ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", hello.ProtocolVersion)
	}
	if hello.AppliedGeneration > math.MaxInt64 || hello.PendingGeneration > math.MaxInt64 {
		return errors.New("agent generation exceeds the controller range")
	}
	if hello.NodeId != authenticatedNodeID {
		return errors.New("hello node identity does not match the authenticated Noise key")
	}
	if len(hello.AgentVersion) == 0 || len(hello.AgentVersion) > 128 {
		return errors.New("agent_version is invalid")
	}
	if len(hello.SessionNonce) != 16 {
		return errors.New("session nonce must be 16 bytes")
	}
	if err := shared.ValidateCapabilities(hello.Capabilities); err != nil {
		return err
	}
	if hello.WireguardPublicKey != "" {
		if err := spec.ValidateWireGuardPublicKey("wireguard_public_key", hello.WireguardPublicKey); err != nil {
			return err
		}
	}
	for _, capability := range hello.Capabilities {
		if capability != nil && capability.Name == "fabric.wireguard" && hello.WireguardPublicKey == "" {
			return errors.New("fabric.wireguard capability requires wireguard_public_key")
		}
	}
	foundSchema := false
	for _, version := range hello.SupportedSchemaVersions {
		if version == spec.CurrentSchemaVersion {
			foundSchema = true
		}
	}
	if !foundSchema {
		return errors.New("agent does not advertise the current schema version")
	}
	if hello.AppliedGeneration == 0 {
		if hello.AppliedDesiredChecksum != "" || hello.AppliedProgramChecksum != "" {
			return errors.New("empty applied generation must not carry checksums")
		}
	} else if !shared.ValidChecksum(hello.AppliedDesiredChecksum) || !shared.ValidChecksum(hello.AppliedProgramChecksum) {
		return errors.New("applied generation checksums are invalid")
	}
	if hello.PendingGeneration == 0 && hello.PendingDesiredChecksum != "" || hello.PendingGeneration > 0 && !shared.ValidChecksum(hello.PendingDesiredChecksum) {
		return errors.New("pending generation checksum is invalid")
	}
	return nil
}

func schemaSet(versions []uint32) map[uint32]struct{} {
	result := make(map[uint32]struct{}, len(versions))
	for _, version := range versions {
		result[version] = struct{}{}
	}
	return result
}

func validateApplyResult(result *controlv1.ApplyResult, nodeID string) error {
	if result == nil || result.NodeId != nodeID || result.Generation == 0 || result.Generation > math.MaxInt64 || !shared.ValidChecksum(result.DesiredChecksum) {
		return errors.New("apply result identity, generation, or desired checksum is invalid")
	}
	if result.ObservedAtUnix <= 0 {
		return errors.New("apply result observed time is invalid")
	}
	switch result.Status {
	case controlv1.ApplyStatus_APPLY_STATUS_APPLIED:
		if !shared.ValidChecksum(result.ProgramChecksum) || result.ErrorCode != controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NONE || result.ErrorMessage != "" {
			return errors.New("applied result must carry a program checksum and no error")
		}
	case controlv1.ApplyStatus_APPLY_STATUS_RETRYABLE_ERROR, controlv1.ApplyStatus_APPLY_STATUS_PERMANENT_ERROR:
		if result.ProgramChecksum != "" && !shared.ValidChecksum(result.ProgramChecksum) {
			return errors.New("failed result program checksum is invalid")
		}
		if result.ErrorCode == controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NONE || result.ErrorCode == controlv1.ApplyErrorCode_APPLY_ERROR_CODE_UNSPECIFIED {
			return errors.New("failed result must carry an error code")
		}
	default:
		return errors.New("apply result status is invalid")
	}
	return nil
}

func applyStatusName(value controlv1.ApplyStatus) string {
	switch value {
	case controlv1.ApplyStatus_APPLY_STATUS_APPLIED:
		return "applied"
	case controlv1.ApplyStatus_APPLY_STATUS_RETRYABLE_ERROR:
		return "retryable_error"
	case controlv1.ApplyStatus_APPLY_STATUS_PERMANENT_ERROR:
		return "permanent_error"
	default:
		return ""
	}
}

func decodeCapabilities(encoded json.RawMessage) ([]*controlv1.Capability, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	var capabilities []*controlv1.Capability
	if err := json.Unmarshal(encoded, &capabilities); err != nil {
		return nil, err
	}
	if err := shared.ValidateCapabilities(capabilities); err != nil {
		return nil, err
	}
	return capabilities, nil
}

func sanitize(value string, limit int) string {
	value = strings.ReplaceAll(value, "\x00", "")
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
