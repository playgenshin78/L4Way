package controlclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/agent"
	shared "flux.local/flux/internal/control"
	"flux.local/flux/internal/dataplane/nft"
	"flux.local/flux/internal/health"
	"flux.local/flux/internal/spec"
	"flux.local/flux/internal/usage"

	"google.golang.org/grpc"
	grpcbackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type Reconciler interface {
	Apply(context.Context, spec.DesiredState) (agent.Result, error)
}

type lifecycleReconciler interface {
	Refresh(context.Context) (agent.Result, error)
}

type driftReconciler interface {
	Audit(context.Context) (agent.Result, error)
}

type usageReconciler interface {
	CollectUsage(context.Context) ([]usage.Batch, error)
	PendingUsage() ([]usage.Batch, error)
	AckUsage(string, uint64) error
}

type StateStore interface {
	Load() (agent.StateRecord, error)
}

type Config struct {
	Target             string
	NodeID             string
	AgentVersion       string
	Credentials        credentials.TransportCredentials
	Capabilities       []*controlv1.Capability
	WireGuardPublicKey string
	ApplyTimeout       time.Duration
	PolicyInterval     time.Duration
	UsageInterval      time.Duration
	ReconcileInterval  time.Duration
	HealthInterval     time.Duration
	HeartbeatInterval  time.Duration
	HealthProbe        health.ProbeFunc
	HealthConcurrency  int
	StateDirectory     string
	SystemctlPath      string
}

type Runner struct {
	config        Config
	reconciler    Reconciler
	store         StateStore
	compiler      nft.Compiler
	logger        *slog.Logger
	now           func() time.Time
	health        *health.Engine
	healthMu      sync.Mutex
	healthLast    map[string]health.Report
	commandMu     sync.Mutex
	commandActive bool
	commandKind   controlv1.NodeCommandKind
}

func New(config Config, reconciler Reconciler, stateStore StateStore, logger *slog.Logger) (*Runner, error) {
	if strings.TrimSpace(config.Target) == "" {
		return nil, errors.New("controller target must not be empty")
	}
	if err := spec.ValidateIdentifier("node_id", config.NodeID); err != nil {
		return nil, err
	}
	if config.AgentVersion == "" || len(config.AgentVersion) > 128 {
		return nil, errors.New("agent version is invalid")
	}
	if config.Credentials == nil {
		return nil, errors.New("authenticated transport credentials must not be nil")
	}
	if reconciler == nil || stateStore == nil {
		return nil, errors.New("reconciler and state store must not be nil")
	}
	if len(config.Capabilities) == 0 {
		config.Capabilities = shared.DefaultCapabilities()
		if config.WireGuardPublicKey == "" {
			config.Capabilities = capabilitiesWithoutFabric(config.Capabilities)
		}
	}
	if err := shared.ValidateCapabilities(config.Capabilities); err != nil {
		return nil, err
	}
	if config.WireGuardPublicKey != "" {
		if err := spec.ValidateWireGuardPublicKey("wireguard_public_key", config.WireGuardPublicKey); err != nil {
			return nil, err
		}
	}
	if config.ApplyTimeout <= 0 {
		config.ApplyTimeout = 45 * time.Second
	}
	if config.PolicyInterval <= 0 {
		config.PolicyInterval = time.Second
	}
	if config.UsageInterval <= 0 {
		config.UsageInterval = 10 * time.Second
	}
	if config.ReconcileInterval <= 0 {
		config.ReconcileInterval = 15 * time.Second
	}
	if config.HealthInterval <= 0 {
		config.HealthInterval = time.Second
	}
	if config.HeartbeatInterval <= 0 {
		config.HeartbeatInterval = 25 * time.Second
	}
	if config.StateDirectory == "" {
		config.StateDirectory = "/var/lib/flux-agent"
	}
	if config.SystemctlPath == "" {
		config.SystemctlPath = "systemctl"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{
		config: config, reconciler: reconciler, store: stateStore, compiler: nft.DefaultCompiler(), logger: logger, now: time.Now,
		health: health.New(config.HealthProbe, config.HealthConcurrency), healthLast: make(map[string]health.Report),
	}, nil
}

func capabilitiesWithoutFabric(capabilities []*controlv1.Capability) []*controlv1.Capability {
	result := make([]*controlv1.Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		if capability == nil || strings.HasPrefix(capability.Name, "fabric.") || capability.Name == "nft.via-exit" {
			continue
		}
		result = append(result, capability)
	}
	return result
}

func (r *Runner) Run(ctx context.Context) error {
	connection, err := grpc.NewClient(
		r.config.Target,
		grpc.WithTransportCredentials(r.config.Credentials.Clone()),
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: grpcbackoff.Config{BaseDelay: time.Second, Multiplier: 1.6, Jitter: .2, MaxDelay: 30 * time.Second}, MinConnectTimeout: 10 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(int(spec.MaxDesiredJSONBytes+1<<20))),
	)
	if err != nil {
		return fmt.Errorf("create controller connection: %w", err)
	}
	defer connection.Close()
	client := controlv1.NewAgentControlClient(connection)
	maintenanceContext, stopMaintenance := context.WithCancel(ctx)
	defer stopMaintenance()
	localResults := make(chan agent.Result, 1)
	usageReady := make(chan struct{}, 1)
	healthReady := make(chan struct{}, 1)
	commandResults := make(chan commandCompletion, 8)
	go r.runLocalMaintenance(maintenanceContext, localResults, usageReady, healthReady)
	delay := time.Second
	for {
		startedAt := r.now()
		err := r.runSession(ctx, client, localResults, usageReady, healthReady, commandResults)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if fatalSessionError(err) {
			return err
		}
		if r.now().Sub(startedAt) >= time.Minute {
			delay = time.Second
		}
		r.logger.Warn("control stream disconnected; retaining last-known-good dataplane", "error", err, "retry_in", delay)
		jitter := time.Duration(rand.Int64N(int64(delay/3 + 1)))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay + jitter):
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func (r *Runner) runSession(
	ctx context.Context,
	client controlv1.AgentControlClient,
	localResults <-chan agent.Result,
	usageReady, healthReady <-chan struct{},
	commandResults chan commandCompletion,
) error {
	stream, err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	hello, applied, err := r.buildHello()
	if err != nil {
		return err
	}
	if err := stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_Hello{Hello: hello}}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	// Re-advertise the last durable ACK on every connection. This closes the
	// ACK-lost window without making a duplicate snapshot necessary.
	if applied != nil {
		if err := stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_ApplyResult{ApplyResult: applied}}); err != nil {
			return fmt.Errorf("resend durable ACK: %w", err)
		}
	}
	if usageSource, ok := r.reconciler.(usageReconciler); ok {
		pending, err := usageSource.PendingUsage()
		if err != nil {
			return fmt.Errorf("load durable usage outbox: %w", err)
		}
		if err := r.sendUsage(stream, pending); err != nil {
			return err
		}
	}
	if err := r.sendHealth(stream, r.pendingHealth()); err != nil {
		return err
	}
	incoming := make(chan controllerReceive, 1)
	go receiveController(stream, incoming)
	heartbeat := time.NewTicker(r.config.HeartbeatInterval)
	defer heartbeat.Stop()
	commandAcks := make(chan *controlv1.NodeCommandAck, 8)
	awaitingCommandACK := make(map[string]commandCompletion)
	defer func() {
		for _, completion := range awaitingCommandACK {
			// The result may have reached Controller while its ACK was lost.
			// Requeue it for the next authenticated session; Controller safely
			// acknowledges duplicate late results.
			select {
			case commandResults <- completion:
			default:
				if completion.release != nil {
					completion.release()
				}
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case received := <-incoming:
			if received.err != nil {
				if errors.Is(received.err, io.EOF) {
					return errors.New("controller closed control stream")
				}
				return received.err
			}
			if err := r.handleControllerEvent(ctx, stream, received.event, commandResults, commandAcks); err != nil {
				return err
			}
			go receiveController(stream, incoming)
		case <-heartbeat.C:
			if err := r.sendHeartbeat(stream); err != nil {
				return err
			}
		case result := <-localResults:
			current, err := r.resultIsCurrent(result)
			if err != nil {
				r.logger.Error("load local reconcile result", "error", err)
				continue
			}
			if !current {
				continue
			}
			applyResult := &controlv1.ApplyResult{NodeId: r.config.NodeID, Generation: result.Generation, DesiredChecksum: result.Checksum, ProgramChecksum: result.ProgramChecksum, Status: controlv1.ApplyStatus_APPLY_STATUS_APPLIED, ErrorCode: controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NONE, ObservedAtUnix: r.now().Unix()}
			if err := stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_ApplyResult{ApplyResult: applyResult}}); err != nil {
				return fmt.Errorf("send local reconcile result: %w", err)
			}
		case <-usageReady:
			if usageSource, ok := r.reconciler.(usageReconciler); ok {
				pending, err := usageSource.PendingUsage()
				if err != nil {
					r.logger.Error("load collected usage", "error", err)
					continue
				}
				if err := r.sendUsage(stream, pending); err != nil {
					return err
				}
			}
		case <-healthReady:
			if err := r.sendHealth(stream, r.pendingHealth()); err != nil {
				return err
			}
		case completion := <-commandResults:
			sendErr := stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_CommandResult{CommandResult: completion.result}})
			if sendErr != nil {
				if completion.release != nil {
					completion.release()
				}
				return fmt.Errorf("send node command result: %w", sendErr)
			}
			awaitingCommandACK[completion.result.RequestId] = completion
		case ack := <-commandAcks:
			if ack == nil || ack.RequestId == "" {
				return errors.New("controller command acknowledgement is invalid")
			}
			completion, exists := awaitingCommandACK[ack.RequestId]
			if !exists || completion.result.Kind != ack.Kind {
				return errors.New("controller command acknowledgement does not match a pending result")
			}
			delete(awaitingCommandACK, ack.RequestId)
			if completion.finalize != nil {
				completion.finalize()
			}
			if completion.release != nil {
				completion.release()
			}
		}
	}
}

func (r *Runner) runLocalMaintenance(ctx context.Context, localResults chan agent.Result, usageReady, healthReady chan<- struct{}) {
	policyTicker := time.NewTicker(r.config.PolicyInterval)
	usageTicker := time.NewTicker(r.config.UsageInterval)
	reconcileTicker := time.NewTicker(r.config.ReconcileInterval)
	healthTicker := time.NewTicker(r.config.HealthInterval)
	defer policyTicker.Stop()
	defer usageTicker.Stop()
	defer reconcileTicker.Stop()
	defer healthTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-policyTicker.C:
			if r.commandInProgress() {
				continue
			}
			local, ok := r.reconciler.(lifecycleReconciler)
			if !ok {
				continue
			}
			operationContext, cancel := context.WithTimeout(ctx, r.config.ApplyTimeout)
			result, err := local.Refresh(operationContext)
			cancel()
			if err != nil {
				r.logger.Error("local lifecycle reconcile failed; last-known-good retained", "error", err)
				continue
			}
			if result.Changed {
				r.logger.Info("local lifecycle transition applied", "generation", result.Generation, "program_checksum", result.ProgramChecksum)
				signalLocalResult(localResults, result)
			}
		case <-reconcileTicker.C:
			if r.commandInProgress() {
				continue
			}
			local, ok := r.reconciler.(driftReconciler)
			if !ok {
				continue
			}
			operationContext, cancel := context.WithTimeout(ctx, r.config.ApplyTimeout)
			result, err := local.Audit(operationContext)
			cancel()
			if err != nil {
				r.logger.Error("offline-capable dataplane audit failed; last-known-good retained", "error", err)
				continue
			}
			if result.Changed {
				r.logger.Warn("dataplane drift repaired", "generation", result.Generation, "program_checksum", result.ProgramChecksum, "fabric_checksum", result.FabricChecksum)
				signalLocalResult(localResults, result)
			}
		case <-usageTicker.C:
			if r.commandInProgress() {
				continue
			}
			local, ok := r.reconciler.(usageReconciler)
			if !ok {
				continue
			}
			operationContext, cancel := context.WithTimeout(ctx, r.config.ApplyTimeout)
			pending, err := local.CollectUsage(operationContext)
			cancel()
			if err != nil {
				r.logger.Error("offline-capable usage collection failed", "error", err)
				continue
			}
			if len(pending) != 0 {
				select {
				case usageReady <- struct{}{}:
				default:
				}
			}
		case <-healthTicker.C:
			if r.commandInProgress() {
				continue
			}
			record, err := r.store.Load()
			if err != nil {
				r.logger.Error("load desired state for health probes", "error", err)
				continue
			}
			if record.Applied == nil {
				continue
			}
			reports := r.health.RunDue(ctx, record.Applied.Desired, r.now().UTC())
			r.replaceHealth(record.Applied.Desired, reports)
			if len(reports) != 0 {
				select {
				case healthReady <- struct{}{}:
				default:
				}
			}
		}
	}
}

func (r *Runner) commandInProgress() bool {
	r.commandMu.Lock()
	defer r.commandMu.Unlock()
	return r.commandActive
}

func (r *Runner) commandKindInProgress(kind controlv1.NodeCommandKind) bool {
	r.commandMu.Lock()
	defer r.commandMu.Unlock()
	return r.commandActive && r.commandKind == kind
}

func signalLocalResult(target chan agent.Result, result agent.Result) {
	select {
	case target <- result:
	default:
		select {
		case <-target:
		default:
		}
		select {
		case target <- result:
		default:
		}
	}
}

func (r *Runner) resultIsCurrent(result agent.Result) (bool, error) {
	record, err := r.store.Load()
	if err != nil {
		return false, err
	}
	if record.Applied == nil {
		return false, nil
	}
	return record.Applied.Desired.Generation == result.Generation &&
		record.Applied.Checksum == result.Checksum &&
		record.Applied.ProgramChecksum == result.ProgramChecksum, nil
}

type controllerReceive struct {
	event *controlv1.ControllerEvent
	err   error
}

func receiveController(stream controlv1.AgentControl_ConnectClient, target chan<- controllerReceive) {
	event, err := stream.Recv()
	target <- controllerReceive{event: event, err: err}
}

func (r *Runner) handleControllerEvent(ctx context.Context, stream controlv1.AgentControl_ConnectClient, event *controlv1.ControllerEvent, commandResults chan<- commandCompletion, commandAcks chan<- *controlv1.NodeCommandAck) error {
	if event == nil {
		return errors.New("controller sent an empty event")
	}
	switch payload := event.Payload.(type) {
	case *controlv1.ControllerEvent_Snapshot:
		if r.commandKindInProgress(controlv1.NodeCommandKind_NODE_COMMAND_KIND_AGENT_UNINSTALL) {
			result := &controlv1.ApplyResult{
				NodeId: r.config.NodeID, Status: controlv1.ApplyStatus_APPLY_STATUS_RETRYABLE_ERROR,
				ErrorCode:      controlv1.ApplyErrorCode_APPLY_ERROR_CODE_INTERNAL,
				ErrorMessage:   "Agent is completing an uninstall and cannot apply another snapshot",
				ObservedAtUnix: r.now().Unix(),
			}
			if payload.Snapshot != nil {
				result.Generation = payload.Snapshot.Generation
				result.DesiredChecksum = payload.Snapshot.DesiredChecksum
			}
			if err := stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_ApplyResult{ApplyResult: result}}); err != nil {
				return fmt.Errorf("defer snapshot during uninstall: %w", err)
			}
			return nil
		}
		result := r.applySnapshot(ctx, payload.Snapshot)
		if err := stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_ApplyResult{ApplyResult: result}}); err != nil {
			return fmt.Errorf("send apply result: %w", err)
		}
		return nil
	case *controlv1.ControllerEvent_Ping:
		return r.sendHeartbeat(stream)
	case *controlv1.ControllerEvent_Disconnect:
		if payload.Disconnect == nil {
			return errors.New("controller disconnect payload is empty")
		}
		code := codes.Unavailable
		if !payload.Disconnect.Retryable {
			code = codes.FailedPrecondition
		}
		return status.Error(code, "controller requested disconnect: "+payload.Disconnect.Reason)
	case *controlv1.ControllerEvent_UsageAck:
		if payload.UsageAck == nil || !shared.ValidChecksum(payload.UsageAck.CounterEpoch) || payload.UsageAck.Sequence == 0 {
			return errors.New("controller usage ACK is invalid")
		}
		if usageSource, ok := r.reconciler.(usageReconciler); ok {
			if err := usageSource.AckUsage(payload.UsageAck.CounterEpoch, payload.UsageAck.Sequence); err != nil {
				return fmt.Errorf("commit usage ACK: %w", err)
			}
		}
		return nil
	case *controlv1.ControllerEvent_Command:
		return r.startCommand(ctx, payload.Command, commandResults)
	case *controlv1.ControllerEvent_CommandAck:
		if payload.CommandAck == nil || payload.CommandAck.RequestId == "" || len(payload.CommandAck.RequestId) > 128 || payload.CommandAck.Kind == controlv1.NodeCommandKind_NODE_COMMAND_KIND_UNSPECIFIED {
			return errors.New("controller command acknowledgement is invalid")
		}
		select {
		case commandAcks <- payload.CommandAck:
			return nil
		default:
			return errors.New("controller sent too many command acknowledgements")
		}
	default:
		return errors.New("controller event payload is required")
	}
}

func (r *Runner) applySnapshot(parent context.Context, snapshot *controlv1.DesiredSnapshot) *controlv1.ApplyResult {
	result := &controlv1.ApplyResult{
		NodeId: r.config.NodeID, Status: controlv1.ApplyStatus_APPLY_STATUS_PERMANENT_ERROR,
		ErrorCode:      controlv1.ApplyErrorCode_APPLY_ERROR_CODE_INVALID_SNAPSHOT,
		ObservedAtUnix: r.now().Unix(),
	}
	if snapshot == nil {
		result.ErrorMessage = "snapshot is empty"
		return result
	}
	result.Generation = snapshot.Generation
	result.DesiredChecksum = snapshot.DesiredChecksum
	if snapshot.ProtocolVersion != shared.ProtocolVersion || !spec.SupportedSchemaVersion(snapshot.SchemaVersion) || snapshot.NodeId != r.config.NodeID || snapshot.Generation == 0 {
		result.ErrorMessage = "snapshot envelope version, identity, or generation is invalid"
		return result
	}
	if !shared.ValidChecksum(snapshot.DesiredChecksum) {
		result.ErrorCode = controlv1.ApplyErrorCode_APPLY_ERROR_CODE_CHECKSUM_MISMATCH
		result.ErrorMessage = "snapshot checksum format is invalid"
		return result
	}
	if err := shared.ValidateCapabilities(snapshot.RequiredCapabilities); err != nil {
		result.ErrorMessage = truncate(err.Error(), 2048)
		return result
	}
	if missing := shared.MissingCapabilities(r.config.Capabilities, snapshot.RequiredCapabilities); len(missing) != 0 {
		result.ErrorCode = controlv1.ApplyErrorCode_APPLY_ERROR_CODE_UNSUPPORTED_CAPABILITY
		result.ErrorMessage = "missing capabilities: " + strings.Join(missing, ",")
		return result
	}
	desired, err := spec.DecodeDesiredJSON(snapshot.DesiredStateJson)
	if err != nil {
		result.ErrorMessage = truncate(err.Error(), 2048)
		return result
	}
	if desired.NodeID != snapshot.NodeId || desired.Generation != snapshot.Generation || desired.SchemaVersion != snapshot.SchemaVersion {
		result.ErrorMessage = "snapshot envelope does not match desired state"
		return result
	}
	checksum, err := desired.Checksum()
	if err != nil || checksum != snapshot.DesiredChecksum {
		result.ErrorCode = controlv1.ApplyErrorCode_APPLY_ERROR_CODE_CHECKSUM_MISMATCH
		result.ErrorMessage = "desired state checksum mismatch"
		return result
	}
	ctx, cancel := context.WithTimeout(parent, r.config.ApplyTimeout)
	defer cancel()
	applyResult, err := r.reconciler.Apply(ctx, desired)
	if err != nil {
		result.ProgramChecksum = applyResult.ProgramChecksum
		result.Status, result.ErrorCode = classifyApplyError(err)
		result.ErrorMessage = truncate(err.Error(), 2048)
		return result
	}
	result.ProgramChecksum = applyResult.ProgramChecksum
	if result.ProgramChecksum == "" {
		result.ProgramChecksum = r.compiler.ProgramChecksumAt(desired, checksum, r.now().UTC())
	}
	result.Status = controlv1.ApplyStatus_APPLY_STATUS_APPLIED
	result.ErrorCode = controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NONE
	result.ErrorMessage = ""
	result.ObservedAtUnix = r.now().Unix()
	return result
}

func (r *Runner) buildHello() (*controlv1.AgentHello, *controlv1.ApplyResult, error) {
	record, err := r.store.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("load durable agent state: %w", err)
	}
	nonce, err := shared.SessionNonce()
	if err != nil {
		return nil, nil, err
	}
	hello := &controlv1.AgentHello{
		ProtocolVersion: shared.ProtocolVersion, NodeId: r.config.NodeID, AgentVersion: r.config.AgentVersion,
		SupportedSchemaVersions: spec.SupportedSchemaVersions(), Capabilities: r.config.Capabilities, SessionNonce: nonce,
		WireguardPublicKey: r.config.WireGuardPublicKey,
	}
	var applied *controlv1.ApplyResult
	if record.Applied != nil {
		if record.Applied.Desired.NodeID != r.config.NodeID {
			return nil, nil, fmt.Errorf("durable state belongs to node %s", record.Applied.Desired.NodeID)
		}
		hello.AppliedGeneration = record.Applied.Desired.Generation
		hello.AppliedDesiredChecksum = record.Applied.Checksum
		hello.AppliedProgramChecksum = record.Applied.ProgramChecksum
		if hello.AppliedProgramChecksum == "" {
			hello.AppliedProgramChecksum = r.compiler.ProgramChecksumAt(record.Applied.Desired, record.Applied.Checksum, r.now().UTC())
		}
		applied = &controlv1.ApplyResult{
			NodeId: r.config.NodeID, Generation: hello.AppliedGeneration,
			DesiredChecksum: hello.AppliedDesiredChecksum, ProgramChecksum: hello.AppliedProgramChecksum,
			Status:    controlv1.ApplyStatus_APPLY_STATUS_APPLIED,
			ErrorCode: controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NONE, ObservedAtUnix: r.now().Unix(),
		}
	}
	if record.Pending != nil {
		hello.PendingGeneration = record.Pending.Desired.Generation
		hello.PendingDesiredChecksum = record.Pending.Checksum
	}
	return hello, applied, nil
}

func (r *Runner) sendUsage(stream controlv1.AgentControl_ConnectClient, batches []usage.Batch) error {
	for _, batch := range batches {
		deltas := make([]*controlv1.UsageDelta, 0, len(batch.Deltas))
		for _, delta := range batch.Deltas {
			direction := controlv1.UsageDirection_USAGE_DIRECTION_UPLOAD
			if delta.Direction == spec.DirectionDownload {
				direction = controlv1.UsageDirection_USAGE_DIRECTION_DOWNLOAD
			}
			deltas = append(deltas, &controlv1.UsageDelta{ForwardId: delta.ForwardID, Protocol: string(delta.Protocol), Direction: direction, ResourceVersion: delta.ResourceVersion, Packets: delta.Packets, Bytes: delta.Bytes, Reset_: delta.Reset})
		}
		message := &controlv1.UsageBatch{NodeId: batch.NodeID, CounterEpoch: batch.Epoch, Sequence: batch.Sequence, Generation: batch.Generation, ObservedAtUnix: batch.ObservedAt.Unix(), Deltas: deltas}
		if err := stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_UsageBatch{UsageBatch: message}}); err != nil {
			return fmt.Errorf("send usage batch %d: %w", batch.Sequence, err)
		}
	}
	return nil
}

func (r *Runner) sendHeartbeat(stream controlv1.AgentControl_ConnectClient) error {
	event := &controlv1.AgentEvent{Payload: &controlv1.AgentEvent_Heartbeat{Heartbeat: &controlv1.AgentHeartbeat{NodeId: r.config.NodeID, ObservedAtUnix: r.now().Unix()}}}
	if err := stream.Send(event); err != nil {
		return fmt.Errorf("send heartbeat: %w", err)
	}
	return nil
}

func (r *Runner) replaceHealth(desired spec.DesiredState, reports []health.Report) {
	active := make(map[string]struct{}, len(desired.HealthChecks))
	for _, check := range desired.HealthChecks {
		active[check.PoolID+"\x00"+check.BackendID] = struct{}{}
	}
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	for key := range r.healthLast {
		if _, exists := active[key]; !exists {
			delete(r.healthLast, key)
		}
	}
	for _, report := range reports {
		r.healthLast[report.PoolID+"\x00"+report.BackendID] = report
	}
}

func (r *Runner) pendingHealth() []health.Report {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	reports := make([]health.Report, 0, len(r.healthLast))
	now := r.now().UTC()
	for key, report := range r.healthLast {
		age := now.Sub(report.ObservedAt)
		if report.ObservedAt.IsZero() || age > 5*time.Minute || age < -5*time.Minute {
			delete(r.healthLast, key)
			continue
		}
		reports = append(reports, report)
	}
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].PoolID == reports[j].PoolID {
			return reports[i].BackendID < reports[j].BackendID
		}
		return reports[i].PoolID < reports[j].PoolID
	})
	return reports
}

func (r *Runner) sendHealth(stream controlv1.AgentControl_ConnectClient, reports []health.Report) error {
	for _, report := range reports {
		status := controlv1.BackendHealthStatus_BACKEND_HEALTH_STATUS_UNKNOWN
		switch report.Status {
		case health.StatusHealthy:
			status = controlv1.BackendHealthStatus_BACKEND_HEALTH_STATUS_HEALTHY
		case health.StatusUnhealthy:
			status = controlv1.BackendHealthStatus_BACKEND_HEALTH_STATUS_UNHEALTHY
		}
		milliseconds := report.Latency.Milliseconds()
		if milliseconds < 0 {
			milliseconds = 0
		}
		if milliseconds > math.MaxUint32 {
			milliseconds = math.MaxUint32
		}
		message := &controlv1.BackendHealthReport{
			NodeId: report.NodeID, Generation: report.Generation, PoolId: report.PoolID, BackendId: report.BackendID,
			ResourceVersion: report.ResourceVersion, Status: status, LatencyMilliseconds: uint32(milliseconds),
			ErrorMessage: truncate(report.Error, 512), ObservedAtUnix: report.ObservedAt.Unix(),
		}
		if err := stream.Send(&controlv1.AgentEvent{Payload: &controlv1.AgentEvent_BackendHealth{BackendHealth: message}}); err != nil {
			return fmt.Errorf("send backend health %s/%s: %w", report.PoolID, report.BackendID, err)
		}
	}
	return nil
}

func classifyApplyError(err error) (controlv1.ApplyStatus, controlv1.ApplyErrorCode) {
	permanent := controlv1.ApplyStatus_APPLY_STATUS_PERMANENT_ERROR
	retryable := controlv1.ApplyStatus_APPLY_STATUS_RETRYABLE_ERROR
	var validation *spec.ValidationError
	switch {
	case errors.As(err, &validation):
		return permanent, controlv1.ApplyErrorCode_APPLY_ERROR_CODE_INVALID_SNAPSHOT
	case errors.Is(err, nft.ErrUnsupported):
		return permanent, controlv1.ApplyErrorCode_APPLY_ERROR_CODE_UNSUPPORTED_CAPABILITY
	case errors.Is(err, agent.ErrStaleGeneration):
		return permanent, controlv1.ApplyErrorCode_APPLY_ERROR_CODE_STALE_GENERATION
	case errors.Is(err, agent.ErrGenerationConflict):
		return permanent, controlv1.ApplyErrorCode_APPLY_ERROR_CODE_GENERATION_CONFLICT
	case errors.Is(err, agent.ErrNodeIdentity):
		return permanent, controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NODE_IDENTITY
	case errors.Is(err, agent.ErrForeignTable), errors.Is(err, agent.ErrKernelAhead):
		return permanent, controlv1.ApplyErrorCode_APPLY_ERROR_CODE_DATAPLANE_CONFLICT
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return retryable, controlv1.ApplyErrorCode_APPLY_ERROR_CODE_APPLY_FAILED
	default:
		return retryable, controlv1.ApplyErrorCode_APPLY_ERROR_CODE_INTERNAL
	}
}

func fatalSessionError(err error) bool {
	if err == nil {
		return false
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.Unauthenticated, codes.PermissionDenied, codes.FailedPrecondition, codes.DataLoss:
		return true
	default:
		return false
	}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
