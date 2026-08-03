package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	dpfabric "flux.local/flux/internal/dataplane/fabric"
	"flux.local/flux/internal/dataplane/nft"
	dptc "flux.local/flux/internal/dataplane/tc"
	"flux.local/flux/internal/meter"
	"flux.local/flux/internal/spec"
	"flux.local/flux/internal/usage"
)

var (
	ErrStaleGeneration           = errors.New("desired generation is stale")
	ErrGenerationConflict        = errors.New("same generation has a different checksum")
	ErrNodeIdentity              = errors.New("desired state node identity changed")
	ErrForeignTable              = errors.New("table inet flux exists but is not managed by Flux")
	ErrKernelAhead               = errors.New("installed generation is newer than local durable state")
	ErrTrafficControlUnavailable = errors.New("rate limiting requested but tc backend is not configured")
	ErrUsageUnavailable          = errors.New("nft counter reader is not configured")
	ErrUsageOutboxFull           = errors.New("durable usage outbox is full")
	ErrFabricUnavailable         = errors.New("cross-node fabric requested but fabric backend is not configured")
)

type Backend interface {
	Inspect(context.Context) (nft.InstalledState, error)
	Check(context.Context, string) error
	Apply(context.Context, string) error
}

type CounterReader interface {
	ReadCounters(context.Context) ([]nft.RawCounter, error)
}

type TrafficBackend interface {
	Check(context.Context, dptc.Program) error
	Apply(context.Context, dptc.Program) error
	Verify(context.Context, dptc.Program) error
}

type ConntrackCleaner interface {
	Delete(context.Context, string, []spec.ForwardSpec) (uint, error)
}

type FabricBackend interface {
	Check(context.Context, dpfabric.Program, dpfabric.Program) error
	Prepare(context.Context, dpfabric.Program) error
	Cleanup(context.Context, dpfabric.Program, dpfabric.Program) error
	Verify(context.Context, dpfabric.Program) error
}

type Result struct {
	Generation       uint64 `json:"generation"`
	Checksum         string `json:"checksum"`
	ProgramChecksum  string `json:"program_checksum,omitempty"`
	TCChecksum       string `json:"tc_checksum,omitempty"`
	FabricChecksum   string `json:"fabric_checksum,omitempty"`
	Changed          bool   `json:"changed"`
	Recovered        bool   `json:"recovered,omitempty"`
	ConntrackDeleted uint64 `json:"conntrack_deleted,omitempty"`
}

type Reconciler struct {
	compiler         nft.Compiler
	backend          Backend
	store            Store
	now              func() time.Time
	tcCompiler       *dptc.Compiler
	tcBackend        TrafficBackend
	conntrackCleaner ConntrackCleaner
	fabricCompiler   *dpfabric.Compiler
	fabricBackend    FabricBackend
	mu               sync.Mutex
}

type Option func(*Reconciler) error

func WithTrafficControl(compiler dptc.Compiler, backend TrafficBackend) Option {
	return func(reconciler *Reconciler) error {
		if backend == nil {
			return errors.New("tc backend must not be nil")
		}
		reconciler.tcCompiler = &compiler
		reconciler.tcBackend = backend
		return nil
	}
}

func WithConntrackCleaner(cleaner ConntrackCleaner) Option {
	return func(reconciler *Reconciler) error {
		if cleaner == nil {
			return errors.New("conntrack cleaner must not be nil")
		}
		reconciler.conntrackCleaner = cleaner
		return nil
	}
}

func WithFabric(compiler dpfabric.Compiler, backend FabricBackend) Option {
	return func(reconciler *Reconciler) error {
		if backend == nil {
			return errors.New("fabric backend must not be nil")
		}
		reconciler.fabricCompiler = &compiler
		reconciler.fabricBackend = backend
		return nil
	}
}

func NewReconciler(compiler nft.Compiler, backend Backend, store Store, now func() time.Time, options ...Option) (*Reconciler, error) {
	if backend == nil {
		return nil, errors.New("backend must not be nil")
	}
	if store == nil {
		return nil, errors.New("store must not be nil")
	}
	if now == nil {
		now = time.Now
	}
	reconciler := &Reconciler{compiler: compiler, backend: backend, store: store, now: now}
	for _, option := range options {
		if err := option(reconciler); err != nil {
			return nil, err
		}
	}
	return reconciler, nil
}

func (r *Reconciler) Apply(ctx context.Context, desired spec.DesiredState) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applyLocked(ctx, desired)
}

func (r *Reconciler) applyLocked(ctx context.Context, desired spec.DesiredState) (Result, error) {
	if err := desired.Validate(); err != nil {
		return Result{}, err
	}
	desired = desired.Canonical()
	checksum, err := desired.Checksum()
	if err != nil {
		return Result{}, fmt.Errorf("calculate desired checksum: %w", err)
	}
	record, err := r.store.Load()
	if err != nil {
		return Result{}, err
	}
	if err := validateIncomingGeneration(record, desired.NodeID, desired.Generation, checksum); err != nil {
		return Result{}, err
	}

	target := Snapshot{Desired: desired, Checksum: checksum, PreparedAt: r.now().UTC()}
	if record.Pending != nil && record.Pending.Desired.Generation == desired.Generation && record.Pending.Checksum == checksum {
		target = *record.Pending
	} else if record.Applied != nil && record.Applied.Desired.Generation == desired.Generation && record.Applied.Checksum == checksum {
		target = *record.Applied
	}
	return r.converge(ctx, record, target, false, true)
}

func (r *Reconciler) Recover(ctx context.Context) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, err := r.store.Load()
	if err != nil {
		return Result{}, err
	}
	var target *Snapshot
	if record.Pending != nil {
		target = record.Pending
	} else {
		target = record.Applied
	}
	if target == nil {
		return Result{Recovered: true}, nil
	}
	result, err := r.converge(ctx, record, *target, true, false)
	result.Recovered = true
	return result, err
}

// Audit verifies every managed kernel subsystem and repairs drift from the
// durable pending or last-known-good snapshot. It does not require Controller
// connectivity and never invents a generation.
func (r *Reconciler) Audit(ctx context.Context) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, err := r.store.Load()
	if err != nil {
		return Result{}, err
	}
	if record.Pending != nil {
		return r.converge(ctx, record, *record.Pending, false, false)
	}
	if record.Applied != nil {
		return r.converge(ctx, record, *record.Applied, false, false)
	}
	return Result{}, nil
}

// Refresh applies only a wall-clock lifecycle transition. It is safe to run
// while Controller is offline and does not invent a new desired generation.
func (r *Reconciler) Refresh(ctx context.Context) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, err := r.store.Load()
	if err != nil {
		return Result{}, err
	}
	if record.Pending != nil {
		return r.converge(ctx, record, *record.Pending, false, false)
	}
	if record.Applied == nil {
		return Result{}, nil
	}
	now := r.now().UTC()
	expected := r.compiler.ProgramChecksumAt(record.Applied.Desired, record.Applied.Checksum, now)
	if record.Applied.ProgramChecksum == expected {
		return Result{Generation: record.Applied.Desired.Generation, Checksum: record.Applied.Checksum, ProgramChecksum: expected, TCChecksum: record.Applied.TCChecksum, FabricChecksum: record.Applied.FabricChecksum}, nil
	}
	return r.converge(ctx, record, *record.Applied, false, false)
}

// Purge removes every Flux-owned kernel resource without inventing or
// persisting a new Controller generation. It is used only during a confirmed
// Agent uninstall. Keeping the durable record unchanged means a failed
// uninstall can still restore the previous last-known-good state.
func (r *Reconciler) Purge(ctx context.Context, nodeID string) error {
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	record, err := r.store.Load()
	if err != nil {
		return err
	}
	if record.Pending != nil {
		return errors.New("cannot purge while a desired state is pending")
	}
	if record.Applied != nil && len(record.Applied.Desired.Forwards) != 0 {
		return errors.New("cannot purge while forwards are still applied")
	}
	clean := spec.DesiredState{
		SchemaVersion: spec.CurrentSchemaVersion,
		NodeID:        nodeID,
		Generation:    1,
		Forwards:      []spec.ForwardSpec{},
	}
	if record.Applied != nil {
		if record.Applied.Desired.NodeID != nodeID {
			return fmt.Errorf("%w: stored=%s requested=%s", ErrNodeIdentity, record.Applied.Desired.NodeID, nodeID)
		}
		clean.SchemaVersion = record.Applied.Desired.SchemaVersion
		clean.Generation = record.Applied.Desired.Generation
	}
	cleanChecksum, err := clean.Checksum()
	if err != nil {
		return fmt.Errorf("calculate purge checksum: %w", err)
	}

	var tcProgram dptc.Program
	if r.tcCompiler != nil {
		tcProgram, err = r.tcCompiler.Compile(clean, cleanChecksum)
		if err != nil {
			return fmt.Errorf("compile tc purge program: %w", err)
		}
		if err := r.tcBackend.Check(ctx, tcProgram); err != nil {
			return fmt.Errorf("preflight tc purge program: %w", err)
		}
	}

	var cleanFabric, previousFabric dpfabric.Program
	if r.fabricCompiler != nil {
		cleanFabric, err = r.fabricCompiler.Compile(clean, cleanChecksum)
		if err != nil {
			return fmt.Errorf("compile fabric purge program: %w", err)
		}
		if record.Applied != nil {
			previousFabric, err = r.fabricCompiler.Compile(record.Applied.Desired, record.Applied.Checksum)
			if err != nil {
				return fmt.Errorf("compile applied fabric before purge: %w", err)
			}
		}
		if err := r.fabricBackend.Check(ctx, previousFabric, cleanFabric); err != nil {
			return fmt.Errorf("preflight fabric purge program: %w", err)
		}
	}

	installed, err := r.backend.Inspect(ctx)
	if err != nil {
		return err
	}
	if installed.Exists && !installed.Managed {
		return ErrForeignTable
	}
	mutated := false
	rollback := func(cause error) error {
		if !mutated {
			return cause
		}
		if restoreErr := r.rollbackDataplane(ctx, record, clean, r.now().UTC()); restoreErr != nil {
			return errors.Join(cause, fmt.Errorf("restore last-known-good after purge failure: %w", restoreErr))
		}
		return cause
	}

	if r.fabricBackend != nil {
		if err := r.fabricBackend.Prepare(ctx, cleanFabric); err != nil {
			return fmt.Errorf("prepare empty fabric before purge: %w", err)
		}
		mutated = true
	}
	if installed.Exists {
		if err := r.backend.Apply(ctx, "delete table inet flux\n"); err != nil {
			return rollback(fmt.Errorf("remove Flux nft table: %w", err))
		}
		mutated = true
	}
	if r.tcBackend != nil {
		if err := r.tcBackend.Apply(ctx, tcProgram); err != nil {
			return rollback(fmt.Errorf("remove Flux tc state: %w", err))
		}
		mutated = true
	}
	if r.fabricBackend != nil {
		if err := r.fabricBackend.Cleanup(ctx, previousFabric, cleanFabric); err != nil {
			return rollback(fmt.Errorf("remove Flux fabric state: %w", err))
		}
	}
	verified, err := r.backend.Inspect(ctx)
	if err != nil {
		return rollback(fmt.Errorf("verify Flux nft removal: %w", err))
	}
	if verified.Exists {
		return rollback(errors.New("verify Flux nft removal: table inet flux still exists"))
	}
	if r.tcBackend != nil {
		if err := r.tcBackend.Verify(ctx, tcProgram); err != nil {
			return rollback(fmt.Errorf("verify Flux tc removal: %w", err))
		}
	}
	if r.fabricBackend != nil {
		if err := r.fabricBackend.Verify(ctx, cleanFabric); err != nil {
			return rollback(fmt.Errorf("verify Flux fabric removal: %w", err))
		}
	}
	return nil
}

func validateIncomingGeneration(record StateRecord, nodeID string, generation uint64, checksum string) error {
	var expectedNodeID string
	if record.Applied != nil {
		expectedNodeID = record.Applied.Desired.NodeID
	} else if record.Pending != nil {
		expectedNodeID = record.Pending.Desired.NodeID
	}
	if expectedNodeID != "" && nodeID != expectedNodeID {
		return fmt.Errorf("%w: stored=%s received=%s", ErrNodeIdentity, expectedNodeID, nodeID)
	}
	if record.Applied != nil {
		switch {
		case generation < record.Applied.Desired.Generation:
			return fmt.Errorf("%w: received=%d applied=%d", ErrStaleGeneration, generation, record.Applied.Desired.Generation)
		case generation == record.Applied.Desired.Generation && checksum != record.Applied.Checksum:
			return fmt.Errorf("%w: generation=%d", ErrGenerationConflict, generation)
		}
	}
	if record.Pending != nil {
		switch {
		case generation < record.Pending.Desired.Generation:
			return fmt.Errorf("%w: received=%d pending=%d", ErrStaleGeneration, generation, record.Pending.Desired.Generation)
		case generation == record.Pending.Desired.Generation && checksum != record.Pending.Checksum:
			return fmt.Errorf("%w: generation=%d is pending", ErrGenerationConflict, generation)
		}
	}
	return nil
}

func (r *Reconciler) converge(ctx context.Context, record StateRecord, target Snapshot, recovering, enforceKernelOrder bool) (Result, error) {
	now := r.now().UTC()
	program, err := r.compiler.CompileAt(target.Desired, target.Checksum, false, now)
	if err != nil {
		return Result{}, err
	}
	target.ProgramChecksum = program.ProgramChecksum
	var tcProgram dptc.Program
	if r.tcCompiler != nil {
		tcProgram, err = r.tcCompiler.Compile(target.Desired, target.Checksum)
		if err != nil {
			return Result{}, err
		}
		target.TCChecksum = tcProgram.Checksum
	} else if desiredHasRateLimit(target.Desired) {
		return Result{}, ErrTrafficControlUnavailable
	}
	var fabricProgram, previousFabric dpfabric.Program
	fabricRequired := desiredHasFabric(target.Desired) || record.Applied != nil && desiredHasFabric(record.Applied.Desired)
	if r.fabricCompiler != nil {
		fabricProgram, err = r.fabricCompiler.Compile(target.Desired, target.Checksum)
		if err != nil {
			return Result{}, err
		}
		target.FabricChecksum = fabricProgram.Checksum
		if record.Applied != nil {
			previousFabric, err = r.fabricCompiler.Compile(record.Applied.Desired, record.Applied.Checksum)
			if err != nil {
				return Result{}, fmt.Errorf("compile applied fabric program: %w", err)
			}
		}
	} else if fabricRequired {
		return Result{}, ErrFabricUnavailable
	}
	result := Result{Generation: target.Desired.Generation, Checksum: target.Checksum, ProgramChecksum: target.ProgramChecksum, TCChecksum: target.TCChecksum, FabricChecksum: target.FabricChecksum, Recovered: recovering}

	installed, err := r.backend.Inspect(ctx)
	if err != nil {
		return result, err
	}
	if installed.Exists && !installed.Managed {
		return result, ErrForeignTable
	}
	if installed.Managed && installed.Generation > target.Desired.Generation {
		return result, fmt.Errorf("%w: installed=%d target=%d", ErrKernelAhead, installed.Generation, target.Desired.Generation)
	}
	if enforceKernelOrder && installed.Managed && installed.Generation == target.Desired.Generation && installed.DesiredChecksum != target.Checksum {
		knownTarget := record.Applied != nil && record.Applied.Checksum == target.Checksum || record.Pending != nil && record.Pending.Checksum == target.Checksum
		if !knownTarget {
			return result, fmt.Errorf("%w: installed generation=%d", ErrGenerationConflict, installed.Generation)
		}
	}

	nftCurrent := installed.Managed && installed.Generation == target.Desired.Generation && installed.DesiredChecksum == target.Checksum && installed.ProgramChecksum == target.ProgramChecksum
	tcCurrent := true
	if r.tcBackend != nil {
		persistedCurrent := record.Applied != nil && record.Applied.Desired.Generation == target.Desired.Generation && record.Applied.TCChecksum == target.TCChecksum
		tcCurrent = persistedCurrent && r.tcBackend.Verify(ctx, tcProgram) == nil
	}
	fabricCurrent := true
	if r.fabricBackend != nil {
		persistedCurrent := record.Applied != nil && record.Applied.FabricChecksum == target.FabricChecksum
		fabricCurrent = persistedCurrent && r.fabricBackend.Verify(ctx, fabricProgram) == nil
	}
	force := explicitForceDeletes(target.Desired)
	cleanupNeeded := len(force) != 0 && !target.ForceCleanupComplete
	if nftCurrent && tcCurrent && fabricCurrent && !cleanupNeeded {
		if record.Pending != nil || record.Applied == nil || record.Applied.Checksum != target.Checksum || record.Applied.ProgramChecksum != target.ProgramChecksum || record.Applied.TCChecksum != target.TCChecksum || record.Applied.FabricChecksum != target.FabricChecksum {
			record.Applied = snapshotCopy(target)
			record.Pending = nil
			if err := r.store.Save(record); err != nil {
				return result, err
			}
		}
		return result, nil
	}

	program, err = r.compiler.CompileAt(target.Desired, target.Checksum, installed.Exists, now)
	if err != nil {
		return result, err
	}
	if !nftCurrent {
		if err := r.backend.Check(ctx, program.Script); err != nil {
			return result, err
		}
	}
	if r.tcBackend != nil && !tcCurrent {
		if err := r.tcBackend.Check(ctx, tcProgram); err != nil {
			return result, err
		}
	}
	if r.fabricBackend != nil && !fabricCurrent {
		if err := r.fabricBackend.Check(ctx, previousFabric, fabricProgram); err != nil {
			return result, err
		}
	}
	if (record.Applied == nil || record.Applied.ProgramChecksum != target.ProgramChecksum) && record.Applied != nil {
		if err := r.collectUsageLocked(ctx, &record, now); err != nil && !errors.Is(err, ErrUsageUnavailable) {
			return result, fmt.Errorf("collect counters before dataplane replacement: %w", err)
		}
	}
	record.Pending = snapshotCopy(target)
	if err := r.store.Save(record); err != nil {
		return result, err
	}
	if r.fabricBackend != nil && !fabricCurrent {
		if err := r.fabricBackend.Prepare(ctx, fabricProgram); err != nil {
			applyErr := fmt.Errorf("prepare fabric before nft commit: %w", err)
			return result, r.withRollback(ctx, record, target.Desired, now, applyErr)
		}
	}
	if !nftCurrent {
		if err := r.backend.Apply(ctx, program.Script); err != nil {
			applyErr := fmt.Errorf("apply nft program after fabric prepare: %w", err)
			return result, r.withRollback(ctx, record, target.Desired, now, applyErr)
		}
	}
	if r.tcBackend != nil && !tcCurrent {
		if err := r.tcBackend.Apply(ctx, tcProgram); err != nil {
			applyErr := fmt.Errorf("apply tc program after nft commit: %w", err)
			return result, r.withRollback(ctx, record, target.Desired, now, applyErr)
		}
	}
	if r.fabricBackend != nil && !fabricCurrent {
		if err := r.fabricBackend.Cleanup(ctx, previousFabric, fabricProgram); err != nil {
			applyErr := fmt.Errorf("cleanup superseded fabric resources: %w", err)
			return result, r.withRollback(ctx, record, target.Desired, now, applyErr)
		}
	}
	verified, err := r.backend.Inspect(ctx)
	if err != nil {
		verifyErr := fmt.Errorf("verify applied nft generation: %w", err)
		return result, r.withRollback(ctx, record, target.Desired, now, verifyErr)
	}
	if !verified.Exists || !verified.Managed || verified.Generation != target.Desired.Generation || verified.DesiredChecksum != target.Checksum || verified.ProgramChecksum != target.ProgramChecksum {
		verifyErr := fmt.Errorf("verify applied nft generation: installed=%+v", verified)
		return result, r.withRollback(ctx, record, target.Desired, now, verifyErr)
	}
	if r.tcBackend != nil {
		if err := r.tcBackend.Verify(ctx, tcProgram); err != nil {
			verifyErr := fmt.Errorf("verify applied tc program: %w", err)
			return result, r.withRollback(ctx, record, target.Desired, now, verifyErr)
		}
	}
	if r.fabricBackend != nil {
		if err := r.fabricBackend.Verify(ctx, fabricProgram); err != nil {
			verifyErr := fmt.Errorf("verify applied fabric program: %w", err)
			return result, r.withRollback(ctx, record, target.Desired, now, verifyErr)
		}
	}
	if cleanupNeeded {
		if r.conntrackCleaner == nil {
			return result, errors.New("force deletion requested but conntrack cleaner is not configured")
		}
		deleted, err := r.conntrackCleaner.Delete(ctx, target.Desired.NodeID, force)
		if err != nil {
			return result, err
		}
		result.ConntrackDeleted = uint64(deleted)
		target.ForceCleanupComplete = true
	}
	record.Applied = snapshotCopy(target)
	record.Pending = nil
	if err := r.store.Save(record); err != nil {
		return result, err
	}
	result.Changed = !nftCurrent || !tcCurrent || !fabricCurrent || cleanupNeeded
	return result, nil
}

func (r *Reconciler) withRollback(ctx context.Context, record StateRecord, target spec.DesiredState, now time.Time, applyErr error) error {
	if rollbackErr := r.rollbackDataplane(ctx, record, target, now); rollbackErr != nil {
		return errors.Join(applyErr, fmt.Errorf("rollback to last-known-good: %w", rollbackErr))
	}
	return applyErr
}

func (r *Reconciler) rollbackDataplane(ctx context.Context, record StateRecord, target spec.DesiredState, now time.Time) error {
	var rollbackErrors []error
	rollbackDesired := target
	rollbackChecksum := ""
	if record.Applied != nil {
		rollbackDesired = record.Applied.Desired
		rollbackChecksum = record.Applied.Checksum
	} else {
		rollbackDesired.Forwards = nil
		rollbackDesired.UserPolicies = nil
		rollbackDesired.FabricLinks = nil
		rollbackDesired.ServiceCIDRs = nil
		var err error
		rollbackChecksum, err = rollbackDesired.Checksum()
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("checksum empty rollback: %w", err))
		}
	}
	var targetFabric, rollbackFabric dpfabric.Program
	if r.fabricCompiler != nil && r.fabricBackend != nil && rollbackChecksum != "" {
		targetChecksum, err := target.Checksum()
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("checksum target fabric rollback: %w", err))
		} else if targetFabric, err = r.fabricCompiler.Compile(target, targetChecksum); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("compile target fabric rollback: %w", err))
		}
		if program, err := r.fabricCompiler.Compile(rollbackDesired, rollbackChecksum); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("compile applied fabric rollback: %w", err))
		} else {
			rollbackFabric = program
			if err := r.fabricBackend.Prepare(ctx, rollbackFabric); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("prepare fabric rollback: %w", err))
			}
		}
	}
	if record.Applied != nil {
		program, err := r.compiler.CompileAt(record.Applied.Desired, record.Applied.Checksum, true, now)
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("compile nft rollback: %w", err))
		} else if err := r.backend.Apply(ctx, program.Script); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("apply nft rollback: %w", err))
		}
	} else if err := r.backend.Apply(ctx, "delete table inet flux\n"); err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("remove first-generation nft table: %w", err))
	}
	if r.tcCompiler != nil && r.tcBackend != nil {
		if rollbackChecksum == "" {
			rollbackErrors = append(rollbackErrors, errors.New("tc rollback checksum is unavailable"))
		} else {
			program, err := r.tcCompiler.Compile(rollbackDesired, rollbackChecksum)
			if err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("compile tc rollback: %w", err))
			} else if err := r.tcBackend.Apply(ctx, program); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("apply tc rollback: %w", err))
			}
		}
	}
	if r.fabricCompiler != nil && r.fabricBackend != nil && rollbackChecksum != "" {
		if err := r.fabricBackend.Cleanup(ctx, targetFabric, rollbackFabric); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("cleanup fabric rollback: %w", err))
		}
		if err := r.fabricBackend.Verify(ctx, rollbackFabric); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("verify fabric rollback: %w", err))
		}
	}
	return errors.Join(rollbackErrors...)
}

func (r *Reconciler) CollectUsage(ctx context.Context) ([]usage.Batch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, err := r.store.Load()
	if err != nil {
		return nil, err
	}
	if err := r.collectUsageLocked(ctx, &record, r.now().UTC()); err != nil {
		return nil, err
	}
	return cloneUsageBatches(record.UsageOutbox), nil
}

func (r *Reconciler) collectUsageLocked(ctx context.Context, record *StateRecord, observedAt time.Time) error {
	if record.Applied == nil {
		return nil
	}
	reader, ok := r.backend.(CounterReader)
	if !ok {
		return ErrUsageUnavailable
	}
	if len(record.UsageOutbox) >= MaxUsageOutbox {
		return ErrUsageOutboxFull
	}
	program, err := r.compiler.CompileAt(record.Applied.Desired, record.Applied.Checksum, true, observedAt)
	if err != nil {
		return err
	}
	raw, err := reader.ReadCounters(ctx)
	if err != nil {
		return err
	}
	bindings := make(map[string]nft.CounterBinding, len(program.Counters))
	for _, binding := range program.Counters {
		bindings[binding.Name] = binding
	}
	if len(bindings) == 0 {
		return nil
	}
	samples := make([]meter.Sample, 0, len(raw))
	for _, sample := range raw {
		if _, exists := bindings[sample.Name]; exists {
			samples = append(samples, meter.Sample{Name: sample.Name, Packets: sample.Packets, Bytes: sample.Bytes})
		}
	}
	if len(samples) == 0 && len(bindings) != 0 {
		return errors.New("nft returned no counters for the applied program")
	}
	tracker, err := meter.NewTracker(record.Meter)
	if err != nil {
		return err
	}
	epoch := record.Applied.ProgramChecksum
	if epoch == "" {
		epoch = program.ProgramChecksum
	}
	meterBatch, err := tracker.Observe(epoch, samples)
	if err != nil {
		return err
	}
	var nonzero bool
	for _, delta := range meterBatch.Deltas {
		if delta.Packets != 0 || delta.Bytes != 0 {
			nonzero = true
			break
		}
	}
	if !nonzero {
		record.Meter = tracker.State()
		return r.store.Save(*record)
	}
	batch := usage.Batch{NodeID: record.Applied.Desired.NodeID, Epoch: meterBatch.Epoch, Sequence: meterBatch.Sequence, Generation: record.Applied.Desired.Generation, ObservedAt: observedAt}
	for _, delta := range meterBatch.Deltas {
		binding := bindings[delta.Name]
		batch.Deltas = append(batch.Deltas, usage.Delta{ForwardID: binding.ForwardID, Protocol: binding.Protocol, Direction: binding.Direction, ResourceVersion: binding.ResourceVersion, Packets: delta.Packets, Bytes: delta.Bytes, Reset: delta.Reset})
	}
	if err := batch.Validate(); err != nil {
		return err
	}
	record.Meter = tracker.State()
	record.UsageOutbox = append(record.UsageOutbox, batch)
	return r.store.Save(*record)
}

func (r *Reconciler) PendingUsage() ([]usage.Batch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, err := r.store.Load()
	if err != nil {
		return nil, err
	}
	return cloneUsageBatches(record.UsageOutbox), nil
}

func (r *Reconciler) AckUsage(epoch string, sequence uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, err := r.store.Load()
	if err != nil {
		return err
	}
	index := -1
	for i, batch := range record.UsageOutbox {
		if batch.Epoch == epoch && batch.Sequence == sequence {
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	record.UsageOutbox = append([]usage.Batch(nil), record.UsageOutbox[index+1:]...)
	return r.store.Save(record)
}

func desiredHasRateLimit(desired spec.DesiredState) bool {
	users := make(map[string]spec.UserPolicySpec, len(desired.UserPolicies))
	for _, policy := range desired.UserPolicies {
		users[policy.UserID] = policy
	}
	for _, forward := range desired.Forwards {
		if forward.IngressNodeID == desired.NodeID && (forward.RateLimit != nil || users[forward.UserID].RateLimit != nil) {
			return true
		}
	}
	return false
}

func desiredHasFabric(desired spec.DesiredState) bool {
	if len(desired.FabricLinks) != 0 {
		return true
	}
	for _, forward := range desired.Forwards {
		if forward.PathMode == spec.PathViaExit {
			return true
		}
	}
	return false
}

func explicitForceDeletes(desired spec.DesiredState) []spec.ForwardSpec {
	var result []spec.ForwardSpec
	for _, forward := range desired.Forwards {
		if forward.Lifecycle == spec.LifecycleForceDeleting {
			result = append(result, forward)
		}
	}
	return result
}

func snapshotCopy(snapshot Snapshot) *Snapshot {
	copy := snapshot
	copy.Desired = snapshot.Desired.Canonical()
	return &copy
}

func cloneUsageBatches(batches []usage.Batch) []usage.Batch {
	result := append([]usage.Batch(nil), batches...)
	for i := range result {
		result[i].Deltas = append([]usage.Delta(nil), result[i].Deltas...)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Sequence < result[j].Sequence })
	return result
}
