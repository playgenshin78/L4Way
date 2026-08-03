package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	dpfabric "flux.local/flux/internal/dataplane/fabric"
	"flux.local/flux/internal/dataplane/nft"
	dptc "flux.local/flux/internal/dataplane/tc"
	"flux.local/flux/internal/spec"
)

type memoryStore struct {
	record    StateRecord
	saveCount int
	saveErr   error
}

func newMemoryStore() *memoryStore {
	return &memoryStore{record: EmptyStateRecord()}
}

func (s *memoryStore) Load() (StateRecord, error) {
	return cloneRecord(s.record), nil
}

func (s *memoryStore) Save(record StateRecord) error {
	s.saveCount++
	if s.saveErr != nil {
		return s.saveErr
	}
	s.record = cloneRecord(record)
	return nil
}

func cloneRecord(record StateRecord) StateRecord {
	encoded, _ := json.Marshal(record)
	var result StateRecord
	_ = json.Unmarshal(encoded, &result)
	return result
}

type fakeBackend struct {
	installed  nft.InstalledState
	checkErr   error
	applyErr   error
	checkCount int
	applyCount int
	events     *[]string
}

type meteredBackend struct {
	*fakeBackend
	counters []nft.RawCounter
}

func (b *meteredBackend) ReadCounters(context.Context) ([]nft.RawCounter, error) {
	return append([]nft.RawCounter(nil), b.counters...), nil
}

type fakeCleaner struct {
	calls int
	seen  []string
}

func (c *fakeCleaner) Delete(_ context.Context, _ string, forwards []spec.ForwardSpec) (uint, error) {
	c.calls++
	for _, forward := range forwards {
		c.seen = append(c.seen, forward.ID)
	}
	return uint(len(forwards)), nil
}

var metadataPattern = regexp.MustCompile(`(?s)counter flux_generation_([0-9]+).*counter flux_desired_([0-9a-f]{64}).*counter flux_program_([0-9a-f]{64})`)

func (b *fakeBackend) Inspect(context.Context) (nft.InstalledState, error) {
	return b.installed, nil
}

func (b *fakeBackend) Check(context.Context, string) error {
	b.checkCount++
	if b.events != nil {
		*b.events = append(*b.events, "nft-check")
	}
	return b.checkErr
}

func (b *fakeBackend) Apply(_ context.Context, script string) error {
	b.applyCount++
	if b.events != nil {
		*b.events = append(*b.events, "nft-apply")
	}
	if b.applyErr != nil {
		return b.applyErr
	}
	if script == "delete table inet flux\n" {
		b.installed = nft.InstalledState{}
		return nil
	}
	matches := metadataPattern.FindStringSubmatch(script)
	if len(matches) != 4 {
		return errors.New("test backend could not find metadata")
	}
	generation, _ := strconv.ParseUint(matches[1], 10, 64)
	b.installed = nft.InstalledState{
		Exists:          true,
		Managed:         true,
		Generation:      generation,
		DesiredChecksum: matches[2],
		ProgramChecksum: matches[3],
	}
	return nil
}

type fakeFabricBackend struct {
	appliedChecksum string
	events          *[]string
	failPrepare     int
}

func (b *fakeFabricBackend) event(value string) {
	if b.events != nil {
		*b.events = append(*b.events, value)
	}
}

func (b *fakeFabricBackend) Check(context.Context, dpfabric.Program, dpfabric.Program) error {
	b.event("fabric-check")
	return nil
}

func (b *fakeFabricBackend) Prepare(_ context.Context, target dpfabric.Program) error {
	b.event("fabric-prepare")
	if b.failPrepare > 0 {
		b.failPrepare--
		return errors.New("injected fabric prepare failure")
	}
	b.appliedChecksum = target.Checksum
	return nil
}

func (b *fakeFabricBackend) Cleanup(context.Context, dpfabric.Program, dpfabric.Program) error {
	b.event("fabric-cleanup")
	return nil
}

func (b *fakeFabricBackend) Verify(_ context.Context, target dpfabric.Program) error {
	b.event("fabric-verify")
	if b.appliedChecksum != target.Checksum {
		return errors.New("fabric drift")
	}
	return nil
}

type fakeTrafficBackend struct {
	appliedChecksum string
	applyCount      int
	failFirst       bool
}

func (*fakeTrafficBackend) Check(context.Context, dptc.Program) error { return nil }
func (b *fakeTrafficBackend) Apply(_ context.Context, program dptc.Program) error {
	b.applyCount++
	if b.failFirst && b.applyCount == 1 {
		return errors.New("injected tc failure")
	}
	b.appliedChecksum = program.Checksum
	return nil
}
func (b *fakeTrafficBackend) Verify(_ context.Context, program dptc.Program) error {
	if b.appliedChecksum != program.Checksum {
		return errors.New("tc drift")
	}
	return nil
}

func testReconciler(t *testing.T, backend *fakeBackend, store Store) *Reconciler {
	t.Helper()
	reconciler, err := NewReconciler(nft.DefaultCompiler(), backend, store, func() time.Time {
		return time.Unix(1000, 0).UTC()
	})
	if err != nil {
		t.Fatal(err)
	}
	return reconciler
}

func TestApplyPersistsPendingThenCommits(t *testing.T) {
	store := newMemoryStore()
	backend := &fakeBackend{}
	result, err := testReconciler(t, backend, store).Apply(context.Background(), agentState(1))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || backend.checkCount != 1 || backend.applyCount != 1 || store.saveCount != 2 {
		t.Fatalf("result=%+v checks=%d applies=%d saves=%d", result, backend.checkCount, backend.applyCount, store.saveCount)
	}
	if store.record.Applied == nil || store.record.Pending != nil {
		t.Fatalf("record=%+v", store.record)
	}
}

func TestApplySameGenerationIsIdempotent(t *testing.T) {
	store := newMemoryStore()
	backend := &fakeBackend{}
	reconciler := testReconciler(t, backend, store)
	if _, err := reconciler.Apply(context.Background(), agentState(1)); err != nil {
		t.Fatal(err)
	}
	backend.checkCount = 0
	backend.applyCount = 0
	result, err := reconciler.Apply(context.Background(), agentState(1))
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || backend.checkCount != 0 || backend.applyCount != 0 {
		t.Fatalf("result=%+v checks=%d applies=%d", result, backend.checkCount, backend.applyCount)
	}
}

func TestPurgeRemovesKernelStateWithoutChangingDurableGeneration(t *testing.T) {
	store := newMemoryStore()
	backend := &fakeBackend{}
	reconciler := testReconciler(t, backend, store)
	if _, err := reconciler.Apply(context.Background(), agentState(1)); err != nil {
		t.Fatal(err)
	}
	clean := agentState(2)
	clean.Forwards = []spec.ForwardSpec{}
	if _, err := reconciler.Apply(context.Background(), clean); err != nil {
		t.Fatal(err)
	}
	appliedBefore := cloneRecord(store.record)
	savesBefore := store.saveCount
	if err := reconciler.Purge(context.Background(), "node-a"); err != nil {
		t.Fatal(err)
	}
	if backend.installed.Exists {
		t.Fatalf("nft state remains installed: %+v", backend.installed)
	}
	if store.saveCount != savesBefore || store.record.Applied == nil || appliedBefore.Applied == nil || store.record.Applied.Desired.Generation != appliedBefore.Applied.Desired.Generation || store.record.Applied.Checksum != appliedBefore.Applied.Checksum {
		t.Fatalf("purge changed durable state: before=%+v after=%+v saves=%d/%d", appliedBefore, store.record, savesBefore, store.saveCount)
	}
}

func TestPurgeRefusesAppliedForwards(t *testing.T) {
	store := newMemoryStore()
	backend := &fakeBackend{}
	reconciler := testReconciler(t, backend, store)
	if _, err := reconciler.Apply(context.Background(), agentState(1)); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Purge(context.Background(), "node-a"); err == nil || !strings.Contains(err.Error(), "forwards are still applied") {
		t.Fatalf("Purge() error = %v", err)
	}
	if !backend.installed.Exists {
		t.Fatal("Purge removed the dataplane despite an applied forward")
	}
}

func TestApplyRejectsStaleAndConflictingGeneration(t *testing.T) {
	store := newMemoryStore()
	store.record.Applied = snapshotFor(t, 2)
	backend := &fakeBackend{installed: nft.InstalledState{
		Exists:          true,
		Managed:         true,
		Generation:      2,
		DesiredChecksum: store.record.Applied.Checksum,
		ProgramChecksum: nft.DefaultCompiler().ProgramChecksum(store.record.Applied.Checksum),
	}}
	reconciler := testReconciler(t, backend, store)
	if _, err := reconciler.Apply(context.Background(), agentState(1)); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale Apply() error = %v", err)
	}
	conflict := agentState(2)
	conflict.Forwards[0].Target.Port = 81
	if _, err := reconciler.Apply(context.Background(), conflict); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("conflicting Apply() error = %v", err)
	}
}

func TestApplyRejectsNodeIdentityChange(t *testing.T) {
	store := newMemoryStore()
	store.record.Applied = snapshotFor(t, 1)
	backend := &fakeBackend{}
	desired := agentState(2)
	desired.NodeID = "node-b"
	desired.Forwards[0].IngressNodeID = "node-b"
	_, err := testReconciler(t, backend, store).Apply(context.Background(), desired)
	if !errors.Is(err, ErrNodeIdentity) {
		t.Fatalf("Apply() error = %v", err)
	}
}

func TestApplyRefusesForeignTable(t *testing.T) {
	backend := &fakeBackend{installed: nft.InstalledState{Exists: true, Managed: false}}
	_, err := testReconciler(t, backend, newMemoryStore()).Apply(context.Background(), agentState(1))
	if !errors.Is(err, ErrForeignTable) {
		t.Fatalf("Apply() error = %v", err)
	}
}

func TestApplyFailureLeavesDurablePending(t *testing.T) {
	store := newMemoryStore()
	backend := &fakeBackend{applyErr: errors.New("injected apply failure")}
	_, err := testReconciler(t, backend, store).Apply(context.Background(), agentState(1))
	if err == nil {
		t.Fatal("Apply() unexpectedly succeeded")
	}
	if store.record.Pending == nil || store.record.Applied != nil {
		t.Fatalf("record=%+v, want pending only", store.record)
	}
}

func TestApplyRepairsProgramFingerprintDrift(t *testing.T) {
	store := newMemoryStore()
	store.record.Applied = snapshotFor(t, 1)
	backend := &fakeBackend{installed: nft.InstalledState{
		Exists:          true,
		Managed:         true,
		Generation:      1,
		DesiredChecksum: store.record.Applied.Checksum,
		ProgramChecksum: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}
	result, err := testReconciler(t, backend, store).Apply(context.Background(), agentState(1))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || backend.applyCount != 1 {
		t.Fatalf("result=%+v applies=%d", result, backend.applyCount)
	}
}

func TestRecoverCommitsAlreadyInstalledPending(t *testing.T) {
	store := newMemoryStore()
	store.record.Pending = snapshotFor(t, 3)
	backend := &fakeBackend{installed: nft.InstalledState{
		Exists:          true,
		Managed:         true,
		Generation:      3,
		DesiredChecksum: store.record.Pending.Checksum,
		ProgramChecksum: nft.DefaultCompiler().ProgramChecksum(store.record.Pending.Checksum),
	}}
	result, err := testReconciler(t, backend, store).Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Recovered || result.Changed || backend.applyCount != 0 {
		t.Fatalf("result=%+v applies=%d", result, backend.applyCount)
	}
	if store.record.Applied == nil || store.record.Pending != nil {
		t.Fatalf("record=%+v", store.record)
	}
}

func TestRecoverRestoresMissingLastKnownGood(t *testing.T) {
	store := newMemoryStore()
	store.record.Applied = snapshotFor(t, 4)
	backend := &fakeBackend{}
	result, err := testReconciler(t, backend, store).Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Recovered || !result.Changed || backend.applyCount != 1 {
		t.Fatalf("result=%+v applies=%d", result, backend.applyCount)
	}
}

func TestCollectUsagePersistsOutboxUntilACK(t *testing.T) {
	store := newMemoryStore()
	backend := &meteredBackend{fakeBackend: &fakeBackend{}}
	reconciler := testReconciler(t, backend.fakeBackend, store)
	// Rebuild with the metered wrapper so the optional counter reader is visible.
	var err error
	reconciler, err = NewReconciler(nft.DefaultCompiler(), backend, store, func() time.Time { return time.Unix(1000, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	desired := agentState(1)
	if _, err := reconciler.Apply(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	checksum, _ := desired.Checksum()
	program, _ := nft.DefaultCompiler().CompileAt(desired, checksum, true, time.Unix(1000, 0).UTC())
	for i, binding := range program.Counters {
		backend.counters = append(backend.counters, nft.RawCounter{Name: binding.Name, Packets: uint64(i + 1), Bytes: uint64((i + 1) * 100)})
	}
	pending, err := reconciler.CollectUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || len(pending[0].Deltas) != 2 {
		t.Fatalf("pending usage = %+v", pending)
	}
	if err := reconciler.AckUsage(pending[0].Epoch, pending[0].Sequence); err != nil {
		t.Fatal(err)
	}
	pending, err = reconciler.PendingUsage()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after ACK = %+v, err=%v", pending, err)
	}
}

func TestForceDeleteBlocksThenCleansConntrack(t *testing.T) {
	store := newMemoryStore()
	backend := &fakeBackend{}
	cleaner := &fakeCleaner{}
	reconciler, err := NewReconciler(nft.DefaultCompiler(), backend, store, func() time.Time { return time.Unix(1000, 0).UTC() }, WithConntrackCleaner(cleaner))
	if err != nil {
		t.Fatal(err)
	}
	desired := agentState(1)
	desired.Forwards[0].Lifecycle = spec.LifecycleForceDeleting
	result, err := reconciler.Apply(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if cleaner.calls != 1 || result.ConntrackDeleted != 1 || store.record.Applied == nil || !store.record.Applied.ForceCleanupComplete {
		t.Fatalf("result=%+v cleaner=%+v state=%+v", result, cleaner, store.record)
	}
}

func TestTCFailureRollsNFTBackAndRetainsPending(t *testing.T) {
	store := newMemoryStore()
	backend := &fakeBackend{}
	traffic := &fakeTrafficBackend{failFirst: true}
	trafficCompiler := dptc.NewCompiler(dptc.Config{PublicInterface: "eth0", IFBInterface: "flux-ifb0", UploadLinkBitsPerSecond: 1_000_000_000, DownloadLinkBitsPerSecond: 1_000_000_000, AllowReplaceRoot: true})
	reconciler, err := NewReconciler(nft.DefaultCompiler(), backend, store, func() time.Time { return time.Unix(1000, 0).UTC() }, WithTrafficControl(trafficCompiler, traffic))
	if err != nil {
		t.Fatal(err)
	}
	desired := agentState(1)
	desired.Forwards[0].TrafficClassID = 2
	desired.Forwards[0].RateLimit = &spec.RateLimitSpec{IngressBitsPerSecond: 10_000_000, BurstBytes: 65536}
	_, err = reconciler.Apply(context.Background(), desired)
	if err == nil || !strings.Contains(err.Error(), "injected tc failure") {
		t.Fatalf("Apply() error = %v", err)
	}
	if backend.installed.Exists || store.record.Pending == nil || store.record.Applied != nil || traffic.applyCount != 2 {
		t.Fatalf("nft=%+v state=%+v tc applies=%d", backend.installed, store.record, traffic.applyCount)
	}
}

func agentFabricState(generation uint64) spec.DesiredState {
	vip := netip.MustParseAddr("10.253.0.10")
	return spec.DesiredState{
		SchemaVersion: spec.SchemaVersionV3, NodeID: "node-a", Generation: generation,
		ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")},
		FabricLinks: []spec.FabricLinkSpec{{
			ID: "fabric-ab", PeerNodeID: "node-b", Transport: spec.FabricWireGuard,
			Interface: "fluxwg0", LocalAddress: netip.MustParsePrefix("10.250.0.1/31"), PeerAddress: netip.MustParseAddr("10.250.0.0"),
			MTU: 1420, RoutingID: 100, ResourceVersion: 1,
			WireGuard: &spec.WireGuardPeerSpec{PeerPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", Endpoint: "203.0.113.2:51820", ListenPort: 51820},
		}},
		Forwards: []spec.ForwardSpec{{
			ID: "cross-web", UserID: "user-a", Protocols: []spec.Protocol{spec.ProtocolTCP},
			IngressNodeID: "node-a", ExitNodeID: "node-b",
			Listen:     spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 443},
			Target:     spec.Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 8443},
			ServiceVIP: &vip, FabricLinkID: "fabric-ab", PathMode: spec.PathViaExit,
			SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade}, Lifecycle: spec.LifecycleActive, ResourceVersion: generation,
		}},
	}
}

func TestViaExitRequiresConfiguredFabricBackend(t *testing.T) {
	_, err := testReconciler(t, &fakeBackend{}, newMemoryStore()).Apply(context.Background(), agentFabricState(1))
	if !errors.Is(err, ErrFabricUnavailable) {
		t.Fatalf("Apply() error = %v", err)
	}
}

func TestFabricPreparePrecedesNFTAndChecksumIsDurable(t *testing.T) {
	var events []string
	store := newMemoryStore()
	nftBackend := &fakeBackend{events: &events}
	fabricBackend := &fakeFabricBackend{events: &events}
	reconciler, err := NewReconciler(
		nft.DefaultCompiler(), nftBackend, store, func() time.Time { return time.Unix(1000, 0).UTC() },
		WithFabric(dpfabric.DefaultCompiler(), fabricBackend),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := reconciler.Apply(context.Background(), agentFabricState(1))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.FabricChecksum == "" || store.record.Applied == nil || store.record.Applied.FabricChecksum != result.FabricChecksum {
		t.Fatalf("result=%+v state=%+v", result, store.record)
	}
	wantOrder := []string{"nft-check", "fabric-check", "fabric-prepare", "nft-apply", "fabric-cleanup", "fabric-verify"}
	if strings.Join(events, ",") != strings.Join(wantOrder, ",") {
		t.Fatalf("events=%v want=%v", events, wantOrder)
	}
}

func TestFabricPrepareFailureRollsBackAndKeepsPending(t *testing.T) {
	store := newMemoryStore()
	nftBackend := &fakeBackend{}
	fabricBackend := &fakeFabricBackend{failPrepare: 1}
	reconciler, err := NewReconciler(
		nft.DefaultCompiler(), nftBackend, store, func() time.Time { return time.Unix(1000, 0).UTC() },
		WithFabric(dpfabric.DefaultCompiler(), fabricBackend),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reconciler.Apply(context.Background(), agentFabricState(1))
	if err == nil || !strings.Contains(err.Error(), "injected fabric prepare failure") {
		t.Fatalf("Apply() error = %v", err)
	}
	if store.record.Pending == nil || store.record.Applied != nil || nftBackend.installed.Exists {
		t.Fatalf("state=%+v nft=%+v", store.record, nftBackend.installed)
	}
}

func TestAuditRepairsFabricDriftWithoutControllerOrNFTRewrite(t *testing.T) {
	store := newMemoryStore()
	nftBackend := &fakeBackend{}
	fabricBackend := &fakeFabricBackend{}
	reconciler, err := NewReconciler(
		nft.DefaultCompiler(), nftBackend, store, func() time.Time { return time.Unix(1000, 0).UTC() },
		WithFabric(dpfabric.DefaultCompiler(), fabricBackend),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Apply(context.Background(), agentFabricState(1)); err != nil {
		t.Fatal(err)
	}
	nftApplies := nftBackend.applyCount
	fabricBackend.appliedChecksum = ""
	result, err := reconciler.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || nftBackend.applyCount != nftApplies || fabricBackend.appliedChecksum != result.FabricChecksum {
		t.Fatalf("result=%+v nft_applies=%d fabric=%s", result, nftBackend.applyCount, fabricBackend.appliedChecksum)
	}
}
