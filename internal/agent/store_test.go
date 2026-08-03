package agent

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"flux.local/flux/internal/spec"
)

func agentState(generation uint64) spec.DesiredState {
	return spec.DesiredState{
		SchemaVersion: spec.CurrentSchemaVersion,
		NodeID:        "node-a",
		Generation:    generation,
		Forwards: []spec.ForwardSpec{
			{
				ID:              "forward-1",
				UserID:          "user-1",
				Protocols:       []spec.Protocol{spec.ProtocolTCP},
				IngressNodeID:   "node-a",
				Listen:          spec.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 8080},
				Target:          spec.Endpoint{Address: netip.MustParseAddr("198.51.100.2"), Port: 80},
				PathMode:        spec.PathDirect,
				SNAT:            spec.SNATSpec{Mode: spec.SNATMasquerade},
				Lifecycle:       spec.LifecycleActive,
				ResourceVersion: generation,
			},
		},
	}
}

func snapshotFor(t *testing.T, generation uint64) *Snapshot {
	t.Helper()
	desired := agentState(generation)
	checksum, err := desired.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	return &Snapshot{Desired: desired.Canonical(), Checksum: checksum, PreparedAt: time.Unix(int64(generation), 0).UTC()}
}

func TestFileStoreRoundTripAndReplace(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	record := EmptyStateRecord()
	record.Applied = snapshotFor(t, 1)
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Applied == nil || loaded.Applied.Checksum != record.Applied.Checksum {
		t.Fatalf("Load() = %+v", loaded)
	}

	record.Pending = snapshotFor(t, 2)
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Pending == nil || loaded.Pending.Desired.Generation != 2 {
		t.Fatalf("Load() after replace = %+v", loaded)
	}
}

func TestFileStoreRejectsUnknownOrCorruptState(t *testing.T) {
	directory := t.TempDir()
	store, _ := NewFileStore(directory)
	if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte(`{"version":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("Load() accepted an unknown field")
	}

	record := EmptyStateRecord()
	record.Applied = snapshotFor(t, 1)
	record.Applied.Checksum = "wrong"
	if err := store.Save(record); err == nil {
		t.Fatal("Save() accepted a corrupt checksum")
	}
}

func TestStateRecordRejectsNodeIdentityChange(t *testing.T) {
	record := EmptyStateRecord()
	record.Applied = snapshotFor(t, 1)
	record.Pending = snapshotFor(t, 2)
	record.Pending.Desired.NodeID = "node-b"
	checksum, err := record.Pending.Desired.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	record.Pending.Checksum = checksum
	if err := record.Validate(); err == nil {
		t.Fatal("Validate() accepted a node identity change")
	}
}
