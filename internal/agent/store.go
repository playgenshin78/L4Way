package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"flux.local/flux/internal/meter"
	"flux.local/flux/internal/spec"
	"flux.local/flux/internal/usage"
)

const (
	stateRecordVersion = uint32(3)
	maxStateFileBytes  = int64(64 << 20)
	MaxUsageOutbox     = 10_000
)

type Snapshot struct {
	Desired              spec.DesiredState `json:"desired"`
	Checksum             string            `json:"checksum"`
	ProgramChecksum      string            `json:"program_checksum,omitempty"`
	TCChecksum           string            `json:"tc_checksum,omitempty"`
	FabricChecksum       string            `json:"fabric_checksum,omitempty"`
	ForceCleanupComplete bool              `json:"force_cleanup_complete,omitempty"`
	PreparedAt           time.Time         `json:"prepared_at"`
}

type StateRecord struct {
	Version     uint32        `json:"version"`
	Applied     *Snapshot     `json:"applied,omitempty"`
	Pending     *Snapshot     `json:"pending,omitempty"`
	Meter       meter.State   `json:"meter"`
	UsageOutbox []usage.Batch `json:"usage_outbox,omitempty"`
}

func EmptyStateRecord() StateRecord {
	return StateRecord{Version: stateRecordVersion}
}

func (r StateRecord) Validate() error {
	if r.Version < 1 || r.Version > stateRecordVersion {
		return fmt.Errorf("state record version must be between 1 and %d", stateRecordVersion)
	}
	if err := validateSnapshot("applied", r.Applied); err != nil {
		return err
	}
	if err := validateSnapshot("pending", r.Pending); err != nil {
		return err
	}
	if r.Applied != nil && r.Pending != nil && r.Pending.Desired.Generation < r.Applied.Desired.Generation {
		return errors.New("pending generation is older than applied generation")
	}
	if r.Applied != nil && r.Pending != nil {
		if r.Pending.Desired.NodeID != r.Applied.Desired.NodeID {
			return errors.New("pending and applied snapshots have different node IDs")
		}
		if r.Pending.Desired.Generation == r.Applied.Desired.Generation && r.Pending.Checksum != r.Applied.Checksum {
			return errors.New("pending and applied snapshots conflict at the same generation")
		}
	}
	if len(r.UsageOutbox) > MaxUsageOutbox {
		return fmt.Errorf("usage outbox exceeds %d batches", MaxUsageOutbox)
	}
	var previous uint64
	for i, batch := range r.UsageOutbox {
		if err := batch.Validate(); err != nil {
			return fmt.Errorf("usage_outbox[%d]: %w", i, err)
		}
		if i > 0 && batch.Sequence <= previous {
			return errors.New("usage outbox sequences must increase")
		}
		previous = batch.Sequence
	}
	return nil
}

func validateSnapshot(name string, snapshot *Snapshot) error {
	if snapshot == nil {
		return nil
	}
	if err := snapshot.Desired.Validate(); err != nil {
		return fmt.Errorf("%s snapshot: %w", name, err)
	}
	checksum, err := snapshot.Desired.Checksum()
	if err != nil {
		return fmt.Errorf("%s snapshot checksum: %w", name, err)
	}
	if checksum != snapshot.Checksum {
		return fmt.Errorf("%s snapshot checksum mismatch", name)
	}
	if snapshot.PreparedAt.IsZero() {
		return fmt.Errorf("%s snapshot prepared_at must not be zero", name)
	}
	if snapshot.ProgramChecksum != "" && !validStateChecksum(snapshot.ProgramChecksum) {
		return fmt.Errorf("%s snapshot program checksum is invalid", name)
	}
	if snapshot.TCChecksum != "" && !validStateChecksum(snapshot.TCChecksum) {
		return fmt.Errorf("%s snapshot tc checksum is invalid", name)
	}
	if snapshot.FabricChecksum != "" && !validStateChecksum(snapshot.FabricChecksum) {
		return fmt.Errorf("%s snapshot fabric checksum is invalid", name)
	}
	return nil
}

func validStateChecksum(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

type Store interface {
	Load() (StateRecord, error)
	Save(StateRecord) error
}

type FileStore struct {
	directory string
	path      string
	mu        sync.Mutex
}

func NewFileStore(directory string) (*FileStore, error) {
	if directory == "" {
		return nil, errors.New("state directory must not be empty")
	}
	return &FileStore{directory: directory, path: filepath.Join(directory, "state.json")}, nil
}

func (s *FileStore) Load() (StateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *FileStore) load() (StateRecord, error) {
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return EmptyStateRecord(), nil
	}
	if err != nil {
		return StateRecord{}, fmt.Errorf("open agent state: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return StateRecord{}, fmt.Errorf("stat agent state: %w", err)
	}
	if info.Size() > maxStateFileBytes {
		return StateRecord{}, fmt.Errorf("agent state exceeds %d bytes", maxStateFileBytes)
	}

	decoder := json.NewDecoder(io.LimitReader(file, maxStateFileBytes+1))
	decoder.DisallowUnknownFields()
	var record StateRecord
	if err := decoder.Decode(&record); err != nil {
		return StateRecord{}, fmt.Errorf("decode agent state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return StateRecord{}, errors.New("decode agent state: trailing JSON content")
	}
	if err := record.Validate(); err != nil {
		return StateRecord{}, fmt.Errorf("validate agent state: %w", err)
	}
	if record.Version < stateRecordVersion {
		record.Version = stateRecordVersion
	}
	return record, nil
}

func (s *FileStore) Save(record StateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(record)
}

func (s *FileStore) save(record StateRecord) error {
	record.Version = stateRecordVersion
	if err := record.Validate(); err != nil {
		return fmt.Errorf("refuse to persist invalid agent state: %w", err)
	}
	if err := os.MkdirAll(s.directory, 0o700); err != nil {
		return fmt.Errorf("create agent state directory: %w", err)
	}
	temporary, err := os.CreateTemp(s.directory, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary agent state: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set temporary agent state permissions: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("encode agent state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary agent state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary agent state: %w", err)
	}

	// The production target is Linux, where rename over an existing file is
	// atomic. Windows is supported only as a development/test host.
	if runtime.GOOS == "windows" {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("replace agent state on Windows: %w", err)
		}
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("commit agent state: %w", err)
	}
	removeTemporary = false

	if runtime.GOOS != "windows" {
		directory, err := os.Open(s.directory)
		if err != nil {
			return fmt.Errorf("open agent state directory for sync: %w", err)
		}
		defer directory.Close()
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync agent state directory: %w", err)
		}
	}
	return nil
}
