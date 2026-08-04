package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	shared "flux.local/flux/internal/control"
	"flux.local/flux/internal/spec"
	"flux.local/flux/internal/targetdns"
	"flux.local/flux/internal/usage"
)

var (
	ErrInvalidEnrollment    = errors.New("enrollment token is invalid, expired, used, or bound to another node")
	ErrNodeNotFound         = errors.New("node does not exist")
	ErrNodeDeletionConflict = errors.New("only a never-enrolled pending node can be deleted")
	ErrNodeAlreadyEnrolled  = errors.New("node already has an active identity")
	ErrNodeRevoked          = errors.New("node is revoked")
	ErrCredentialRevoked    = errors.New("node Noise key is unknown or revoked")
	ErrGenerationMissing    = errors.New("node generation does not exist")
	ErrChecksumMismatch     = errors.New("generation checksum does not match controller state")
	ErrProgramMismatch      = errors.New("applied program checksum conflicts with an earlier ACK")
	ErrServiceVIPConflict   = errors.New("service VIP is already allocated to another forward path")
	ErrManagementConflict   = errors.New("node desired state is owned by another management domain")
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	pool      *database
	path      string
	targetDNS *targetdns.Cache
}

type NodeKeyRecord struct {
	NodeID      string
	Fingerprint string
	PublicKey   []byte
	CreatedAt   time.Time
}

type HelloRecord struct {
	NodeID             string
	KeyFingerprint     string
	AgentVersion       string
	Capabilities       json.RawMessage
	WireGuardPublicKey string
	ObservedAt         time.Time
}

type SnapshotRecord struct {
	NodeID               string
	Generation           uint64
	SchemaVersion        uint32
	DesiredChecksum      string
	DesiredStateJSON     []byte
	RequiredCapabilities json.RawMessage
	CreatedAt            time.Time
}

type ApplyRecord struct {
	NodeID          string
	Generation      uint64
	DesiredChecksum string
	ProgramChecksum string
	Status          string
	ErrorCode       string
	ErrorMessage    string
	ObservedAt      time.Time
}

type OutboxEvent struct {
	ID          int64
	Topic       string
	AggregateID string
	Generation  uint64
	Payload     json.RawMessage
}

func Open(ctx context.Context, databasePath string) (*Store, error) {
	pool, resolvedPath, err := openSQLite(ctx, databasePath)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool, path: resolvedPath, targetDNS: targetdns.NewCache(nil, time.Minute, 3*time.Second, time.Now)}, nil
}

func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// BackupTo creates a transactionally consistent standalone SQLite snapshot.
// It is safe while the Controller is running and intentionally does not copy
// the live WAL or SHM files.
func (s *Store) BackupTo(ctx context.Context, destination string) error {
	if s == nil || s.pool == nil || s.path == ":memory:" {
		return errors.New("persistent SQLite database is required for backup")
	}
	absolute, err := filepath.Abs(filepath.Clean(destination))
	if err != nil {
		return fmt.Errorf("resolve SQLite backup path: %w", err)
	}
	if _, err := os.Stat(absolute); err == nil {
		return fmt.Errorf("backup destination already exists: %s", absolute)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect SQLite backup destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return fmt.Errorf("create SQLite backup directory: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `VACUUM INTO $1`, absolute); err != nil {
		return fmt.Errorf("create consistent SQLite backup: %w", err)
	}
	if err := os.Chmod(absolute, 0o600); err != nil {
		return fmt.Errorf("protect SQLite backup: %w", err)
	}
	return nil
}

func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS flux_schema_migrations (version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return fmt.Errorf("create migration registry: %w", err)
	}
	paths := []string{"migrations/001_sqlite.sql", "migrations/002_identity.sql"}
	for version, path := range paths {
		migrationVersion := int64(version + 1)
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM flux_schema_migrations WHERE version=$1)`, migrationVersion).Scan(&exists); err != nil {
			return fmt.Errorf("read migration registry: %w", err)
		}
		if exists {
			continue
		}
		script, err := migrations.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read embedded migration: %w", err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return fmt.Errorf("apply schema migration %d: %w", migrationVersion, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO flux_schema_migrations(version) VALUES ($1)`, migrationVersion); err != nil {
			return fmt.Errorf("record schema migration: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	return nil
}

func HashEnrollmentToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func (s *Store) CreateEnrollmentToken(ctx context.Context, nodeID string, ttl time.Duration) (string, time.Time, error) {
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		return "", time.Time{}, err
	}
	if ttl < time.Minute || ttl > 24*time.Hour {
		return "", time.Time{}, errors.New("enrollment token TTL must be between one minute and 24 hours")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, fmt.Errorf("generate enrollment token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := HashEnrollmentToken(token)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("begin enrollment token transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := ensurePendingNodeTx(ctx, tx, nodeID); err != nil {
		return "", time.Time{}, err
	}
	var alreadyEnrolled bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_keys WHERE node_id=$1 AND revoked_at IS NULL)`, nodeID).Scan(&alreadyEnrolled); err != nil {
		return "", time.Time{}, fmt.Errorf("check existing node enrollment: %w", err)
	}
	if alreadyEnrolled {
		return "", time.Time{}, ErrNodeAlreadyEnrolled
	}
	expiresAt := time.Now().UTC().Add(ttl)
	if _, err := tx.Exec(ctx, `INSERT INTO enrollment_tokens(token_hash,node_id,expires_at) VALUES ($1,$2,$3)`, hash[:], nodeID, expiresAt); err != nil {
		return "", time.Time{}, fmt.Errorf("store enrollment token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, fmt.Errorf("commit enrollment token: %w", err)
	}
	return token, expiresAt, nil
}

func (s *Store) CompleteEnrollment(ctx context.Context, nodeID, token string, publicKey []byte) (NodeKeyRecord, error) {
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		return NodeKeyRecord{}, err
	}
	if len(publicKey) != 32 {
		return NodeKeyRecord{}, errors.New("node Noise public key must be 32 bytes")
	}
	fingerprintBytes := sha256.Sum256(publicKey)
	fingerprint := fmt.Sprintf("%x", fingerprintBytes[:])
	hash := HashEnrollmentToken(token)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return NodeKeyRecord{}, fmt.Errorf("begin enrollment transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	var boundNode string
	var expiresAt time.Time
	var usedAt *time.Time
	var storedFingerprint *string
	var storedPublicKey []byte
	err = tx.QueryRow(ctx, `
SELECT node_id,expires_at,used_at,node_key_fingerprint,node_public_key
FROM enrollment_tokens WHERE token_hash=$1 FOR UPDATE`, hash[:]).Scan(&boundNode, &expiresAt, &usedAt, &storedFingerprint, &storedPublicKey)
	if errors.Is(err, sql.ErrNoRows) || err == nil && boundNode != nodeID {
		return NodeKeyRecord{}, ErrInvalidEnrollment
	}
	if err != nil {
		return NodeKeyRecord{}, fmt.Errorf("read enrollment token: %w", err)
	}
	if usedAt != nil {
		if storedFingerprint == nil || *storedFingerprint != fingerprint || len(storedPublicKey) != 32 || !equalBytes(storedPublicKey, publicKey) {
			return NodeKeyRecord{}, ErrInvalidEnrollment
		}
		var createdAt time.Time
		if err := tx.QueryRow(ctx, `SELECT created_at FROM node_keys WHERE fingerprint=$1`, fingerprint).Scan(&createdAt); err != nil {
			return NodeKeyRecord{}, fmt.Errorf("read enrolled node key: %w", err)
		}
		return NodeKeyRecord{NodeID: nodeID, Fingerprint: fingerprint, PublicKey: append([]byte(nil), publicKey...), CreatedAt: createdAt}, nil
	}
	if !time.Now().UTC().Before(expiresAt) {
		return NodeKeyRecord{}, ErrInvalidEnrollment
	}
	var alreadyEnrolled bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_keys WHERE node_id=$1 AND revoked_at IS NULL)`, nodeID).Scan(&alreadyEnrolled); err != nil {
		return NodeKeyRecord{}, fmt.Errorf("check competing node enrollment: %w", err)
	}
	if alreadyEnrolled {
		return NodeKeyRecord{}, ErrNodeAlreadyEnrolled
	}
	command, err := tx.Exec(ctx, `
UPDATE enrollment_tokens SET used_at=CURRENT_TIMESTAMP,node_key_fingerprint=$2,node_public_key=$3
WHERE token_hash=$1 AND used_at IS NULL`, hash[:], fingerprint, publicKey)
	if err != nil || command.RowsAffected() != 1 {
		if err != nil {
			return NodeKeyRecord{}, fmt.Errorf("consume enrollment token: %w", err)
		}
		return NodeKeyRecord{}, ErrInvalidEnrollment
	}
	createdAt := time.Now().UTC()
	if _, err := tx.Exec(ctx, `INSERT INTO node_keys(fingerprint,node_id,public_key,created_at) VALUES ($1,$2,$3,$4)`, fingerprint, nodeID, publicKey, createdAt); err != nil {
		return NodeKeyRecord{}, fmt.Errorf("store node Noise key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return NodeKeyRecord{}, fmt.Errorf("commit enrollment: %w", err)
	}
	return NodeKeyRecord{NodeID: nodeID, Fingerprint: fingerprint, PublicKey: append([]byte(nil), publicKey...), CreatedAt: createdAt}, nil
}

func (s *Store) AuthorizeNodeKey(ctx context.Context, nodeID string, publicKey []byte, _ time.Time) error {
	if len(publicKey) != 32 {
		return ErrCredentialRevoked
	}
	fingerprintBytes := sha256.Sum256(publicKey)
	fingerprint := fmt.Sprintf("%x", fingerprintBytes[:])
	var nodeRevoked, keyRevoked *time.Time
	var storedPublicKey []byte
	err := s.pool.QueryRow(ctx, `
SELECT n.revoked_at,k.revoked_at,k.public_key
FROM nodes n JOIN node_keys k ON k.node_id=n.id
WHERE n.id=$1 AND k.fingerprint=$2`, nodeID, fingerprint).Scan(&nodeRevoked, &keyRevoked, &storedPublicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCredentialRevoked
	}
	if err != nil {
		return fmt.Errorf("authorize node: %w", err)
	}
	if nodeRevoked != nil {
		return ErrNodeRevoked
	}
	if keyRevoked != nil || !equalBytes(storedPublicKey, publicKey) {
		return ErrCredentialRevoked
	}
	return nil
}

func (s *Store) RecordHello(ctx context.Context, record HelloRecord) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin agent hello transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	var previousPublicKey *string
	if err := tx.QueryRow(ctx, `SELECT wireguard_public_key FROM nodes WHERE id=$1 AND revoked_at IS NULL FOR UPDATE`, record.NodeID).Scan(&previousPublicKey); errors.Is(err, sql.ErrNoRows) {
		return ErrNodeNotFound
	} else if err != nil {
		return fmt.Errorf("lock node hello state: %w", err)
	}
	if _, err := tx.Exec(ctx, `
UPDATE nodes SET agent_version=$2,capabilities=$3,last_seen_at=$4,
    wireguard_public_key=COALESCE(NULLIF($5,''),wireguard_public_key),updated_at=now()
WHERE id=$1`, record.NodeID, record.AgentVersion, record.Capabilities, record.ObservedAt, record.WireGuardPublicKey); err != nil {
		return fmt.Errorf("record agent hello: %w", err)
	}
	if record.WireGuardPublicKey != "" && (previousPublicKey == nil || *previousPublicKey != record.WireGuardPublicKey) {
		if _, err := tx.Exec(ctx, `INSERT INTO node_wireguard_key_events(node_id,previous_public_key,public_key,observed_at) VALUES ($1,$2,$3,$4)`, record.NodeID, previousPublicKey, record.WireGuardPublicKey, record.ObservedAt); err != nil {
			return fmt.Errorf("audit WireGuard public key change: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE node_keys SET last_seen_at=$3 WHERE node_id=$1 AND fingerprint=$2`, record.NodeID, record.KeyFingerprint, record.ObservedAt); err != nil {
		return fmt.Errorf("record Noise key activity: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit agent hello: %w", err)
	}
	return nil
}

func (s *Store) PublishDesired(ctx context.Context, nodeID string, desired spec.DesiredState, requiredCapabilities json.RawMessage) (SnapshotRecord, error) {
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		return SnapshotRecord{}, err
	}
	if len(requiredCapabilities) == 0 {
		requiredCapabilities = json.RawMessage(`[]`)
	}
	if !json.Valid(requiredCapabilities) {
		return SnapshotRecord{}, errors.New("required capabilities must be valid JSON")
	}
	if strings.HasPrefix(desired.ManagementDomain, "cluster:") {
		return SnapshotRecord{}, errors.New("cluster-owned desired state must be published through a cluster plan")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SnapshotRecord{}, fmt.Errorf("begin publish transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	var current int64
	err = tx.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1 AND revoked_at IS NULL FOR UPDATE`, nodeID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return SnapshotRecord{}, ErrNodeNotFound
	}
	if err != nil {
		return SnapshotRecord{}, fmt.Errorf("lock node generation: %w", err)
	}
	var schedulingPlan string
	if err := tx.QueryRow(ctx, `SELECT plan_id FROM node_scheduling_profiles WHERE node_id=$1`, nodeID).Scan(&schedulingPlan); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return SnapshotRecord{}, fmt.Errorf("read node scheduling ownership: %w", err)
	} else if err == nil {
		return SnapshotRecord{}, fmt.Errorf("%w: node is assigned to cluster plan %s", ErrManagementConflict, schedulingPlan)
	}
	if current > 0 {
		var currentJSON []byte
		if err := tx.QueryRow(ctx, `SELECT desired_state FROM node_generations WHERE node_id=$1 AND generation=$2`, nodeID, current).Scan(&currentJSON); err != nil {
			return SnapshotRecord{}, fmt.Errorf("read current management domain: %w", err)
		}
		currentDesired, err := spec.DecodeDesiredJSON(currentJSON)
		if err != nil {
			return SnapshotRecord{}, fmt.Errorf("decode current management domain: %w", err)
		}
		if strings.HasPrefix(currentDesired.ManagementDomain, "cluster:") {
			return SnapshotRecord{}, ErrManagementConflict
		}
	}
	record, err := s.publishDesiredTx(ctx, tx, nodeID, current, desired, requiredCapabilities)
	if err != nil {
		return SnapshotRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SnapshotRecord{}, fmt.Errorf("commit desired generation: %w", err)
	}
	return record, nil
}

func (s *Store) publishDesiredTx(ctx context.Context, tx *transaction, nodeID string, current int64, desired spec.DesiredState, requiredCapabilities json.RawMessage) (SnapshotRecord, error) {
	if current == math.MaxInt64 {
		return SnapshotRecord{}, errors.New("node generation exhausted")
	}
	generation := uint64(current + 1)
	desired.NodeID = nodeID
	desired.Generation = generation
	if desired.SchemaVersion == 0 {
		desired.SchemaVersion = spec.CurrentSchemaVersion
	}
	if desired.SchemaVersion >= spec.SchemaVersionV2 {
		if err := s.resolveTrafficClasses(ctx, tx, nodeID, &desired); err != nil {
			return SnapshotRecord{}, err
		}
	}
	if err := desired.Validate(); err != nil {
		return SnapshotRecord{}, err
	}
	if err := syncServiceVIPBindings(ctx, tx, desired); err != nil {
		return SnapshotRecord{}, err
	}
	calculatedCapabilities, err := json.Marshal(shared.RequiredCapabilities(desired))
	if err != nil {
		return SnapshotRecord{}, fmt.Errorf("encode required capabilities: %w", err)
	}
	requiredCapabilities = calculatedCapabilities
	encoded, err := spec.EncodeDesiredJSON(desired)
	if err != nil {
		return SnapshotRecord{}, err
	}
	checksum, err := desired.Checksum()
	if err != nil {
		return SnapshotRecord{}, fmt.Errorf("calculate desired checksum: %w", err)
	}
	createdAt := time.Now().UTC()
	if _, err := tx.Exec(ctx, `
INSERT INTO node_generations(node_id,generation,schema_version,desired_checksum,desired_state,required_capabilities,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)`, nodeID, int64(generation), desired.SchemaVersion, checksum, encoded, requiredCapabilities, createdAt); err != nil {
		return SnapshotRecord{}, fmt.Errorf("insert node generation: %w", err)
	}
	payload, _ := json.Marshal(map[string]any{"node_id": nodeID, "generation": generation})
	if _, err := tx.Exec(ctx, `
INSERT INTO transactional_outbox(topic,aggregate_id,generation,payload)
VALUES ('node.snapshot.ready',$1,$2,$3)`, nodeID, int64(generation), payload); err != nil {
		return SnapshotRecord{}, fmt.Errorf("insert generation outbox event: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE nodes SET desired_generation=$2,updated_at=now() WHERE id=$1`, nodeID, int64(generation)); err != nil {
		return SnapshotRecord{}, fmt.Errorf("advance desired generation: %w", err)
	}
	return SnapshotRecord{NodeID: nodeID, Generation: generation, SchemaVersion: desired.SchemaVersion, DesiredChecksum: checksum, DesiredStateJSON: encoded, RequiredCapabilities: append(json.RawMessage(nil), requiredCapabilities...), CreatedAt: createdAt}, nil
}

func (s *Store) resolveTrafficClasses(ctx context.Context, tx *transaction, nodeID string, desired *spec.DesiredState) error {
	ingressUsers := make(map[string]struct{})
	for _, forward := range desired.Forwards {
		if forward.IngressNodeID == desired.NodeID {
			ingressUsers[forward.UserID] = struct{}{}
		}
	}
	for i := range desired.UserPolicies {
		_, usedAtIngress := ingressUsers[desired.UserPolicies[i].UserID]
		if !usedAtIngress || desired.UserPolicies[i].RateLimit == nil {
			desired.UserPolicies[i].TrafficClassID = 0
			continue
		}
		classID, err := allocateTrafficClass(ctx, tx, nodeID, "user", desired.UserPolicies[i].UserID)
		if err != nil {
			return err
		}
		desired.UserPolicies[i].TrafficClassID = classID
	}
	for i := range desired.Forwards {
		if desired.Forwards[i].IngressNodeID != desired.NodeID || desired.Forwards[i].RateLimit == nil {
			desired.Forwards[i].TrafficClassID = 0
			continue
		}
		classID, err := allocateTrafficClass(ctx, tx, nodeID, "forward", desired.Forwards[i].ID)
		if err != nil {
			return err
		}
		desired.Forwards[i].TrafficClassID = classID
	}
	return nil
}

func syncServiceVIPBindings(ctx context.Context, tx *transaction, desired spec.DesiredState) error {
	forwardIDs := make([]string, 0)
	for _, forward := range desired.Forwards {
		if forward.PathMode != spec.PathViaExit {
			continue
		}
		forwardIDs = append(forwardIDs, forward.ID)
		var allocated string
		err := tx.QueryRow(ctx, `
INSERT INTO service_vip_allocations(service_vip,forward_id,user_id,ingress_node_id,exit_node_id)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (service_vip) DO UPDATE SET
  ingress_node_id=EXCLUDED.ingress_node_id,
  exit_node_id=EXCLUDED.exit_node_id,
  updated_at=now()
WHERE service_vip_allocations.forward_id=EXCLUDED.forward_id
  AND service_vip_allocations.user_id=EXCLUDED.user_id
RETURNING service_vip`, forward.ServiceVIP.String(), forward.ID, forward.UserID, forward.IngressNodeID, forward.ExitNodeID).Scan(&allocated)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrServiceVIPConflict, forward.ServiceVIP)
		}
		if err != nil {
			return fmt.Errorf("allocate service VIP %s: %w", forward.ServiceVIP, err)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO service_vip_bindings(node_id,forward_id,service_vip)
VALUES ($1,$2,$3)
ON CONFLICT (node_id,forward_id) DO UPDATE
SET service_vip=EXCLUDED.service_vip,updated_at=now()`, desired.NodeID, forward.ID, allocated); err != nil {
			return fmt.Errorf("bind service VIP %s to node %s: %w", forward.ServiceVIP, desired.NodeID, err)
		}
	}
	if len(forwardIDs) == 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM service_vip_bindings WHERE node_id=$1`, desired.NodeID); err != nil {
			return fmt.Errorf("remove stale service VIP bindings: %w", err)
		}
	} else if encodedIDs, encodeErr := json.Marshal(forwardIDs); encodeErr != nil {
		return fmt.Errorf("encode active service VIP bindings: %w", encodeErr)
	} else if _, err := tx.Exec(ctx, `DELETE FROM service_vip_bindings WHERE node_id=$1 AND forward_id NOT IN (SELECT value FROM json_each($2))`, desired.NodeID, string(encodedIDs)); err != nil {
		return fmt.Errorf("remove stale service VIP bindings: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM service_vip_allocations WHERE NOT EXISTS (SELECT 1 FROM service_vip_bindings b WHERE b.service_vip=service_vip_allocations.service_vip)`); err != nil {
		return fmt.Errorf("remove orphaned service VIP allocations: %w", err)
	}
	return nil
}

func allocateTrafficClass(ctx context.Context, tx *transaction, nodeID, ownerKind, ownerID string) (uint16, error) {
	var existing int
	err := tx.QueryRow(ctx, `SELECT class_id FROM traffic_class_allocations WHERE node_id=$1 AND owner_kind=$2 AND owner_id=$3`, nodeID, ownerKind, ownerID).Scan(&existing)
	if err == nil {
		return uint16(existing), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("read traffic class allocation: %w", err)
	}
	allocatedRows, err := tx.Query(ctx, `SELECT class_id FROM traffic_class_allocations WHERE node_id=$1 ORDER BY class_id`, nodeID)
	if err != nil {
		return 0, fmt.Errorf("allocate traffic class: %w", err)
	}
	defer allocatedRows.Close()
	candidate := 2
	for allocatedRows.Next() {
		var allocated int
		if err := allocatedRows.Scan(&allocated); err != nil {
			return 0, fmt.Errorf("scan traffic class allocation: %w", err)
		}
		if allocated < candidate {
			continue
		}
		if allocated == candidate {
			candidate++
			continue
		}
		break
	}
	if err := allocatedRows.Err(); err != nil {
		return 0, fmt.Errorf("iterate traffic class allocations: %w", err)
	}
	if candidate > 65534 {
		return 0, errors.New("node traffic class space is exhausted")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO traffic_class_allocations(node_id,owner_kind,owner_id,class_id) VALUES ($1,$2,$3,$4)`, nodeID, ownerKind, ownerID, candidate); err != nil {
		return 0, fmt.Errorf("store traffic class allocation: %w", err)
	}
	return uint16(candidate), nil
}

func (s *Store) LatestSnapshot(ctx context.Context, nodeID string) (SnapshotRecord, bool, error) {
	var record SnapshotRecord
	var generation int64
	err := s.pool.QueryRow(ctx, `
SELECT node_id,generation,schema_version,desired_checksum,desired_state,required_capabilities,created_at
FROM node_generations WHERE node_id=$1 ORDER BY generation DESC LIMIT 1`, nodeID).Scan(
		&record.NodeID, &generation, &record.SchemaVersion, &record.DesiredChecksum, &record.DesiredStateJSON, &record.RequiredCapabilities, &record.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SnapshotRecord{}, false, nil
	}
	if err != nil {
		return SnapshotRecord{}, false, fmt.Errorf("read latest node snapshot: %w", err)
	}
	record.Generation = uint64(generation)
	return record, true, nil
}

func (s *Store) RecordApplyResult(ctx context.Context, record ApplyRecord) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin ACK transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	var expected string
	err = tx.QueryRow(ctx, `SELECT desired_checksum FROM node_generations WHERE node_id=$1 AND generation=$2 FOR UPDATE`, record.NodeID, int64(record.Generation)).Scan(&expected)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrGenerationMissing
	}
	if err != nil {
		return fmt.Errorf("read ACK generation: %w", err)
	}
	if expected != record.DesiredChecksum {
		return ErrChecksumMismatch
	}
	var currentApplied, currentDesiredGeneration int64
	var currentDesired, currentProgram *string
	if err := tx.QueryRow(ctx, `SELECT applied_generation,desired_generation,applied_desired_checksum,applied_program_checksum FROM nodes WHERE id=$1 FOR UPDATE`, record.NodeID).Scan(&currentApplied, &currentDesiredGeneration, &currentDesired, &currentProgram); err != nil {
		return fmt.Errorf("lock node ACK state: %w", err)
	}
	if record.Status == "applied" && currentApplied == int64(record.Generation) && (currentDesired == nil || *currentDesired != record.DesiredChecksum) {
		return ErrProgramMismatch
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO generation_ack_events(node_id,generation,desired_checksum,program_checksum,status,error_code,error_message,observed_at)
VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8)`, record.NodeID, int64(record.Generation), record.DesiredChecksum, record.ProgramChecksum, record.Status, record.ErrorCode, record.ErrorMessage, record.ObservedAt); err != nil {
		return fmt.Errorf("insert ACK event: %w", err)
	}
	if _, err := tx.Exec(ctx, `
UPDATE node_generations
SET status=CASE WHEN status='applied' AND $3<>'applied' THEN status ELSE $3 END,
    applied_at=CASE WHEN $3='applied' THEN $4 ELSE applied_at END
WHERE node_id=$1 AND generation=$2`, record.NodeID, int64(record.Generation), record.Status, record.ObservedAt); err != nil {
		return fmt.Errorf("update generation ACK status: %w", err)
	}
	if record.Status == "applied" {
		if _, err := tx.Exec(ctx, `
UPDATE nodes SET applied_generation=$2,applied_desired_checksum=$3,applied_program_checksum=$4,last_seen_at=$5,updated_at=now()
WHERE id=$1 AND applied_generation <= $2`, record.NodeID, int64(record.Generation), record.DesiredChecksum, record.ProgramChecksum, record.ObservedAt); err != nil {
			return fmt.Errorf("update node applied generation: %w", err)
		}
		if currentDesiredGeneration == int64(record.Generation) {
			var desiredJSON, requiredCapabilities []byte
			if err := tx.QueryRow(ctx, `SELECT desired_state,required_capabilities FROM node_generations WHERE node_id=$1 AND generation=$2`, record.NodeID, int64(record.Generation)).Scan(&desiredJSON, &requiredCapabilities); err != nil {
				return fmt.Errorf("read applied desired state: %w", err)
			}
			desired, err := spec.DecodeDesiredJSON(desiredJSON)
			if err != nil {
				return fmt.Errorf("decode applied desired state: %w", err)
			}
			removed := make([]string, 0)
			kept := desired.Forwards[:0]
			for _, forward := range desired.Forwards {
				if forward.Lifecycle == spec.LifecycleForceDeleting {
					removed = append(removed, forward.ID)
					continue
				}
				kept = append(kept, forward)
			}
			if len(removed) != 0 {
				desired.Forwards = kept
				next, err := s.publishDesiredTx(ctx, tx, record.NodeID, currentDesiredGeneration, desired, json.RawMessage(requiredCapabilities))
				if err != nil {
					return fmt.Errorf("publish post-force cleanup generation: %w", err)
				}
				for _, forwardID := range removed {
					detail, _ := json.Marshal(map[string]any{"acked_generation": record.Generation})
					if _, err := tx.Exec(ctx, `INSERT INTO policy_audit_events(node_id,generation,action,subject_id,detail) VALUES ($1,$2,'force_remove',$3,$4)`, record.NodeID, int64(next.Generation), forwardID, detail); err != nil {
						return fmt.Errorf("record force removal audit: %w", err)
					}
				}
			}
		}
	}
	if err := recordClusterRolloutACKTx(ctx, tx, record); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit ACK: %w", err)
	}
	return nil
}

func (s *Store) RecordHeartbeat(ctx context.Context, nodeID string, observedAt time.Time) error {
	command, err := s.pool.Exec(ctx, `UPDATE nodes SET last_seen_at=$2,updated_at=now() WHERE id=$1 AND revoked_at IS NULL`, nodeID, observedAt)
	if err != nil {
		return fmt.Errorf("record heartbeat: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrNodeNotFound
	}
	return nil
}

func (s *Store) RecordUsageBatch(ctx context.Context, batch usage.Batch) error {
	if err := batch.Validate(); err != nil {
		return err
	}
	if batch.Sequence > math.MaxInt64 || batch.Generation > math.MaxInt64 {
		return errors.New("usage sequence or generation exceeds controller range")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin usage transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	var desiredJSON []byte
	if err := tx.QueryRow(ctx, `SELECT desired_state FROM node_generations WHERE node_id=$1 AND generation=$2`, batch.NodeID, int64(batch.Generation)).Scan(&desiredJSON); errors.Is(err, sql.ErrNoRows) {
		return ErrGenerationMissing
	} else if err != nil {
		return fmt.Errorf("read usage generation: %w", err)
	}
	command, err := tx.Exec(ctx, `
INSERT INTO usage_batches(node_id,counter_epoch,sequence,generation,observed_at)
VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, batch.NodeID, batch.Epoch, int64(batch.Sequence), int64(batch.Generation), batch.ObservedAt)
	if err != nil {
		return fmt.Errorf("insert usage batch: %w", err)
	}
	if command.RowsAffected() == 0 {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit duplicate usage batch: %w", err)
		}
		return nil
	}

	desired, err := spec.DecodeDesiredJSON(desiredJSON)
	if err != nil {
		return fmt.Errorf("decode usage generation: %w", err)
	}
	forwards := make(map[string]spec.ForwardSpec, len(desired.Forwards))
	for _, forward := range desired.Forwards {
		forwards[forward.ID] = forward
	}
	for _, delta := range batch.Deltas {
		if delta.Packets > math.MaxInt64 || delta.Bytes > math.MaxInt64 {
			return errors.New("usage delta exceeds controller range")
		}
		forward, exists := forwards[delta.ForwardID]
		if !exists || forward.ResourceVersion != delta.ResourceVersion || !forwardHasProtocol(forward, delta.Protocol) {
			return fmt.Errorf("usage binding is not present in generation %d", batch.Generation)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO usage_deltas(node_id,counter_epoch,sequence,forward_id,user_id,protocol,direction,resource_version,packets,bytes,counter_reset)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, batch.NodeID, batch.Epoch, int64(batch.Sequence), delta.ForwardID, forward.UserID, string(delta.Protocol), string(delta.Direction), int64(delta.ResourceVersion), int64(delta.Packets), int64(delta.Bytes), delta.Reset); err != nil {
			return fmt.Errorf("insert usage delta: %w", err)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO usage_rollups(node_id,forward_id,user_id,protocol,direction,packets,bytes)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (node_id,forward_id,protocol,direction) DO UPDATE
SET user_id=EXCLUDED.user_id,packets=usage_rollups.packets+EXCLUDED.packets,
    bytes=usage_rollups.bytes+EXCLUDED.bytes,updated_at=now()`, batch.NodeID, delta.ForwardID, forward.UserID, string(delta.Protocol), string(delta.Direction), int64(delta.Packets), int64(delta.Bytes)); err != nil {
			return fmt.Errorf("aggregate usage delta: %w", err)
		}
	}

	var current int64
	if err := tx.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1 AND revoked_at IS NULL FOR UPDATE`, batch.NodeID).Scan(&current); err != nil {
		return fmt.Errorf("lock node for quota evaluation: %w", err)
	}
	if current > 0 {
		var currentJSON, requiredCapabilities []byte
		if err := tx.QueryRow(ctx, `SELECT desired_state,required_capabilities FROM node_generations WHERE node_id=$1 AND generation=$2`, batch.NodeID, current).Scan(&currentJSON, &requiredCapabilities); err != nil {
			return fmt.Errorf("read current state for quota evaluation: %w", err)
		}
		currentDesired, err := spec.DecodeDesiredJSON(currentJSON)
		if err != nil {
			return fmt.Errorf("decode current state for quota evaluation: %w", err)
		}
		changed, audits, err := evaluateQuotas(ctx, tx, batch.NodeID, &currentDesired)
		if err != nil {
			return err
		}
		if changed {
			next, err := s.publishDesiredTx(ctx, tx, batch.NodeID, current, currentDesired, json.RawMessage(requiredCapabilities))
			if err != nil {
				return fmt.Errorf("publish quota policy generation: %w", err)
			}
			if err := insertPolicyAudits(ctx, tx, batch.NodeID, next.Generation, audits); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit usage batch: %w", err)
	}
	return nil
}

type policyAudit struct {
	action    string
	subjectID string
	detail    json.RawMessage
}

func evaluateQuotas(ctx context.Context, tx *transaction, nodeID string, desired *spec.DesiredState) (bool, []policyAudit, error) {
	changed := false
	var audits []policyAudit
	pausedUsers := make(map[string]bool)
	for _, policy := range desired.UserPolicies {
		if policy.TrafficQuota == nil {
			continue
		}
		exceeded, total, err := quotaExceeded(ctx, tx, `SELECT CAST(COALESCE(SUM(bytes),0) AS TEXT) FROM usage_rollups WHERE node_id=$1 AND user_id=$2`, nodeID, policy.UserID, policy.TrafficQuota.Bytes)
		if err != nil {
			return false, nil, err
		}
		if exceeded {
			pausedUsers[policy.UserID] = true
			detail, _ := json.Marshal(map[string]any{"used_bytes": total, "quota_bytes": policy.TrafficQuota.Bytes})
			audits = append(audits, policyAudit{action: "user_quota_pause", subjectID: policy.UserID, detail: detail})
		}
	}
	for i := range desired.Forwards {
		forward := &desired.Forwards[i]
		if forward.Lifecycle == spec.LifecyclePaused || forward.Lifecycle == spec.LifecycleForceDeleting {
			continue
		}
		action := ""
		var detail json.RawMessage
		if pausedUsers[forward.UserID] {
			action = "user_quota_pause"
			detail, _ = json.Marshal(map[string]any{"user_id": forward.UserID})
		} else if forward.TrafficQuota != nil {
			exceeded, total, err := quotaExceeded(ctx, tx, `SELECT CAST(COALESCE(SUM(bytes),0) AS TEXT) FROM usage_rollups WHERE node_id=$1 AND forward_id=$2`, nodeID, forward.ID, forward.TrafficQuota.Bytes)
			if err != nil {
				return false, nil, err
			}
			if exceeded {
				action = "forward_quota_pause"
				detail, _ = json.Marshal(map[string]any{"used_bytes": total, "quota_bytes": forward.TrafficQuota.Bytes})
			}
		}
		if action != "" {
			forward.Lifecycle = spec.LifecyclePaused
			forward.DrainDeadline = nil
			forward.ResourceVersion++
			changed = true
			audits = append(audits, policyAudit{action: action, subjectID: forward.ID, detail: detail})
		}
	}
	return changed, audits, nil
}

func quotaExceeded(ctx context.Context, tx *transaction, query, nodeID, subjectID string, quota uint64) (bool, string, error) {
	var total string
	if err := tx.QueryRow(ctx, query, nodeID, subjectID).Scan(&total); err != nil {
		return false, "", fmt.Errorf("read usage quota total: %w", err)
	}
	value, ok := new(big.Int).SetString(total, 10)
	if !ok {
		return false, "", errors.New("usage quota total is invalid")
	}
	limit := new(big.Int).SetUint64(quota)
	return value.Cmp(limit) >= 0, total, nil
}

func forwardHasProtocol(forward spec.ForwardSpec, protocol spec.Protocol) bool {
	for _, candidate := range forward.Protocols {
		if candidate == protocol {
			return true
		}
	}
	return false
}

func insertPolicyAudits(ctx context.Context, tx *transaction, nodeID string, generation uint64, audits []policyAudit) error {
	for _, audit := range audits {
		if len(audit.detail) == 0 {
			audit.detail = json.RawMessage(`{}`)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO policy_audit_events(node_id,generation,action,subject_id,detail) VALUES ($1,$2,$3,$4,$5)`, nodeID, int64(generation), audit.action, audit.subjectID, audit.detail); err != nil {
			return fmt.Errorf("record policy audit: %w", err)
		}
	}
	return nil
}

func (s *Store) EnforcePolicies(ctx context.Context, limit int, now time.Time) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, errors.New("policy scan limit must be between 1 and 1000")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin policy transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
SELECT n.id,n.desired_generation
FROM nodes n
WHERE n.revoked_at IS NULL AND n.desired_generation>0
  AND NOT EXISTS (
    SELECT 1
    FROM cluster_rollout_nodes target
    JOIN cluster_rollouts rollout ON rollout.id=target.rollout_id
    WHERE target.node_id=n.id
      AND rollout.status IN ('publishing','awaiting_ack','baking','rollback_pending','rolling_back')
  )
ORDER BY n.policy_checked_at NULLS FIRST,n.id
LIMIT $1`, limit)
	if err != nil {
		return 0, fmt.Errorf("claim policy nodes: %w", err)
	}
	type claimedNode struct {
		id         string
		generation int64
	}
	var nodes []claimedNode
	for rows.Next() {
		var node claimedNode
		if err := rows.Scan(&node.id, &node.generation); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan policy node: %w", err)
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate policy nodes: %w", err)
	}
	rows.Close()

	published := 0
	for _, node := range nodes {
		var rolloutActive bool
		if err := tx.QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM cluster_rollout_nodes target
  JOIN cluster_rollouts rollout ON rollout.id=target.rollout_id
  WHERE target.node_id=$1
    AND rollout.status IN ('publishing','awaiting_ack','baking','rollback_pending','rolling_back')
)`, node.id).Scan(&rolloutActive); err != nil {
			return published, fmt.Errorf("recheck node rollout ownership: %w", err)
		}
		if rolloutActive {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE nodes SET policy_checked_at=$2 WHERE id=$1`, node.id, now); err != nil {
			return published, fmt.Errorf("advance policy scan cursor: %w", err)
		}
		var desiredJSON, requiredCapabilities []byte
		if err := tx.QueryRow(ctx, `SELECT desired_state,required_capabilities FROM node_generations WHERE node_id=$1 AND generation=$2`, node.id, node.generation).Scan(&desiredJSON, &requiredCapabilities); err != nil {
			return published, fmt.Errorf("read policy desired state: %w", err)
		}
		desired, err := spec.DecodeDesiredJSON(desiredJSON)
		if err != nil {
			return published, fmt.Errorf("decode policy desired state: %w", err)
		}
		var audits []policyAudit
		for i := range desired.Forwards {
			forward := &desired.Forwards[i]
			switch {
			case forward.ExpiresAt != nil && !now.Before(*forward.ExpiresAt) && forward.Lifecycle != spec.LifecyclePaused && forward.Lifecycle != spec.LifecycleForceDeleting:
				forward.Lifecycle = spec.LifecyclePaused
				forward.DrainDeadline = nil
				forward.ResourceVersion++
				detail, _ := json.Marshal(map[string]any{"expires_at": forward.ExpiresAt.UTC().Format(time.RFC3339)})
				audits = append(audits, policyAudit{action: "expiry_pause", subjectID: forward.ID, detail: detail})
			case forward.Lifecycle == spec.LifecycleDraining && forward.DrainDeadline != nil && !now.Before(*forward.DrainDeadline):
				deadline := forward.DrainDeadline.UTC().Format(time.RFC3339)
				forward.Lifecycle = spec.LifecycleForceDeleting
				forward.DrainDeadline = nil
				forward.ResourceVersion++
				detail, _ := json.Marshal(map[string]any{"drain_deadline": deadline})
				audits = append(audits, policyAudit{action: "drain_force", subjectID: forward.ID, detail: detail})
			}
		}
		if len(audits) == 0 {
			continue
		}
		next, err := s.publishDesiredTx(ctx, tx, node.id, node.generation, desired, json.RawMessage(requiredCapabilities))
		if err != nil {
			return published, fmt.Errorf("publish time policy generation: %w", err)
		}
		if err := insertPolicyAudits(ctx, tx, node.id, next.Generation, audits); err != nil {
			return published, err
		}
		published++
	}
	if err := tx.Commit(ctx); err != nil {
		return published, fmt.Errorf("commit policy transaction: %w", err)
	}
	return published, nil
}

func (s *Store) ClaimOutbox(ctx context.Context, owner string, limit int, lease time.Duration) ([]OutboxEvent, error) {
	if owner == "" || limit < 1 || limit > 1000 || lease < time.Second {
		return nil, errors.New("invalid outbox claim arguments")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin outbox claim: %w", err)
	}
	defer tx.Rollback(ctx)
	ready, err := tx.Query(ctx, `
SELECT id,topic,aggregate_id,generation,payload FROM transactional_outbox
WHERE delivered_at IS NULL AND available_at <= CURRENT_TIMESTAMP
  AND (leased_until IS NULL OR leased_until < CURRENT_TIMESTAMP)
ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("select outbox events: %w", err)
	}
	var events []OutboxEvent
	for ready.Next() {
		var event OutboxEvent
		var generation int64
		if err := ready.Scan(&event.ID, &event.Topic, &event.AggregateID, &generation, &event.Payload); err != nil {
			ready.Close()
			return nil, fmt.Errorf("scan outbox event: %w", err)
		}
		event.Generation = uint64(generation)
		events = append(events, event)
	}
	if err := ready.Err(); err != nil {
		ready.Close()
		return nil, fmt.Errorf("iterate outbox events: %w", err)
	}
	ready.Close()
	leasedUntil := time.Now().UTC().Add(lease)
	for _, event := range events {
		if _, err := tx.Exec(ctx, `UPDATE transactional_outbox SET leased_by=$2,leased_until=$3,attempts=attempts+1 WHERE id=$1 AND delivered_at IS NULL`, event.ID, owner, leasedUntil); err != nil {
			return nil, fmt.Errorf("lease outbox event: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit outbox claim: %w", err)
	}
	return events, nil
}

func (s *Store) MarkOutboxDelivered(ctx context.Context, owner string, id int64) error {
	command, err := s.pool.Exec(ctx, `UPDATE transactional_outbox SET delivered_at=now(),leased_by=NULL,leased_until=NULL WHERE id=$1 AND leased_by=$2 AND delivered_at IS NULL`, id, owner)
	if err != nil {
		return fmt.Errorf("mark outbox event delivered: %w", err)
	}
	if command.RowsAffected() != 1 {
		return errors.New("outbox lease was lost")
	}
	return nil
}

func (s *Store) ReleaseOutbox(ctx context.Context, owner string, id int64, reason string) error {
	if len(reason) > 2048 {
		reason = reason[:2048]
	}
	_, err := s.pool.Exec(ctx, `UPDATE transactional_outbox SET leased_by=NULL,leased_until=NULL,available_at=$4,last_error=$3 WHERE id=$1 AND leased_by=$2 AND delivered_at IS NULL`, id, owner, reason, time.Now().UTC().Add(2*time.Second))
	if err != nil {
		return fmt.Errorf("release outbox event: %w", err)
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
