package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"flux.local/flux/internal/controller/iam"
)

const (
	maxTenantPageSize = 200
	maxAuditPageSize  = 500
)

type TenantCreate struct {
	ID            string
	Name          string
	Username      string
	DisplayName   string
	PasswordHash  string
	ExpiresAt     *time.Time
	InitialPolicy *iam.Policy
}

func (s *Store) CreateOwner(ctx context.Context, username, displayName, passwordHash string) (iam.Account, error) {
	username, err := iam.NormalizeUsername(username)
	if err != nil {
		return iam.Account{}, err
	}
	displayName, err = iam.ValidateDisplayName(displayName)
	if err != nil {
		return iam.Account{}, err
	}
	if len(passwordHash) < 32 || len(passwordHash) > 512 {
		return iam.Account{}, errors.New("owner password hash is invalid")
	}
	accountID, err := iam.NewID("account")
	if err != nil {
		return iam.Account{}, err
	}
	now := time.Now().UTC()
	result, err := s.pool.Exec(ctx, `
INSERT INTO accounts(id,username,display_name,role,password_hash,status,created_at,updated_at)
VALUES ($1,$2,$3,'owner',$4,'active',$5,$5)
ON CONFLICT DO NOTHING`, accountID, username, displayName, passwordHash, now)
	if err != nil {
		return iam.Account{}, fmt.Errorf("create Owner account: %w", err)
	}
	if result.RowsAffected() != 1 {
		return iam.Account{}, fmt.Errorf("%w: an Owner or username already exists", iam.ErrConflict)
	}
	return s.AccountByID(ctx, accountID)
}

func (s *Store) OwnerCount(ctx context.Context) (int, error) {
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM accounts WHERE role='owner'`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count Owner accounts: %w", err)
	}
	return count, nil
}

func (s *Store) CreateTenant(ctx context.Context, input TenantCreate) (iam.Tenant, iam.Account, iam.Policy, error) {
	name, err := iam.ValidateTenantName(input.Name)
	if err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
	}
	username, err := iam.NormalizeUsername(input.Username)
	if err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
	}
	displayName, err := iam.ValidateDisplayName(input.DisplayName)
	if err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
	}
	if len(input.PasswordHash) < 32 || len(input.PasswordHash) > 512 {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, errors.New("tenant password hash is invalid")
	}
	now := time.Now().UTC()
	if input.ExpiresAt != nil && !now.Before(*input.ExpiresAt) {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, errors.New("tenant expiry must be in the future")
	}
	tenantID := strings.TrimSpace(input.ID)
	if tenantID == "" {
		tenantID, err = iam.NewID("tenant")
		if err != nil {
			return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
		}
	} else if err := iam.ValidateInternalID("tenant_id", tenantID); err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
	}
	accountID, err := iam.NewID("account")
	if err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, fmt.Errorf("begin tenant creation: %w", err)
	}
	defer tx.Rollback(ctx)
	policy := iam.EmptyPolicy(tenantID)
	if input.InitialPolicy != nil {
		policy = *input.InitialPolicy
		policy.TenantID = tenantID
		policy.ResourceVersion = 1
		policy.CreatedAt = time.Time{}
		policy.UpdatedAt = time.Time{}
		policy = iam.CanonicalizePolicy(policy)
		if err := policy.Validate(); err != nil {
			return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
		}
		if err := validatePolicyNodesQuery(ctx, tx, policy); err != nil {
			return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
		}
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO tenants(id,name,status,expires_at,created_at,updated_at)
VALUES ($1,$2,'active',$3,$4,$4)`, tenantID, name, input.ExpiresAt, now); err != nil {
		if isUniqueViolation(err) {
			return iam.Tenant{}, iam.Account{}, iam.Policy{}, fmt.Errorf("%w: tenant already exists", iam.ErrConflict)
		}
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, fmt.Errorf("create tenant: %w", err)
	}
	allowedIngress, _ := json.Marshal(policy.AllowedIngressNodes)
	allowedExit, _ := json.Marshal(policy.AllowedExitNodes)
	allowedListen, _ := json.Marshal(policy.AllowedListenIPs)
	allowedPorts, _ := json.Marshal(policy.AllowedPortRanges)
	allowedProtocols, _ := json.Marshal(policy.AllowedProtocols)
	allowedTargets, _ := json.Marshal(policy.AllowedTargetCIDRs)
	deniedTargets, _ := json.Marshal(policy.DeniedTargetCIDRs)
	if _, err := tx.Exec(ctx, `
INSERT INTO tenant_policies(
    tenant_id,allowed_ingress_nodes,allowed_exit_nodes,allowed_listen_ips,allowed_port_ranges,
    allowed_protocols,allow_via_exit,max_forwards,ingress_rate_limit_bps,egress_rate_limit_bps,
    traffic_quota_bytes,allowed_target_cidrs,denied_target_cidrs,created_at,updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)`,
		tenantID, allowedIngress, allowedExit, allowedListen, allowedPorts, allowedProtocols,
		policy.AllowViaExit, policy.MaxForwards, policy.IngressRateLimitBPS, policy.EgressRateLimitBPS,
		policy.TrafficQuotaBytes, allowedTargets, deniedTargets, now); err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, fmt.Errorf("create tenant policy: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO accounts(id,tenant_id,username,display_name,role,password_hash,status,expires_at,created_at,updated_at)
VALUES ($1,$2,$3,$4,'tenant',$5,'active',$6,$7,$7)`, accountID, tenantID, username, displayName, input.PasswordHash, input.ExpiresAt, now); err != nil {
		if isUniqueViolation(err) {
			return iam.Tenant{}, iam.Account{}, iam.Policy{}, fmt.Errorf("%w: username already exists", iam.ErrConflict)
		}
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, fmt.Errorf("create tenant account: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, fmt.Errorf("commit tenant creation: %w", err)
	}
	tenant, err := s.TenantByID(ctx, tenantID)
	if err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
	}
	account, err := s.AccountByID(ctx, accountID)
	if err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
	}
	policy, err = s.TenantPolicy(ctx, tenantID)
	if err != nil {
		return iam.Tenant{}, iam.Account{}, iam.Policy{}, err
	}
	return tenant, account, policy, nil
}

func (s *Store) TenantByID(ctx context.Context, tenantID string) (iam.Tenant, error) {
	if err := iam.ValidateInternalID("tenant_id", tenantID); err != nil {
		return iam.Tenant{}, err
	}
	return scanTenant(s.pool.QueryRow(ctx, `
SELECT id,name,status,expires_at,resource_version,created_at,updated_at FROM tenants WHERE id=$1`, tenantID))
}

func (s *Store) ListTenants(ctx context.Context, limit, offset int) ([]iam.Tenant, error) {
	if limit <= 0 || limit > maxTenantPageSize {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.pool.Query(ctx, `
SELECT id,name,status,expires_at,resource_version,created_at,updated_at
FROM tenants ORDER BY created_at DESC,id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()
	result := make([]iam.Tenant, 0)
	for rows.Next() {
		tenant, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, tenant)
	}
	return result, rows.Err()
}

func (s *Store) UpdateTenant(ctx context.Context, tenantID, name string, status iam.Status, expiresAt *time.Time, expectedVersion uint64) (iam.Tenant, error) {
	if err := iam.ValidateInternalID("tenant_id", tenantID); err != nil {
		return iam.Tenant{}, err
	}
	name, err := iam.ValidateTenantName(name)
	if err != nil {
		return iam.Tenant{}, err
	}
	if status != iam.StatusActive && status != iam.StatusDisabled {
		return iam.Tenant{}, errors.New("tenant status is invalid")
	}
	if expectedVersion == 0 {
		return iam.Tenant{}, errors.New("tenant resource_version is required")
	}
	now := time.Now().UTC()
	result, err := s.pool.Exec(ctx, `
UPDATE tenants SET name=$2,status=$3,expires_at=$4,resource_version=resource_version+1,updated_at=$5
WHERE id=$1 AND resource_version=$6`, tenantID, name, status, expiresAt, now, expectedVersion)
	if err != nil {
		return iam.Tenant{}, fmt.Errorf("update tenant: %w", err)
	}
	if result.RowsAffected() != 1 {
		if _, lookupErr := s.TenantByID(ctx, tenantID); errors.Is(lookupErr, iam.ErrNotFound) {
			return iam.Tenant{}, lookupErr
		}
		return iam.Tenant{}, iam.ErrConflict
	}
	if status == iam.StatusDisabled {
		if _, err := s.pool.Exec(ctx, `
UPDATE management_sessions SET revoked_at=$2
WHERE revoked_at IS NULL AND account_id IN (SELECT id FROM accounts WHERE tenant_id=$1)`, tenantID, now); err != nil {
			return iam.Tenant{}, fmt.Errorf("revoke disabled tenant sessions: %w", err)
		}
	}
	return s.TenantByID(ctx, tenantID)
}

func (s *Store) TenantPolicy(ctx context.Context, tenantID string) (iam.Policy, error) {
	if err := iam.ValidateInternalID("tenant_id", tenantID); err != nil {
		return iam.Policy{}, err
	}
	return scanPolicy(s.pool.QueryRow(ctx, `
SELECT tenant_id,allowed_ingress_nodes,allowed_exit_nodes,allowed_listen_ips,allowed_port_ranges,
       allowed_protocols,allow_via_exit,max_forwards,ingress_rate_limit_bps,egress_rate_limit_bps,
       traffic_quota_bytes,allowed_target_cidrs,denied_target_cidrs,resource_version,created_at,updated_at
FROM tenant_policies WHERE tenant_id=$1`, tenantID))
}

func (s *Store) UpdateTenantPolicy(ctx context.Context, policy iam.Policy) (iam.Policy, error) {
	policy = iam.CanonicalizePolicy(policy)
	if err := policy.Validate(); err != nil {
		return iam.Policy{}, err
	}
	if err := s.validatePolicyNodes(ctx, policy); err != nil {
		return iam.Policy{}, err
	}
	allowedIngress, _ := json.Marshal(policy.AllowedIngressNodes)
	allowedExit, _ := json.Marshal(policy.AllowedExitNodes)
	allowedListen, _ := json.Marshal(policy.AllowedListenIPs)
	allowedPorts, _ := json.Marshal(policy.AllowedPortRanges)
	allowedProtocols, _ := json.Marshal(policy.AllowedProtocols)
	allowedTargets, _ := json.Marshal(policy.AllowedTargetCIDRs)
	deniedTargets, _ := json.Marshal(policy.DeniedTargetCIDRs)
	now := time.Now().UTC()
	result, err := s.pool.Exec(ctx, `
UPDATE tenant_policies SET
    allowed_ingress_nodes=$2,allowed_exit_nodes=$3,allowed_listen_ips=$4,allowed_port_ranges=$5,
    allowed_protocols=$6,allow_via_exit=$7,max_forwards=$8,ingress_rate_limit_bps=$9,
    egress_rate_limit_bps=$10,traffic_quota_bytes=$11,allowed_target_cidrs=$12,denied_target_cidrs=$13,
    resource_version=resource_version+1,updated_at=$14
WHERE tenant_id=$1 AND resource_version=$15`, policy.TenantID, allowedIngress, allowedExit, allowedListen, allowedPorts,
		allowedProtocols, policy.AllowViaExit, policy.MaxForwards, policy.IngressRateLimitBPS,
		policy.EgressRateLimitBPS, policy.TrafficQuotaBytes, allowedTargets, deniedTargets, now, policy.ResourceVersion)
	if err != nil {
		return iam.Policy{}, fmt.Errorf("update tenant policy: %w", err)
	}
	if result.RowsAffected() != 1 {
		if _, lookupErr := s.TenantPolicy(ctx, policy.TenantID); errors.Is(lookupErr, iam.ErrNotFound) {
			return iam.Policy{}, lookupErr
		}
		return iam.Policy{}, iam.ErrConflict
	}
	return s.TenantPolicy(ctx, policy.TenantID)
}

func (s *Store) validatePolicyNodes(ctx context.Context, policy iam.Policy) error {
	return validatePolicyNodesQuery(ctx, s.pool, policy)
}

func validatePolicyNodesQuery(ctx context.Context, source queryer, policy iam.Policy) error {
	seen := make(map[string]bool)
	for _, nodeID := range append(append([]string{}, policy.AllowedIngressNodes...), policy.AllowedExitNodes...) {
		if seen[nodeID] {
			continue
		}
		seen[nodeID] = true
		var exists bool
		if err := source.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1 AND revoked_at IS NULL)`, nodeID).Scan(&exists); err != nil {
			return fmt.Errorf("validate tenant node grant: %w", err)
		}
		if !exists {
			return fmt.Errorf("assigned node %q does not exist or is revoked", nodeID)
		}
	}
	return nil
}

func (s *Store) AccountByUsername(ctx context.Context, username string) (iam.Account, error) {
	username, err := iam.NormalizeUsername(username)
	if err != nil {
		return iam.Account{}, iam.ErrUnauthenticated
	}
	return scanAccount(s.pool.QueryRow(ctx, accountSelect+` WHERE a.username=$1`, username))
}

func (s *Store) AccountByID(ctx context.Context, accountID string) (iam.Account, error) {
	if err := iam.ValidateInternalID("account_id", accountID); err != nil {
		return iam.Account{}, err
	}
	return scanAccount(s.pool.QueryRow(ctx, accountSelect+` WHERE a.id=$1`, accountID))
}

func (s *Store) TenantAccountByTenantID(ctx context.Context, tenantID string) (iam.Account, error) {
	if err := iam.ValidateInternalID("tenant_id", tenantID); err != nil {
		return iam.Account{}, err
	}
	return scanAccount(s.pool.QueryRow(ctx, accountSelect+` WHERE a.tenant_id=$1 AND a.role='tenant'`, tenantID))
}

func (s *Store) ReplaceAccountPassword(ctx context.Context, accountID, passwordHash string, expectedVersion uint64) (iam.Account, error) {
	if err := iam.ValidateInternalID("account_id", accountID); err != nil {
		return iam.Account{}, err
	}
	if len(passwordHash) < 32 || len(passwordHash) > 512 {
		return iam.Account{}, errors.New("account password hash is invalid")
	}
	if expectedVersion == 0 {
		return iam.Account{}, errors.New("account resource_version is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return iam.Account{}, fmt.Errorf("begin password replacement: %w", err)
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	result, err := tx.Exec(ctx, `
UPDATE accounts
SET password_hash=$2,failed_login_count=0,locked_until=NULL,resource_version=resource_version+1,updated_at=$3
WHERE id=$1 AND resource_version=$4`, accountID, passwordHash, now, expectedVersion)
	if err != nil {
		return iam.Account{}, fmt.Errorf("replace account password: %w", err)
	}
	if result.RowsAffected() != 1 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1)`, accountID).Scan(&exists); err != nil {
			return iam.Account{}, fmt.Errorf("check password account: %w", err)
		}
		if !exists {
			return iam.Account{}, iam.ErrNotFound
		}
		return iam.Account{}, iam.ErrConflict
	}
	if _, err := tx.Exec(ctx, `
UPDATE management_sessions SET revoked_at=$2
WHERE account_id=$1 AND revoked_at IS NULL`, accountID, now); err != nil {
		return iam.Account{}, fmt.Errorf("revoke sessions after password replacement: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return iam.Account{}, fmt.Errorf("commit password replacement: %w", err)
	}
	return s.AccountByID(ctx, accountID)
}

func (s *Store) RecordLoginFailure(ctx context.Context, accountID string, now time.Time) error {
	lockUntil := now.UTC().Add(15 * time.Minute)
	_, err := s.pool.Exec(ctx, `
UPDATE accounts SET failed_login_count=failed_login_count+1,
    locked_until=CASE WHEN failed_login_count+1 >= 5 THEN $2 ELSE locked_until END,
    updated_at=$1
WHERE id=$3`, now.UTC(), lockUntil, accountID)
	if err != nil {
		return fmt.Errorf("record login failure: %w", err)
	}
	return nil
}

func (s *Store) RecordLoginSuccess(ctx context.Context, accountID string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
UPDATE accounts SET failed_login_count=0,locked_until=NULL,last_login_at=$2,updated_at=$2 WHERE id=$1`, accountID, now.UTC())
	if err != nil {
		return fmt.Errorf("record login success: %w", err)
	}
	return nil
}

func (s *Store) CreateManagementSession(ctx context.Context, accountID string, ttl time.Duration, remoteIP, userAgent string) (string, string, iam.Session, error) {
	if ttl < 5*time.Minute || ttl > 30*24*time.Hour {
		return "", "", iam.Session{}, errors.New("management session TTL must be between five minutes and 30 days")
	}
	account, err := s.AccountByID(ctx, accountID)
	if err != nil {
		return "", "", iam.Session{}, err
	}
	now := time.Now().UTC()
	if err := account.Available(now); err != nil {
		return "", "", iam.Session{}, err
	}
	if account.Role == iam.RoleTenant {
		tenant, err := s.TenantByID(ctx, account.TenantID)
		if err != nil || tenant.Status != iam.StatusActive || tenant.ExpiresAt != nil && !now.Before(*tenant.ExpiresAt) {
			return "", "", iam.Session{}, iam.ErrUnauthenticated
		}
	}
	token, tokenHash, err := iam.NewSecret()
	if err != nil {
		return "", "", iam.Session{}, err
	}
	csrf, csrfHash, err := iam.NewSecret()
	if err != nil {
		return "", "", iam.Session{}, err
	}
	expiresAt := now.Add(ttl)
	if account.ExpiresAt != nil && expiresAt.After(*account.ExpiresAt) {
		expiresAt = *account.ExpiresAt
	}
	if _, err := s.pool.Exec(ctx, `
INSERT INTO management_sessions(token_hash,csrf_hash,account_id,expires_at,created_at,last_seen_at,remote_ip,user_agent)
VALUES ($1,$2,$3,$4,$5,$5,$6,$7)`, tokenHash[:], csrfHash[:], accountID, expiresAt, now, truncate(remoteIP, 128), truncate(userAgent, 512)); err != nil {
		return "", "", iam.Session{}, fmt.Errorf("create management session: %w", err)
	}
	return token, csrf, iam.Session{Account: account, CSRFHash: csrfHash, ExpiresAt: expiresAt}, nil
}

func (s *Store) ManagementSession(ctx context.Context, rawToken string, now time.Time) (iam.Session, error) {
	if len(rawToken) < 32 || len(rawToken) > 128 {
		return iam.Session{}, iam.ErrUnauthenticated
	}
	hash := iam.HashSecret(rawToken)
	var csrf []byte
	var sessionExpires time.Time
	var tenantStatus sql.NullString
	var tenantExpires sql.NullTime
	account, err := scanAccountExtra(s.pool.QueryRow(ctx, `SELECT `+accountSelectColumns+`,s.csrf_hash,s.expires_at,t.status,t.expires_at
FROM accounts a
JOIN management_sessions s ON s.account_id=a.id
LEFT JOIN tenants t ON t.id=a.tenant_id
WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>$2`, hash[:], now.UTC()), &csrf, &sessionExpires, &tenantStatus, &tenantExpires)
	if err != nil {
		if errors.Is(err, iam.ErrNotFound) {
			return iam.Session{}, iam.ErrUnauthenticated
		}
		return iam.Session{}, err
	}
	if err := account.Available(now.UTC()); err != nil || account.Role == iam.RoleTenant && (tenantStatus.String != string(iam.StatusActive) || tenantExpires.Valid && !now.UTC().Before(tenantExpires.Time)) {
		return iam.Session{}, iam.ErrUnauthenticated
	}
	if len(csrf) != 32 {
		return iam.Session{}, iam.ErrUnauthenticated
	}
	var csrfHash [32]byte
	copy(csrfHash[:], csrf)
	_, _ = s.pool.Exec(ctx, `UPDATE management_sessions SET last_seen_at=$2 WHERE token_hash=$1 AND last_seen_at<$3`, hash[:], now.UTC(), now.UTC().Add(-5*time.Minute))
	return iam.Session{Account: account, CSRFHash: csrfHash, ExpiresAt: sessionExpires}, nil
}

func (s *Store) RevokeManagementSession(ctx context.Context, rawToken string, now time.Time) error {
	hash := iam.HashSecret(rawToken)
	_, err := s.pool.Exec(ctx, `UPDATE management_sessions SET revoked_at=$2 WHERE token_hash=$1 AND revoked_at IS NULL`, hash[:], now.UTC())
	if err != nil {
		return fmt.Errorf("revoke management session: %w", err)
	}
	return nil
}

func (s *Store) RecordManagementAudit(ctx context.Context, event iam.AuditEvent) error {
	if event.Action == "" || len(event.Action) > 128 || event.ResourceType == "" || len(event.ResourceType) > 64 {
		return errors.New("management audit event is invalid")
	}
	if event.Outcome != "success" && event.Outcome != "denied" && event.Outcome != "error" {
		return errors.New("management audit outcome is invalid")
	}
	detail := event.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("encode management audit detail: %w", err)
	}
	if len(encoded) > 64<<10 {
		return errors.New("management audit detail is too large")
	}
	var actor any
	if event.ActorAccountID != "" {
		actor = event.ActorAccountID
	}
	var tenant any
	if event.TenantID != "" {
		tenant = event.TenantID
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO management_audit_events(actor_account_id,actor_username,actor_role,tenant_id,action,resource_type,resource_id,outcome,source_ip,detail)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, actor, truncate(event.ActorUsername, 64), event.ActorRole, tenant,
		event.Action, event.ResourceType, truncate(event.ResourceID, 128), event.Outcome, truncate(event.SourceIP, 128), encoded)
	if err != nil {
		return fmt.Errorf("record management audit: %w", err)
	}
	return nil
}

func (s *Store) ListManagementAudit(ctx context.Context, limit, offset int) ([]iam.AuditEvent, error) {
	if limit <= 0 || limit > maxAuditPageSize {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.pool.Query(ctx, `
SELECT id,actor_account_id,actor_username,actor_role,tenant_id,action,resource_type,resource_id,outcome,source_ip,detail,created_at
FROM management_audit_events ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list management audit: %w", err)
	}
	defer rows.Close()
	result := make([]iam.AuditEvent, 0)
	for rows.Next() {
		var event iam.AuditEvent
		var actorID, tenantID sql.NullString
		var role string
		var detail []byte
		if err := rows.Scan(&event.ID, &actorID, &event.ActorUsername, &role, &tenantID, &event.Action, &event.ResourceType,
			&event.ResourceID, &event.Outcome, &event.SourceIP, &detail, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan management audit: %w", err)
		}
		event.ActorAccountID = actorID.String
		event.TenantID = tenantID.String
		event.ActorRole = iam.Role(role)
		if err := json.Unmarshal(detail, &event.Detail); err != nil {
			return nil, fmt.Errorf("decode management audit detail: %w", err)
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

const accountSelectColumns = `a.id,a.tenant_id,a.username,a.display_name,a.role,a.password_hash,a.status,
       a.failed_login_count,a.locked_until,a.expires_at,a.resource_version,a.last_login_at,a.created_at,a.updated_at`

const accountSelect = `SELECT ` + accountSelectColumns + ` FROM accounts a`

type scanner interface {
	Scan(...any) error
}

func scanAccount(source scanner) (iam.Account, error) {
	return scanAccountExtra(source)
}

func scanAccountExtra(source scanner, extra ...any) (iam.Account, error) {
	var account iam.Account
	var lockedUntil, expiresAt, lastLogin sql.NullTime
	var tenantIDString sql.NullString
	var role, status string
	arguments := []any{&account.ID, &tenantIDString, &account.Username, &account.DisplayName, &role, &account.PasswordHash, &status,
		&account.FailedLoginCount, &lockedUntil, &expiresAt, &account.ResourceVersion, &lastLogin, &account.CreatedAt, &account.UpdatedAt}
	arguments = append(arguments, extra...)
	if err := source.Scan(arguments...); errors.Is(err, sql.ErrNoRows) {
		return iam.Account{}, iam.ErrNotFound
	} else if err != nil {
		return iam.Account{}, fmt.Errorf("scan account: %w", err)
	}
	account.TenantID = tenantIDString.String
	account.Role = iam.Role(role)
	account.Status = iam.Status(status)
	if lockedUntil.Valid {
		account.LockedUntil = &lockedUntil.Time
	}
	if expiresAt.Valid {
		account.ExpiresAt = &expiresAt.Time
	}
	if lastLogin.Valid {
		account.LastLoginAt = &lastLogin.Time
	}
	return account, nil
}

func scanTenant(source scanner) (iam.Tenant, error) {
	var tenant iam.Tenant
	var status string
	var expiresAt sql.NullTime
	if err := source.Scan(&tenant.ID, &tenant.Name, &status, &expiresAt, &tenant.ResourceVersion, &tenant.CreatedAt, &tenant.UpdatedAt); errors.Is(err, sql.ErrNoRows) {
		return iam.Tenant{}, iam.ErrNotFound
	} else if err != nil {
		return iam.Tenant{}, fmt.Errorf("scan tenant: %w", err)
	}
	tenant.Status = iam.Status(status)
	if expiresAt.Valid {
		tenant.ExpiresAt = &expiresAt.Time
	}
	return tenant, nil
}

func scanPolicy(source scanner) (iam.Policy, error) {
	var policy iam.Policy
	var allowedIngress, allowedExit, allowedListen, allowedPorts, allowedProtocols, allowedTargets, deniedTargets []byte
	if err := source.Scan(&policy.TenantID, &allowedIngress, &allowedExit, &allowedListen, &allowedPorts, &allowedProtocols,
		&policy.AllowViaExit, &policy.MaxForwards, &policy.IngressRateLimitBPS, &policy.EgressRateLimitBPS,
		&policy.TrafficQuotaBytes, &allowedTargets, &deniedTargets, &policy.ResourceVersion, &policy.CreatedAt, &policy.UpdatedAt); errors.Is(err, sql.ErrNoRows) {
		return iam.Policy{}, iam.ErrNotFound
	} else if err != nil {
		return iam.Policy{}, fmt.Errorf("scan tenant policy: %w", err)
	}
	for _, item := range []struct {
		data   []byte
		target any
	}{
		{allowedIngress, &policy.AllowedIngressNodes}, {allowedExit, &policy.AllowedExitNodes},
		{allowedListen, &policy.AllowedListenIPs}, {allowedPorts, &policy.AllowedPortRanges},
		{allowedProtocols, &policy.AllowedProtocols}, {allowedTargets, &policy.AllowedTargetCIDRs},
		{deniedTargets, &policy.DeniedTargetCIDRs},
	} {
		if err := json.Unmarshal(item.data, item.target); err != nil {
			return iam.Policy{}, fmt.Errorf("decode tenant policy: %w", err)
		}
	}
	return policy, nil
}

func isUniqueViolation(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint") || strings.Contains(message, "constraint failed")
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}
