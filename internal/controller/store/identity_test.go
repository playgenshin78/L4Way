package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"flux.local/flux/internal/controller/iam"
	"flux.local/flux/internal/spec"
)

func TestIdentityTenantPolicySessionAndAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "flux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var migrationCount int
	if err := repository.pool.QueryRow(ctx, `SELECT COUNT(*) FROM flux_schema_migrations`).Scan(&migrationCount); err != nil || migrationCount != 2 {
		t.Fatalf("migration count = %d, err = %v", migrationCount, err)
	}

	ownerHash, err := iam.HashPassword("owner-password-for-tests")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := repository.CreateOwner(ctx, "Owner", "Primary Owner", ownerHash)
	if err != nil {
		t.Fatal(err)
	}
	if owner.Username != "owner" || owner.Role != iam.RoleOwner {
		t.Fatalf("owner = %+v", owner)
	}
	if _, err := repository.CreateOwner(ctx, "owner-2", "Other Owner", ownerHash); !errors.Is(err, iam.ErrConflict) {
		t.Fatalf("second Owner error = %v, want conflict", err)
	}

	tenantHash, err := iam.HashPassword("tenant-password-for-tests")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour)
	tenant, tenantAccount, policy, err := repository.CreateTenant(ctx, TenantCreate{
		ID: "tenant-a", Name: "Tenant A", Username: "tenant-a", DisplayName: "Tenant A", PasswordHash: tenantHash, ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tenantAccount.TenantID != tenant.ID || tenantAccount.Role != iam.RoleTenant || policy.MaxForwards != 0 {
		t.Fatalf("tenant=%+v account=%+v policy=%+v", tenant, tenantAccount, policy)
	}

	for _, nodeID := range []string{"node-a", "node-b"} {
		if _, _, err := repository.CreateEnrollmentToken(ctx, nodeID, 10*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	initialPolicy := iam.EmptyPolicy("")
	initialPolicy.AllowedIngressNodes = []string{"node-a"}
	initialPolicy.AllowedListenIPs = []string{"198.51.100.20"}
	initialPolicy.AllowedPortRanges = []iam.PortRange{{Start: 30000, End: 30100}}
	initialPolicy.AllowedProtocols = []spec.Protocol{spec.ProtocolTCP}
	initialPolicy.MaxForwards = 2
	initialPolicy.AllowedTargetCIDRs = []string{"192.0.2.0/24"}
	initialTenant, initialAccount, createdPolicy, err := repository.CreateTenant(ctx, TenantCreate{
		ID: "tenant-b", Name: "Tenant B", Username: "tenant-b", DisplayName: "Tenant B",
		PasswordHash: tenantHash, InitialPolicy: &initialPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if createdPolicy.TenantID != initialTenant.ID || createdPolicy.MaxForwards != 2 ||
		len(createdPolicy.AllowedIngressNodes) != 1 || initialAccount.TenantID != initialTenant.ID {
		t.Fatalf("atomic initial tenant policy was not preserved: tenant=%+v account=%+v policy=%+v", initialTenant, initialAccount, createdPolicy)
	}
	policy.AllowedIngressNodes = []string{"node-a"}
	policy.AllowedExitNodes = []string{"node-b"}
	policy.AllowedListenIPs = []string{"198.51.100.10"}
	policy.AllowedPortRanges = []iam.PortRange{{Start: 10000, End: 20000}}
	policy.AllowedProtocols = []spec.Protocol{spec.ProtocolUDP, spec.ProtocolTCP}
	policy.AllowViaExit = true
	policy.MaxForwards = 4
	policy.AllowedTargetCIDRs = []string{"10.0.0.0/8"}
	updatedPolicy, err := repository.UpdateTenantPolicy(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	if updatedPolicy.ResourceVersion != 2 || updatedPolicy.AllowedProtocols[0] != spec.ProtocolTCP {
		t.Fatalf("updated policy = %+v", updatedPolicy)
	}
	if _, err := repository.UpdateTenantPolicy(ctx, policy); !errors.Is(err, iam.ErrConflict) {
		t.Fatalf("stale policy error = %v, want conflict", err)
	}

	token, csrf, session, err := repository.CreateManagementSession(ctx, owner.ID, time.Hour, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.ManagementSession(ctx, token, time.Now().UTC())
	if err != nil || loaded.Account.ID != owner.ID || loaded.CSRFHash != iam.HashSecret(csrf) || session.ExpiresAt.IsZero() {
		t.Fatalf("loaded session = %+v, err = %v", loaded, err)
	}
	if err := repository.RevokeManagementSession(ctx, token, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ManagementSession(ctx, token, time.Now().UTC()); !errors.Is(err, iam.ErrUnauthenticated) {
		t.Fatalf("revoked session error = %v", err)
	}
	passwordToken, _, _, err := repository.CreateManagementSession(ctx, owner.ID, time.Hour, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	replacementHash, err := iam.HashPassword("replacement-owner-password")
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := repository.ReplaceAccountPassword(ctx, owner.ID, replacementHash, owner.ResourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ResourceVersion != owner.ResourceVersion+1 || !iam.VerifyPassword(replaced.PasswordHash, "replacement-owner-password") {
		t.Fatalf("replaced account = %+v", replaced)
	}
	if _, err := repository.ManagementSession(ctx, passwordToken, time.Now().UTC()); !errors.Is(err, iam.ErrUnauthenticated) {
		t.Fatalf("password replacement did not revoke session: %v", err)
	}

	tenantToken, _, _, err := repository.CreateManagementSession(ctx, tenantAccount.ID, time.Hour, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.UpdateTenant(ctx, tenant.ID, tenant.Name, iam.StatusDisabled, tenant.ExpiresAt, tenant.ResourceVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ManagementSession(ctx, tenantToken, time.Now().UTC()); !errors.Is(err, iam.ErrUnauthenticated) {
		t.Fatalf("disabled tenant session error = %v", err)
	}

	if err := repository.RecordManagementAudit(ctx, iam.AuditEvent{ActorAccountID: owner.ID, ActorUsername: owner.Username, ActorRole: owner.Role,
		Action: "tenant.create", ResourceType: "tenant", ResourceID: tenant.ID, Outcome: "success", Detail: map[string]any{"test": true}}); err != nil {
		t.Fatal(err)
	}
	events, err := repository.ListManagementAudit(ctx, 10, 0)
	if err != nil || len(events) != 1 || events[0].ResourceID != tenant.ID {
		t.Fatalf("audit events = %+v, err = %v", events, err)
	}

	for index := 0; index < 5; index++ {
		if err := repository.RecordLoginFailure(ctx, owner.ID, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	locked, err := repository.AccountByID(ctx, owner.ID)
	if err != nil || locked.LockedUntil == nil || locked.Available(time.Now().UTC()) == nil {
		t.Fatalf("locked account = %+v, err = %v", locked, err)
	}
}
