package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"flux.local/flux/internal/cluster"
	"flux.local/flux/internal/controller/iam"
	"flux.local/flux/internal/spec"
	"flux.local/flux/internal/targetdns"
)

func TestResolvePlanTargetsRefreshesOwnerDomainWithoutPublishingHostname(t *testing.T) {
	ctx := context.Background()
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "flux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000, 0).UTC()
	repository.targetDNS = targetdns.NewCache(func(context.Context, string) (netip.Addr, error) {
		return netip.MustParseAddr("198.51.100.77"), nil
	}, time.Minute, time.Second, func() time.Time { return now })
	plan := cluster.Plan{
		BackendPools: []cluster.BackendPool{{ID: "pool", Backends: []cluster.Backend{{
			ID: "primary", Target: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Hostname: "example.com", Port: 443},
		}}}},
		Forwards: []cluster.Forward{{ID: "forward", UserID: "owner", BackendPoolID: "pool"}},
	}
	resolved, err := repository.resolvePlanTargets(ctx, repository.pool, plan)
	if err != nil {
		t.Fatal(err)
	}
	target := resolved.BackendPools[0].Backends[0].Target
	if target.Address.String() != "198.51.100.77" || target.Hostname != "" {
		t.Fatalf("resolved target = %+v", target)
	}
	if plan.BackendPools[0].Backends[0].Target.Hostname != "example.com" {
		t.Fatal("durable plan hostname was mutated")
	}
}

func TestResolvePlanTargetsKeepsAllowedFallbackWhenDNSMovesOutsideTenantPolicy(t *testing.T) {
	ctx := context.Background()
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "flux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	policy := iam.EmptyPolicy("tenant_dns")
	policy.AllowedTargetCIDRs = []string{"192.0.2.0/24"}
	if _, _, _, err := repository.CreateTenant(ctx, TenantCreate{
		ID: "tenant_dns", Name: "DNS tenant", Username: "dns-user", DisplayName: "DNS user",
		PasswordHash: "0123456789abcdef0123456789abcdef", InitialPolicy: &policy,
	}); err != nil {
		t.Fatal(err)
	}
	repository.targetDNS = targetdns.NewCache(func(context.Context, string) (netip.Addr, error) {
		return netip.MustParseAddr("198.51.100.77"), nil
	}, time.Minute, time.Second, time.Now)
	plan := cluster.Plan{
		BackendPools: []cluster.BackendPool{{ID: "pool", Backends: []cluster.Backend{{
			ID: "primary", Target: spec.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Hostname: "example.com", Port: 443},
		}}}},
		Forwards: []cluster.Forward{{ID: "forward", UserID: "tenant_dns", BackendPoolID: "pool"}},
	}

	resolved, err := repository.resolvePlanTargets(ctx, repository.pool, plan)
	if err != nil {
		t.Fatal(err)
	}
	target := resolved.BackendPools[0].Backends[0].Target
	if target.Address.String() != "192.0.2.10" || target.Hostname != "" {
		t.Fatalf("policy fallback target = %+v", target)
	}
}
