package targetdns

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestCacheRefreshesAndKeepsLastKnownGood(t *testing.T) {
	now := time.Unix(1_000, 0).UTC()
	answers := []struct {
		address netip.Addr
		err     error
	}{
		{address: netip.MustParseAddr("198.51.100.20")},
		{err: errors.New("temporary DNS failure")},
	}
	lookups := 0
	cache := NewCache(func(context.Context, string) (netip.Addr, error) {
		answer := answers[lookups]
		lookups++
		return answer.address, answer.err
	}, time.Minute, time.Second, func() time.Time { return now })

	address, err := cache.Resolve(context.Background(), "example.com", netip.MustParseAddr("192.0.2.10"))
	if err != nil || address.String() != "198.51.100.20" {
		t.Fatalf("first resolution = %s, %v", address, err)
	}
	now = now.Add(61 * time.Second)
	address, err = cache.Resolve(context.Background(), "example.com", netip.MustParseAddr("192.0.2.10"))
	if err == nil || address.String() != "198.51.100.20" {
		t.Fatalf("last-known-good resolution = %s, %v", address, err)
	}
}

func TestCacheUsesDurableFallbackOnInitialFailure(t *testing.T) {
	cache := NewCache(func(context.Context, string) (netip.Addr, error) {
		return netip.Addr{}, errors.New("offline")
	}, time.Minute, time.Second, time.Now)
	address, err := cache.Resolve(context.Background(), "example.com", netip.MustParseAddr("192.0.2.30"))
	if err == nil || address.String() != "192.0.2.30" {
		t.Fatalf("fallback resolution = %s, %v", address, err)
	}
}
