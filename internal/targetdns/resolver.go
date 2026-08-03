package targetdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type LookupFunc func(context.Context, string) (netip.Addr, error)

// LookupIPv4 resolves one stable IPv4 address. Sorting prevents DNS response
// order from acting as implicit load balancing or multi-target failover.
func LookupIPv4(ctx context.Context, hostname string) (netip.Addr, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", hostname)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve %s: %w", hostname, err)
	}
	usable := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.IsValid() && address.Is4() && !address.IsUnspecified() && !address.IsMulticast() {
			usable = append(usable, address)
		}
	}
	if len(usable) == 0 {
		return netip.Addr{}, errors.New("hostname has no usable IPv4 address")
	}
	sort.Slice(usable, func(i, j int) bool { return usable[i].Less(usable[j]) })
	return usable[0], nil
}

type cacheEntry struct {
	address      netip.Addr
	refreshAfter time.Time
}

// Cache periodically refreshes DNS while retaining a last-known-good address
// across transient resolver failures. The durable plan address is the fallback
// after Controller restart.
type Cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	lookup  LookupFunc
	refresh time.Duration
	timeout time.Duration
	now     func() time.Time
}

func NewCache(lookup LookupFunc, refresh, timeout time.Duration, now func() time.Time) *Cache {
	if lookup == nil {
		lookup = LookupIPv4
	}
	if refresh <= 0 {
		refresh = time.Minute
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &Cache{entries: make(map[string]cacheEntry), lookup: lookup, refresh: refresh, timeout: timeout, now: now}
}

// Resolve returns a concrete IPv4 address. A non-nil error means the returned
// value came from the cache or fallback and should remain in service.
func (c *Cache) Resolve(ctx context.Context, hostname string, fallback netip.Addr) (netip.Addr, error) {
	now := c.now().UTC()
	c.mu.Lock()
	entry, exists := c.entries[hostname]
	if exists && now.Before(entry.refreshAfter) {
		c.mu.Unlock()
		return entry.address, nil
	}
	c.mu.Unlock()

	lookupContext, cancel := context.WithTimeout(ctx, c.timeout)
	address, err := c.lookup(lookupContext, hostname)
	cancel()
	if err == nil && address.IsValid() && address.Unmap().Is4() {
		address = address.Unmap()
		c.mu.Lock()
		c.entries[hostname] = cacheEntry{address: address, refreshAfter: now.Add(c.refresh)}
		c.mu.Unlock()
		return address, nil
	}
	if err == nil {
		err = errors.New("resolver returned a non-IPv4 address")
	}

	address = fallback.Unmap()
	if exists && entry.address.IsValid() {
		address = entry.address
	}
	retry := c.refresh / 4
	if retry <= 0 || retry > 15*time.Second {
		retry = 15 * time.Second
	}
	c.mu.Lock()
	c.entries[hostname] = cacheEntry{address: address, refreshAfter: now.Add(retry)}
	c.mu.Unlock()
	return address, err
}
