package management

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestResolveForwardTargetAcceptsIPv4AndDomain(t *testing.T) {
	server := &Server{config: Config{
		TargetResolveTimeout: time.Second,
		ResolveTargetIPv4: func(_ context.Context, hostname string) (netip.Addr, error) {
			if hostname != "example.com" {
				return netip.Addr{}, errors.New("unexpected hostname")
			}
			return netip.MustParseAddr("198.51.100.44"), nil
		},
	}}

	domain, err := server.resolveForwardTarget(context.Background(), forwardEndpointPayload{Address: "Example.COM.", Port: 443})
	if err != nil || domain.Hostname != "example.com" || domain.Address.String() != "198.51.100.44" {
		t.Fatalf("domain target = %+v, %v", domain, err)
	}
	ip, err := server.resolveForwardTarget(context.Background(), forwardEndpointPayload{Address: "192.0.2.20", Port: 80})
	if err != nil || ip.Hostname != "" || ip.Address.String() != "192.0.2.20" {
		t.Fatalf("IP target = %+v, %v", ip, err)
	}
	if _, err := server.resolveForwardTarget(context.Background(), forwardEndpointPayload{Address: "2001:db8::1", Port: 443}); err == nil {
		t.Fatal("IPv6 target was accepted")
	}
}
