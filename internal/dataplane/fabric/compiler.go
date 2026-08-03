package fabric

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"

	"flux.local/flux/internal/spec"
)

const (
	CompilerABI       = "fabric-phase4-v1"
	RoutingMarkPrefix = uint32(0x47000000)
	RoutingMarkMask   = uint32(0xffff0000)
	RouteTableBase    = uint32(47000)
	RulePriorityBase  = uint32(20000)
	RouteProtocol     = uint8(186)
	MainRouteTable    = uint32(254)
)

var checksumPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type LinkPlan struct {
	ID           string                  `json:"id"`
	PeerNodeID   string                  `json:"peer_node_id"`
	Transport    spec.FabricTransport    `json:"transport"`
	Interface    string                  `json:"interface"`
	LocalAddress netip.Prefix            `json:"local_address"`
	PeerAddress  netip.Addr              `json:"peer_address"`
	MTU          uint16                  `json:"mtu"`
	RoutingID    uint16                  `json:"routing_id"`
	WireGuard    *spec.WireGuardPeerSpec `json:"wireguard,omitempty"`
	GRE          *spec.GRESpec           `json:"gre,omitempty"`
	AllowedIPs   []netip.Prefix          `json:"allowed_ips,omitempty"`
}

type RoutePlan struct {
	Destination netip.Prefix `json:"destination"`
	Interface   string       `json:"interface"`
	Gateway     *netip.Addr  `json:"gateway,omitempty"`
	Table       uint32       `json:"table"`
	Protocol    uint8        `json:"protocol"`
}

type RulePlan struct {
	Mark     uint32 `json:"mark"`
	Mask     uint32 `json:"mask"`
	Table    uint32 `json:"table"`
	Priority uint32 `json:"priority"`
}

type Program struct {
	Active          bool        `json:"active"`
	Generation      uint64      `json:"generation"`
	DesiredChecksum string      `json:"desired_checksum"`
	Checksum        string      `json:"checksum"`
	Links           []LinkPlan  `json:"links,omitempty"`
	Routes          []RoutePlan `json:"routes,omitempty"`
	Rules           []RulePlan  `json:"rules,omitempty"`
}

type Compiler struct{}

func DefaultCompiler() Compiler { return Compiler{} }

func RoutingMark(routingID uint16) uint32 { return RoutingMarkPrefix | uint32(routingID) }

func RouteTable(routingID uint16) uint32 { return RouteTableBase + uint32(routingID) }

func RulePriority(routingID uint16) uint32 { return RulePriorityBase + uint32(routingID) }

func (Compiler) ProgramChecksum(desiredChecksum string) string {
	value := sha256.Sum256([]byte(CompilerABI + "\n" + desiredChecksum))
	return hex.EncodeToString(value[:])
}

func (c Compiler) Compile(state spec.DesiredState, desiredChecksum string) (Program, error) {
	if err := state.Validate(); err != nil {
		return Program{}, err
	}
	if !checksumPattern.MatchString(desiredChecksum) {
		return Program{}, errors.New("checksum must be a lowercase SHA-256 value")
	}
	calculated, err := state.Checksum()
	if err != nil {
		return Program{}, fmt.Errorf("calculate desired checksum: %w", err)
	}
	if calculated != desiredChecksum {
		return Program{}, errors.New("checksum does not match desired state")
	}

	canonical := state.Canonical()
	program := Program{
		Active:          len(canonical.FabricLinks) != 0,
		Generation:      canonical.Generation,
		DesiredChecksum: desiredChecksum,
	}
	links := make(map[string]int, len(canonical.FabricLinks))
	allowed := make(map[string]map[netip.Prefix]struct{}, len(canonical.FabricLinks))
	for _, link := range canonical.FabricLinks {
		plan := LinkPlan{
			ID: link.ID, PeerNodeID: link.PeerNodeID, Transport: link.Transport,
			Interface: link.Interface, LocalAddress: link.LocalAddress,
			PeerAddress: link.PeerAddress, MTU: link.MTU, RoutingID: link.RoutingID,
			WireGuard: copyWireGuard(link.WireGuard), GRE: copyGRE(link.GRE),
		}
		program.Links = append(program.Links, plan)
		links[link.ID] = len(program.Links) - 1
		allowed[link.ID] = map[netip.Prefix]struct{}{hostPrefix(link.PeerAddress): {}}
	}

	routes := make(map[string]RoutePlan)
	rules := make(map[uint16]RulePlan)
	for _, forward := range canonical.Forwards {
		if forward.PathMode != spec.PathViaExit {
			continue
		}
		link := &program.Links[links[forward.FabricLinkID]]
		if canonical.NodeID == forward.IngressNodeID {
			vip := hostPrefix(*forward.ServiceVIP)
			allowed[link.ID][vip] = struct{}{}
			gateway := link.PeerAddress
			route := RoutePlan{Destination: vip, Interface: link.Interface, Gateway: &gateway, Table: MainRouteTable, Protocol: RouteProtocol}
			routes[routeKey(route)] = route
			continue
		}
		peerRoute := RoutePlan{Destination: hostPrefix(link.PeerAddress), Interface: link.Interface, Table: RouteTable(link.RoutingID), Protocol: RouteProtocol}
		routes[routeKey(peerRoute)] = peerRoute
		rules[link.RoutingID] = RulePlan{Mark: RoutingMark(link.RoutingID), Mask: ^uint32(0), Table: RouteTable(link.RoutingID), Priority: RulePriority(link.RoutingID)}
	}

	for i := range program.Links {
		for prefix := range allowed[program.Links[i].ID] {
			program.Links[i].AllowedIPs = append(program.Links[i].AllowedIPs, prefix)
		}
		sort.Slice(program.Links[i].AllowedIPs, func(a, b int) bool {
			return program.Links[i].AllowedIPs[a].String() < program.Links[i].AllowedIPs[b].String()
		})
	}
	for _, route := range routes {
		program.Routes = append(program.Routes, route)
	}
	sort.Slice(program.Routes, func(i, j int) bool { return routeKey(program.Routes[i]) < routeKey(program.Routes[j]) })
	for _, rule := range rules {
		program.Rules = append(program.Rules, rule)
	}
	sort.Slice(program.Rules, func(i, j int) bool { return program.Rules[i].Priority < program.Rules[j].Priority })
	material, err := json.Marshal(struct {
		Links  []LinkPlan  `json:"links"`
		Routes []RoutePlan `json:"routes"`
		Rules  []RulePlan  `json:"rules"`
	}{program.Links, program.Routes, program.Rules})
	if err != nil {
		return Program{}, fmt.Errorf("encode fabric program: %w", err)
	}
	digest := sha256.Sum256(append([]byte(CompilerABI+"\n"), material...))
	program.Checksum = hex.EncodeToString(digest[:])
	return program, nil
}

func hostPrefix(address netip.Addr) netip.Prefix {
	return netip.PrefixFrom(address.Unmap(), 32)
}

func routeKey(route RoutePlan) string {
	gateway := ""
	if route.Gateway != nil {
		gateway = route.Gateway.String()
	}
	return fmt.Sprintf("%010d|%s|%s|%s", route.Table, route.Destination, route.Interface, gateway)
}

func copyWireGuard(value *spec.WireGuardPeerSpec) *spec.WireGuardPeerSpec {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func copyGRE(value *spec.GRESpec) *spec.GRESpec {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

// MarshalPlan is used by the CLI without exposing private key material.
func MarshalPlan(program Program) ([]byte, error) {
	return json.MarshalIndent(program, "", "  ")
}
