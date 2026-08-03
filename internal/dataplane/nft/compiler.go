package nft

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"flux.local/flux/internal/dataplane/fabric"
	"flux.local/flux/internal/spec"
)

const (
	TableFamily = "inet"
	TableName   = "flux"
	CompilerABI = "nft-phase4-v3"

	// HTTPS application identifiers are normally present near the start of a
	// TLS ClientHello. nft's raw payload offset is limited to 255 bytes, so the
	// bounded scan stays within that ABI. It is entered only for a valid
	// ClientHello on a Flux-managed TCP connection.
	httpsALPNScanBytes = 256

	// Flux owns the complete skb mark on traffic matched by one of its
	// listeners. The prefix makes accidental classification easy to spot and
	// the low 16 bits carry the Controller-allocated tc class minor.
	TrafficMarkPrefix uint32 = 0x46000000
)

var checksumPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var (
	ErrUnsupported     = errors.New("desired state uses a capability not implemented by this dataplane")
	ErrUnresolvedClass = errors.New("rate-limited policy has no allocated traffic class")
)

type CounterBinding struct {
	Name            string                `json:"name"`
	ForwardID       string                `json:"forward_id"`
	Protocol        spec.Protocol         `json:"protocol"`
	Direction       spec.TrafficDirection `json:"direction"`
	ResourceVersion uint64                `json:"resource_version"`
}

type Program struct {
	Generation      uint64           `json:"generation"`
	DesiredChecksum string           `json:"desired_checksum"`
	ProgramChecksum string           `json:"program_checksum"`
	Script          string           `json:"-"`
	Counters        []CounterBinding `json:"counters"`
}

type Compiler struct{}

func DefaultCompiler() Compiler { return Compiler{} }

type protocolElements struct {
	managed          []string
	paused           []string
	draining         []string
	dnatAddresses    []string
	dnatPorts        []string
	marks            []string
	routeMarks       []string
	masquerade       []string
	snat             []string
	mssClamp         []string
	uploadCounters   []string
	downloadCounters []string
}

func TrafficMark(classID uint16) uint32 {
	return TrafficMarkPrefix | uint32(classID)
}

// ProgramChecksum is retained for snapshots without wall-clock transitions.
func (Compiler) ProgramChecksum(desiredChecksum string) string {
	return checksum(CompilerABI + "\n" + desiredChecksum)
}

func (c Compiler) ProgramChecksumAt(state spec.DesiredState, desiredChecksum string, now time.Time) string {
	fingerprint := runtimeFingerprint(state, now)
	if fingerprint == "" {
		return c.ProgramChecksum(desiredChecksum)
	}
	return checksum(CompilerABI + "\n" + desiredChecksum + "\n" + fingerprint)
}

func (c Compiler) Compile(state spec.DesiredState, desiredChecksum string, tableExists bool) (Program, error) {
	return c.CompileAt(state, desiredChecksum, tableExists, time.Now().UTC())
}

func (c Compiler) CompileAt(state spec.DesiredState, desiredChecksum string, tableExists bool, now time.Time) (Program, error) {
	if err := state.Validate(); err != nil {
		return Program{}, err
	}
	if !checksumPattern.MatchString(desiredChecksum) {
		return Program{}, errors.New("checksum must be a lowercase SHA-256 value")
	}
	calculatedChecksum, err := state.Checksum()
	if err != nil {
		return Program{}, fmt.Errorf("calculate desired checksum: %w", err)
	}
	if desiredChecksum != calculatedChecksum {
		return Program{}, errors.New("checksum does not match desired state")
	}

	canonical := state.Canonical()
	policies := make(map[string]spec.UserPolicySpec, len(canonical.UserPolicies))
	for _, policy := range canonical.UserPolicies {
		policies[policy.UserID] = policy
	}
	fabrics := make(map[string]spec.FabricLinkSpec, len(canonical.FabricLinks))
	for _, link := range canonical.FabricLinks {
		fabrics[link.ID] = link
	}
	byProtocol := map[spec.Protocol]*protocolElements{
		spec.ProtocolTCP: {},
		spec.ProtocolUDP: {},
	}
	program := Program{
		Generation:      state.Generation,
		DesiredChecksum: desiredChecksum,
		ProgramChecksum: c.ProgramChecksumAt(canonical, desiredChecksum, now),
	}

	for _, forward := range canonical.Forwards {
		isIngress := canonical.NodeID == forward.IngressNodeID
		classID := uint16(0)
		if isIngress {
			classID, err = forwardingClass(forward, policies[forward.UserID])
			if err != nil {
				return Program{}, err
			}
		}
		effective := forward.EffectiveLifecycle(now)

		for _, protocol := range forward.Protocols {
			elements := byProtocol[protocol]
			keyAddress := forward.Listen.Address.Unmap()
			keyPort := forward.Listen.Port
			targetAddress := forward.Target.Address.Unmap()
			targetPort := forward.Target.Port
			var transportSNAT *spec.FabricLinkSpec
			if forward.PathMode == spec.PathViaExit {
				link, exists := fabrics[forward.FabricLinkID]
				if !exists {
					return Program{}, fmt.Errorf("%w: forward %s fabric link is unresolved", ErrUnsupported, forward.ID)
				}
				if isIngress {
					targetAddress = forward.ServiceVIP.Unmap()
					transportSNAT = &link
				} else {
					keyAddress = forward.ServiceVIP.Unmap()
					keyPort = forward.Target.Port
				}
				elements.mssClamp = append(elements.mssClamp, fmt.Sprintf("%s . %d", keyAddress, keyPort))
			}
			key := fmt.Sprintf("%s . %d", keyAddress, keyPort)
			uploadName := stableCounterName(forward.ID, protocol, spec.DirectionUpload)
			downloadName := stableCounterName(forward.ID, protocol, spec.DirectionDownload)

			elements.managed = append(elements.managed, key)
			elements.dnatAddresses = append(elements.dnatAddresses, key+" : "+targetAddress.String())
			elements.dnatPorts = append(elements.dnatPorts, fmt.Sprintf("%s : %d", key, targetPort))
			if isIngress {
				elements.uploadCounters = append(elements.uploadCounters, key+" : \""+uploadName+"\"")
				elements.downloadCounters = append(elements.downloadCounters, key+" : \""+downloadName+"\"")
			}
			if isIngress && classID != 0 {
				elements.marks = append(elements.marks, fmt.Sprintf("%s : 0x%08x", key, TrafficMark(classID)))
			}
			if !isIngress && forward.PathMode == spec.PathViaExit {
				link := fabrics[forward.FabricLinkID]
				elements.routeMarks = append(elements.routeMarks, fmt.Sprintf("%s : 0x%08x", key, fabric.RoutingMark(link.RoutingID)))
			}
			if transportSNAT != nil {
				elements.snat = append(elements.snat, fmt.Sprintf("%s : %s", key, transportSNAT.LocalAddress.Addr().Unmap()))
			} else if forward.SNAT.Mode == spec.SNATStatic {
				elements.snat = append(elements.snat, fmt.Sprintf("%s : %s", key, forward.SNAT.Address.Unmap()))
			} else {
				elements.masquerade = append(elements.masquerade, key)
			}
			switch effective {
			case spec.LifecyclePaused, spec.LifecycleForceDeleting:
				elements.paused = append(elements.paused, key)
			case spec.LifecycleDraining:
				elements.draining = append(elements.draining, key)
			}
			if isIngress {
				program.Counters = append(program.Counters,
					CounterBinding{Name: uploadName, ForwardID: forward.ID, Protocol: protocol, Direction: spec.DirectionUpload, ResourceVersion: forward.ResourceVersion},
					CounterBinding{Name: downloadName, ForwardID: forward.ID, Protocol: protocol, Direction: spec.DirectionDownload, ResourceVersion: forward.ResourceVersion},
				)
			}
		}
	}

	var builder strings.Builder
	if tableExists {
		builder.WriteString("delete table inet flux\n")
	}
	builder.WriteString("table inet flux {\n")
	writeMetadataCounters(&builder, state.Generation, program.DesiredChecksum, program.ProgramChecksum)

	for _, binding := range program.Counters {
		fmt.Fprintf(&builder, "  counter %s { packets 0 bytes 0; }\n", binding.Name)
	}
	if len(program.Counters) != 0 {
		builder.WriteByte('\n')
	}

	writeSet(&builder, "managed_tcp", byProtocol[spec.ProtocolTCP].managed)
	writeSet(&builder, "managed_udp", byProtocol[spec.ProtocolUDP].managed)
	writeSet(&builder, "paused_tcp", byProtocol[spec.ProtocolTCP].paused)
	writeSet(&builder, "paused_udp", byProtocol[spec.ProtocolUDP].paused)
	writeSet(&builder, "draining_tcp", byProtocol[spec.ProtocolTCP].draining)
	writeSet(&builder, "draining_udp", byProtocol[spec.ProtocolUDP].draining)
	writeMap(&builder, "dnat_addresses_tcp", "ipv4_addr", byProtocol[spec.ProtocolTCP].dnatAddresses)
	writeMap(&builder, "dnat_addresses_udp", "ipv4_addr", byProtocol[spec.ProtocolUDP].dnatAddresses)
	writeMap(&builder, "dnat_ports_tcp", "inet_service", byProtocol[spec.ProtocolTCP].dnatPorts)
	writeMap(&builder, "dnat_ports_udp", "inet_service", byProtocol[spec.ProtocolUDP].dnatPorts)
	writeMap(&builder, "marks_tcp", "mark", byProtocol[spec.ProtocolTCP].marks)
	writeMap(&builder, "marks_udp", "mark", byProtocol[spec.ProtocolUDP].marks)
	writeMap(&builder, "route_marks_tcp", "mark", byProtocol[spec.ProtocolTCP].routeMarks)
	writeMap(&builder, "route_marks_udp", "mark", byProtocol[spec.ProtocolUDP].routeMarks)
	writeSet(&builder, "masquerade_tcp", byProtocol[spec.ProtocolTCP].masquerade)
	writeSet(&builder, "masquerade_udp", byProtocol[spec.ProtocolUDP].masquerade)
	writeMap(&builder, "snat_tcp", "ipv4_addr", byProtocol[spec.ProtocolTCP].snat)
	writeMap(&builder, "snat_udp", "ipv4_addr", byProtocol[spec.ProtocolUDP].snat)
	writeSet(&builder, "mss_clamp_tcp", byProtocol[spec.ProtocolTCP].mssClamp)
	writeMap(&builder, "upload_counters_tcp", "counter", byProtocol[spec.ProtocolTCP].uploadCounters)
	writeMap(&builder, "upload_counters_udp", "counter", byProtocol[spec.ProtocolUDP].uploadCounters)
	writeMap(&builder, "download_counters_tcp", "counter", byProtocol[spec.ProtocolTCP].downloadCounters)
	writeMap(&builder, "download_counters_udp", "counter", byProtocol[spec.ProtocolUDP].downloadCounters)

	builder.WriteString("  chain prerouting_route {\n")
	builder.WriteString("    type filter hook prerouting priority mangle; policy accept;\n")
	builder.WriteString("    ct direction original meta l4proto tcp ct mark set ip daddr . tcp dport map @route_marks_tcp\n")
	builder.WriteString("    ct direction original meta l4proto udp ct mark set ip daddr . udp dport map @route_marks_udp\n")
	fmt.Fprintf(&builder, "    ct direction reply ct mark & 0x%08x == 0x%08x meta mark set ct mark\n", fabric.RoutingMarkMask, fabric.RoutingMarkPrefix)
	builder.WriteString("  }\n\n")

	builder.WriteString("  chain prerouting_nat {\n")
	builder.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
	builder.WriteString("    meta l4proto tcp dnat ip to ip daddr . tcp dport map @dnat_addresses_tcp : ip daddr . tcp dport map @dnat_ports_tcp\n")
	builder.WriteString("    meta l4proto udp dnat ip to ip daddr . udp dport map @dnat_addresses_udp : ip daddr . udp dport map @dnat_ports_udp\n")
	builder.WriteString("  }\n\n")

	if canonical.ProtocolBlocks != nil && canonical.ProtocolBlocks.Any() {
		writeProtocolBlockChains(&builder, *canonical.ProtocolBlocks)
	}

	builder.WriteString("  chain forward_control {\n")
	builder.WriteString("    type filter hook forward priority -10; policy accept;\n")
	builder.WriteString("    meta l4proto tcp ct original ip daddr . ct original proto-dst @paused_tcp drop\n")
	builder.WriteString("    meta l4proto udp ct original ip daddr . ct original proto-dst @paused_udp drop\n")
	builder.WriteString("    ct state new meta l4proto tcp ct original ip daddr . ct original proto-dst @draining_tcp drop\n")
	builder.WriteString("    ct state new meta l4proto udp ct original ip daddr . ct original proto-dst @draining_udp drop\n")
	if canonical.ProtocolBlocks != nil && canonical.ProtocolBlocks.Any() {
		builder.WriteString("    ct direction original meta l4proto tcp ct original ip daddr . ct original proto-dst @managed_tcp jump protocol_block\n")
	}
	builder.WriteString("    meta l4proto tcp ct original ip daddr . ct original proto-dst @mss_clamp_tcp tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu\n")
	builder.WriteString("    meta l4proto tcp meta mark set ct original ip daddr . ct original proto-dst map @marks_tcp\n")
	builder.WriteString("    meta l4proto udp meta mark set ct original ip daddr . ct original proto-dst map @marks_udp\n")
	builder.WriteString("    ct direction original meta l4proto tcp counter name ct original ip daddr . ct original proto-dst map @upload_counters_tcp\n")
	builder.WriteString("    ct direction original meta l4proto udp counter name ct original ip daddr . ct original proto-dst map @upload_counters_udp\n")
	builder.WriteString("    ct direction reply meta l4proto tcp counter name ct original ip daddr . ct original proto-dst map @download_counters_tcp\n")
	builder.WriteString("    ct direction reply meta l4proto udp counter name ct original ip daddr . ct original proto-dst map @download_counters_udp\n")
	builder.WriteString("  }\n\n")

	builder.WriteString("  chain postrouting_nat {\n")
	builder.WriteString("    type nat hook postrouting priority srcnat; policy accept;\n")
	builder.WriteString("    ct direction original meta l4proto tcp ct original ip daddr . ct original proto-dst @masquerade_tcp masquerade\n")
	builder.WriteString("    ct direction original meta l4proto udp ct original ip daddr . ct original proto-dst @masquerade_udp masquerade\n")
	builder.WriteString("    ct direction original meta l4proto tcp snat ip to ct original ip daddr . ct original proto-dst map @snat_tcp\n")
	builder.WriteString("    ct direction original meta l4proto udp snat ip to ct original ip daddr . ct original proto-dst map @snat_udp\n")
	builder.WriteString("  }\n")
	builder.WriteString("}\n")

	program.Script = builder.String()
	return program, nil
}

func writeProtocolBlockChains(builder *strings.Builder, policy spec.ProtocolBlockPolicy) {
	builder.WriteString("  chain protocol_block {\n")
	if policy.HTTP {
		builder.WriteString("    @ih,0,32 { 0x47455420, 0x50555420, 0x50524920 } drop\n") // GET, PUT, HTTP/2 PRI
		builder.WriteString("    @ih,0,40 { 0x4845414420, 0x504f535420 } drop\n")         // HEAD, POST
		builder.WriteString("    @ih,0,48 { 0x504154434820, 0x545241434520 } drop\n")     // PATCH, TRACE
		builder.WriteString("    @ih,0,56 0x44454c45544520 drop\n")                       // DELETE
		builder.WriteString("    @ih,0,64 0x4f5054494f4e5320 drop\n")                     // OPTIONS
	}
	if policy.SOCKS {
		// SOCKS4's empty USERID terminator and SOCKS5's advertised method
		// list make these signatures materially stronger than version bytes.
		builder.WriteString("    @ih,0,16 { 0x0401, 0x0402 } @ih,64,8 0x00 drop\n")
		builder.WriteString("    @ih,0,24 { 0x050100, 0x050102 } drop\n")
		values := make([]string, 0, 30)
		for methods := 2; methods <= 16; methods++ {
			values = append(values, fmt.Sprintf("0x05%02x0002", methods), fmt.Sprintf("0x05%02x0200", methods))
		}
		fmt.Fprintf(builder, "    @ih,0,32 { %s } drop\n", strings.Join(values, ", "))
	}
	if policy.HTTPS {
		builder.WriteString("    @ih,0,64 0x434f4e4e45435420 drop\n") // HTTP CONNECT proxy
	}
	if policy.TLS {
		builder.WriteString("    @ih,0,24 { 0x160301, 0x160302, 0x160303, 0x160304 } @ih,40,8 0x01 drop\n")
	} else if policy.HTTPS {
		builder.WriteString("    @ih,0,24 { 0x160301, 0x160302, 0x160303, 0x160304 } @ih,40,8 0x01 jump https_alpn\n")
	}
	builder.WriteString("  }\n\n")

	if !policy.HTTPS || policy.TLS {
		return
	}
	builder.WriteString("  chain https_alpn {\n")
	for offset := 6; offset+9 <= httpsALPNScanBytes; offset++ {
		fmt.Fprintf(builder, "    @ih,%d,72 0x08687474702f312e31 drop\n", offset*8)
	}
	for offset := 6; offset+3 <= httpsALPNScanBytes; offset++ {
		fmt.Fprintf(builder, "    @ih,%d,24 0x026832 drop\n", offset*8)
	}
	builder.WriteString("  }\n\n")
}

func forwardingClass(forward spec.ForwardSpec, user spec.UserPolicySpec) (uint16, error) {
	if forward.RateLimit != nil {
		if forward.TrafficClassID == 0 {
			return 0, fmt.Errorf("%w: forward %s", ErrUnresolvedClass, forward.ID)
		}
		return forward.TrafficClassID, nil
	}
	if user.RateLimit != nil {
		if user.TrafficClassID == 0 {
			return 0, fmt.Errorf("%w: user %s", ErrUnresolvedClass, forward.UserID)
		}
		return user.TrafficClassID, nil
	}
	return 0, nil
}

func runtimeFingerprint(state spec.DesiredState, now time.Time) string {
	var values []string
	for _, forward := range state.Canonical().Forwards {
		if forward.ExpiresAt == nil && forward.DrainDeadline == nil {
			continue
		}
		values = append(values, forward.ID+"="+string(forward.EffectiveLifecycle(now)))
	}
	return strings.Join(values, ";")
}

func stableCounterName(forwardID string, protocol spec.Protocol, direction spec.TrafficDirection) string {
	digest := sha256.Sum256([]byte(forwardID))
	protocolSuffix := "t"
	if protocol == spec.ProtocolUDP {
		protocolSuffix = "u"
	}
	directionSuffix := "up"
	if direction == spec.DirectionDownload {
		directionSuffix = "down"
	}
	return "c_" + hex.EncodeToString(digest[:12]) + "_" + protocolSuffix + "_" + directionSuffix
}

func checksum(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func writeSet(builder *strings.Builder, name string, elements []string) {
	fmt.Fprintf(builder, "  set %s {\n", name)
	builder.WriteString("    type ipv4_addr . inet_service;\n")
	if len(elements) != 0 {
		fmt.Fprintf(builder, "    elements = { %s };\n", strings.Join(elements, ", "))
	}
	builder.WriteString("  }\n\n")
}

func writeMetadataCounters(builder *strings.Builder, generation uint64, desiredChecksum, programChecksum string) {
	fmt.Fprintf(builder, "  counter flux_generation_%d { packets 0 bytes 0; }\n", generation)
	fmt.Fprintf(builder, "  counter flux_desired_%s { packets 0 bytes 0; }\n", desiredChecksum)
	fmt.Fprintf(builder, "  counter flux_program_%s { packets 0 bytes 0; }\n\n", programChecksum)
}

func writeMap(builder *strings.Builder, name, valueType string, elements []string) {
	fmt.Fprintf(builder, "  map %s {\n", name)
	fmt.Fprintf(builder, "    type ipv4_addr . inet_service : %s;\n", valueType)
	if len(elements) != 0 {
		fmt.Fprintf(builder, "    elements = { %s };\n", strings.Join(elements, ", "))
	}
	builder.WriteString("  }\n\n")
}
