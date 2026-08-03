package tc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"flux.local/flux/internal/dataplane/nft"
	"flux.local/flux/internal/spec"
)

const CompilerABI = "tc-phase4-v1"

var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

var ErrOwnershipRequired = errors.New("tc root replacement requires explicit ownership")

type Config struct {
	PublicInterface           string `json:"public_interface"`
	IFBInterface              string `json:"ifb_interface"`
	UploadLinkBitsPerSecond   uint64 `json:"upload_link_bits_per_second"`
	DownloadLinkBitsPerSecond uint64 `json:"download_link_bits_per_second"`
	AllowReplaceRoot          bool   `json:"allow_replace_root"`
}

type ClassBinding struct {
	Interface string `json:"interface"`
	ClassID   uint16 `json:"class_id"`
	Rate      uint64 `json:"rate_bits_per_second"`
}

type Program struct {
	Active          bool           `json:"active"`
	Checksum        string         `json:"checksum"`
	Config          Config         `json:"config"`
	Batch           string         `json:"-"`
	ExpectedClasses []ClassBinding `json:"expected_classes"`
}

type Compiler struct{ config Config }

func NewCompiler(config Config) Compiler { return Compiler{config: config} }

func (c Compiler) Compile(state spec.DesiredState, desiredChecksum string) (Program, error) {
	if err := state.Validate(); err != nil {
		return Program{}, err
	}
	active := hasRateLimits(state)
	program := Program{Active: active, Config: c.config}
	if !active {
		if c.config.PublicInterface != "" && c.config.IFBInterface != "" && c.config.AllowReplaceRoot {
			program.Batch = cleanupBatch(c.config)
		}
		program.Checksum = programChecksum(c.config, active, program.Batch)
		return program, nil
	}
	if err := validateConfig(c.config); err != nil {
		return Program{}, err
	}

	canonical := state.Canonical()
	users := make(map[string]spec.UserPolicySpec, len(canonical.UserPolicies))
	ingressUsers := make(map[string]struct{})
	for _, forward := range canonical.Forwards {
		if forward.IngressNodeID == canonical.NodeID {
			ingressUsers[forward.UserID] = struct{}{}
		}
	}
	for _, policy := range canonical.UserPolicies {
		users[policy.UserID] = policy
		_, usedAtIngress := ingressUsers[policy.UserID]
		if usedAtIngress && policy.RateLimit != nil && policy.TrafficClassID == 0 {
			return Program{}, fmt.Errorf("%w: user %s", nft.ErrUnresolvedClass, policy.UserID)
		}
	}
	for _, forward := range canonical.Forwards {
		if forward.IngressNodeID == canonical.NodeID && forward.RateLimit != nil && forward.TrafficClassID == 0 {
			return Program{}, fmt.Errorf("%w: forward %s", nft.ErrUnresolvedClass, forward.ID)
		}
	}

	var builder strings.Builder
	builder.WriteString(cleanupBatch(c.config))
	writeRoot(&builder, c.config.PublicInterface, c.config.DownloadLinkBitsPerSecond)
	writeRoot(&builder, c.config.IFBInterface, c.config.UploadLinkBitsPerSecond)
	fmt.Fprintf(&builder, "qdisc add dev %s clsact\n", c.config.PublicInterface)

	writeDirectionClasses(&builder, &program, canonical, users, spec.DirectionDownload, c.config.PublicInterface, c.config.DownloadLinkBitsPerSecond)
	writeDirectionClasses(&builder, &program, canonical, users, spec.DirectionUpload, c.config.IFBInterface, c.config.UploadLinkBitsPerSecond)
	writeIngressRedirects(&builder, canonical, users, c.config)
	program.Batch = builder.String()
	program.Checksum = programChecksum(c.config, active, program.Batch)
	sort.Slice(program.ExpectedClasses, func(i, j int) bool {
		if program.ExpectedClasses[i].Interface != program.ExpectedClasses[j].Interface {
			return program.ExpectedClasses[i].Interface < program.ExpectedClasses[j].Interface
		}
		return program.ExpectedClasses[i].ClassID < program.ExpectedClasses[j].ClassID
	})
	return program, nil
}

func validateConfig(config Config) error {
	if !interfacePattern.MatchString(config.PublicInterface) || !interfacePattern.MatchString(config.IFBInterface) || config.PublicInterface == config.IFBInterface {
		return errors.New("public and IFB interface names are invalid or identical")
	}
	if config.UploadLinkBitsPerSecond == 0 || config.DownloadLinkBitsPerSecond == 0 {
		return errors.New("upload and download link capacities must be greater than zero")
	}
	if !config.AllowReplaceRoot {
		return ErrOwnershipRequired
	}
	return nil
}

func hasRateLimits(state spec.DesiredState) bool {
	users := make(map[string]spec.UserPolicySpec, len(state.UserPolicies))
	for _, policy := range state.UserPolicies {
		users[policy.UserID] = policy
	}
	for _, forward := range state.Forwards {
		if forward.IngressNodeID == state.NodeID && (forward.RateLimit != nil || users[forward.UserID].RateLimit != nil) {
			return true
		}
	}
	return false
}

func cleanupBatch(config Config) string {
	return fmt.Sprintf("qdisc del dev %s root\nqdisc del dev %s clsact\nqdisc del dev %s root\n", config.PublicInterface, config.PublicInterface, config.IFBInterface)
}

func writeRoot(builder *strings.Builder, device string, capacity uint64) {
	fmt.Fprintf(builder, "qdisc add dev %s root handle 1: htb default ffff\n", device)
	fmt.Fprintf(builder, "class add dev %s parent 1: classid 1:1 htb rate %dbit ceil %dbit\n", device, capacity, capacity)
	fmt.Fprintf(builder, "class add dev %s parent 1:1 classid 1:ffff htb rate %dbit ceil %dbit\n", device, capacity, capacity)
	fmt.Fprintf(builder, "qdisc add dev %s parent 1:ffff fq_codel\n", device)
}

func writeDirectionClasses(builder *strings.Builder, program *Program, state spec.DesiredState, users map[string]spec.UserPolicySpec, direction spec.TrafficDirection, device string, capacity uint64) {
	ingressUsers := make(map[string]struct{})
	for _, forward := range state.Forwards {
		if forward.IngressNodeID == state.NodeID {
			ingressUsers[forward.UserID] = struct{}{}
		}
	}
	for _, policy := range state.UserPolicies {
		if _, used := ingressUsers[policy.UserID]; !used {
			continue
		}
		rate, burst := directionRate(policy.RateLimit, direction)
		if rate == 0 {
			continue
		}
		if rate > capacity {
			rate = capacity
		}
		writeClass(builder, device, 1, policy.TrafficClassID, rate, burst)
		program.ExpectedClasses = append(program.ExpectedClasses, ClassBinding{Interface: device, ClassID: policy.TrafficClassID, Rate: rate})
	}
	seenFilter := make(map[uint16]struct{})
	for _, forward := range state.Forwards {
		if forward.IngressNodeID != state.NodeID || forward.RateLimit == nil {
			continue
		}
		user := users[forward.UserID]
		rate, burst := directionRate(forward.RateLimit, direction)
		userRate, userBurst := directionRate(user.RateLimit, direction)
		parent := uint16(1)
		if userRate != 0 {
			parent = user.TrafficClassID
			if rate == 0 {
				rate, burst = userRate, userBurst
			}
		}
		if rate == 0 {
			continue
		}
		if rate > capacity {
			rate = capacity
		}
		writeClass(builder, device, parent, forward.TrafficClassID, rate, burst)
		program.ExpectedClasses = append(program.ExpectedClasses, ClassBinding{Interface: device, ClassID: forward.TrafficClassID, Rate: rate})
	}

	for _, forward := range state.Forwards {
		if forward.IngressNodeID != state.NodeID {
			continue
		}
		user := users[forward.UserID]
		rate, _ := effectiveDirectionRate(forward, user, direction)
		if rate == 0 {
			continue
		}
		classID := classForForward(forward, user)
		if _, exists := seenFilter[classID]; exists {
			continue
		}
		seenFilter[classID] = struct{}{}
		fmt.Fprintf(builder, "filter add dev %s parent 1: protocol all pref %d handle 0x%08x fw classid 1:%x\n", device, classID, nft.TrafficMark(classID), classID)
	}
}

func writeClass(builder *strings.Builder, device string, parent, classID uint16, rate, burst uint64) {
	if burst == 0 {
		burst = 64 * 1024
	}
	fmt.Fprintf(builder, "class add dev %s parent 1:%x classid 1:%x htb rate %dbit ceil %dbit burst %db cburst %db\n", device, parent, classID, rate, rate, burst, burst)
	fmt.Fprintf(builder, "qdisc add dev %s parent 1:%x fq_codel\n", device, classID)
}

func writeIngressRedirects(builder *strings.Builder, state spec.DesiredState, users map[string]spec.UserPolicySpec, config Config) {
	preference := uint32(10)
	for _, forward := range state.Forwards {
		if forward.IngressNodeID != state.NodeID {
			continue
		}
		user := users[forward.UserID]
		rate, _ := effectiveDirectionRate(forward, user, spec.DirectionUpload)
		if rate == 0 {
			continue
		}
		classID := classForForward(forward, user)
		for _, protocol := range forward.Protocols {
			fmt.Fprintf(builder, "filter add dev %s ingress protocol ip pref %d flower dst_ip %s ip_proto %s dst_port %d action skbedit mark 0x%08x action mirred egress redirect dev %s\n",
				config.PublicInterface, preference, forward.Listen.Address.Unmap(), protocol, forward.Listen.Port, nft.TrafficMark(classID), config.IFBInterface)
			preference++
		}
	}
}

func classForForward(forward spec.ForwardSpec, user spec.UserPolicySpec) uint16 {
	if forward.RateLimit != nil {
		return forward.TrafficClassID
	}
	return user.TrafficClassID
}

func effectiveDirectionRate(forward spec.ForwardSpec, user spec.UserPolicySpec, direction spec.TrafficDirection) (uint64, uint64) {
	if rate, burst := directionRate(forward.RateLimit, direction); rate != 0 {
		return rate, burst
	}
	return directionRate(user.RateLimit, direction)
}

func directionRate(limit *spec.RateLimitSpec, direction spec.TrafficDirection) (uint64, uint64) {
	if limit == nil {
		return 0, 0
	}
	if direction == spec.DirectionUpload {
		return limit.IngressBitsPerSecond, limit.BurstBytes
	}
	return limit.EgressBitsPerSecond, limit.BurstBytes
}

func programChecksum(config Config, active bool, batch string) string {
	value := fmt.Sprintf("%s\n%s\n%s\n%d\n%d\n%t\n%t\n%s", CompilerABI, config.PublicInterface, config.IFBInterface, config.UploadLinkBitsPerSecond, config.DownloadLinkBitsPerSecond, config.AllowReplaceRoot, active, batch)
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
