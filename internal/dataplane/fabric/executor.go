package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"flux.local/flux/internal/spec"
)

var (
	ErrOwnershipRequired = errors.New("fabric management requires explicit ownership")
	ErrResourceConflict  = errors.New("fabric resource conflicts with existing network state")
)

type Runner interface {
	Run(context.Context, string, []string, []byte) ([]byte, []byte, error)
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, path string, args []string, stdin []byte) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	command.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type Config struct {
	IPPath         string
	WGPath         string
	SysctlPath     string
	PrivateKeyPath string
	AllowManage    bool
}

type Executor struct {
	config Config
	runner Runner
}

func NewExecutor(config Config, runner Runner) (*Executor, error) {
	if config.IPPath == "" || config.WGPath == "" || config.SysctlPath == "" || config.PrivateKeyPath == "" {
		return nil, errors.New("fabric executable and private key paths must not be empty")
	}
	if runner == nil {
		runner = OSRunner{}
	}
	return &Executor{config: config, runner: runner}, nil
}

// Check is read-only. It rejects link, route and rule collisions before the
// Reconciler persists pending state or changes any kernel subsystem.
func (e *Executor) Check(ctx context.Context, previous, target Program) error {
	if !target.Active {
		return nil
	}
	if !e.config.AllowManage {
		return ErrOwnershipRequired
	}
	forwarding, err := e.sysctlValue(ctx, "net.ipv4.ip_forward")
	if err != nil {
		return err
	}
	if forwarding != "1" {
		return errors.New("net.ipv4.ip_forward must be 1 before enabling fabric")
	}
	if programUsesWireGuard(target) {
		if _, err := loadPrivateKey(e.config.PrivateKeyPath); err != nil {
			return fmt.Errorf("load node-local WireGuard key: %w", err)
		}
	}
	for _, link := range target.Links {
		info, exists, err := e.linkInfo(ctx, link.Interface)
		if err != nil {
			return err
		}
		expectedKind := linkKind(link.Transport)
		if link.Transport == spec.FabricDirectL3 {
			if !exists {
				return fmt.Errorf("direct_l3 interface %s does not exist", link.Interface)
			}
			if info.MTU != int(link.MTU) {
				return fmt.Errorf("direct_l3 interface %s MTU is %d, expected %d", link.Interface, info.MTU, link.MTU)
			}
			if err := e.verifyAddress(ctx, link); err != nil {
				return err
			}
			rpFilter, err := e.sysctlValue(ctx, rpFilterKey(link.Interface))
			if err != nil {
				return err
			}
			if rpFilter != "0" && rpFilter != "2" {
				return fmt.Errorf("direct_l3 interface %s rp_filter must be 0 or 2", link.Interface)
			}
			continue
		}
		if exists && info.Kind != expectedKind {
			return fmt.Errorf("%w: interface %s has kind %q, expected %q", ErrResourceConflict, link.Interface, info.Kind, expectedKind)
		}
		if exists && info.Alias != linkAlias(link) {
			return fmt.Errorf("%w: interface %s is not marked as Flux fabric %s", ErrResourceConflict, link.Interface, link.ID)
		}
	}
	for _, route := range target.Routes {
		if err := e.checkRoute(ctx, route, previous.Routes); err != nil {
			return err
		}
	}
	for _, rule := range target.Rules {
		if err := e.checkRule(ctx, rule); err != nil {
			return err
		}
	}
	return nil
}

// Prepare installs or updates target resources without deleting resources
// still used by the applied generation. nftables is committed afterwards.
func (e *Executor) Prepare(ctx context.Context, target Program) error {
	if !target.Active {
		return nil
	}
	if !e.config.AllowManage {
		return ErrOwnershipRequired
	}
	privateKey := ""
	if programUsesWireGuard(target) {
		var err error
		privateKey, err = loadPrivateKey(e.config.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("load node-local WireGuard key: %w", err)
		}
	}
	var batch strings.Builder
	for _, link := range target.Links {
		_, exists, err := e.linkInfo(ctx, link.Interface)
		if err != nil {
			return err
		}
		if !exists {
			switch link.Transport {
			case spec.FabricWireGuard:
				fmt.Fprintf(&batch, "link add dev %s type wireguard\n", link.Interface)
			case spec.FabricGRE:
				fmt.Fprintf(&batch, "link add dev %s type gre local %s remote %s key %d\n", link.Interface, link.GRE.UnderlayLocal, link.GRE.UnderlayRemote, link.GRE.Key)
			case spec.FabricDirectL3:
				return fmt.Errorf("direct_l3 interface %s disappeared after preflight", link.Interface)
			}
		}
		if link.Transport != spec.FabricDirectL3 {
			if link.Transport == spec.FabricGRE && exists {
				fmt.Fprintf(&batch, "link set dev %s type gre local %s remote %s key %d\n", link.Interface, link.GRE.UnderlayLocal, link.GRE.UnderlayRemote, link.GRE.Key)
			}
			fmt.Fprintf(&batch, "address flush dev %s scope global\n", link.Interface)
			fmt.Fprintf(&batch, "address add %s dev %s\n", link.LocalAddress, link.Interface)
			fmt.Fprintf(&batch, "link set dev %s alias %s\n", link.Interface, linkAlias(link))
			fmt.Fprintf(&batch, "link set dev %s mtu %d up\n", link.Interface, link.MTU)
		}
	}
	for _, route := range target.Routes {
		writeRoute(&batch, "replace", route)
	}
	for _, rule := range target.Rules {
		exists, err := e.ruleExists(ctx, rule)
		if err != nil {
			return err
		}
		if !exists {
			fmt.Fprintf(&batch, "rule add priority %d fwmark 0x%08x/0x%08x lookup %d\n", rule.Priority, rule.Mark, rule.Mask, rule.Table)
		}
	}
	if err := e.runIPBatch(ctx, batch.String(), false); err != nil {
		return err
	}
	for _, link := range target.Links {
		if link.Transport != spec.FabricWireGuard {
			continue
		}
		configuration := wireGuardConfiguration(privateKey, link)
		if _, stderr, err := e.runner.Run(ctx, e.config.WGPath, []string{"syncconf", link.Interface, "/dev/stdin"}, []byte(configuration)); err != nil {
			return commandError("configure WireGuard interface "+link.Interface, stderr, err)
		}
	}
	var sysctlArgs []string
	for _, link := range target.Links {
		if link.Transport != spec.FabricDirectL3 {
			sysctlArgs = append(sysctlArgs, rpFilterKey(link.Interface)+"=0")
		}
	}
	if len(sysctlArgs) != 0 {
		args := append([]string{"-w"}, sysctlArgs...)
		if _, stderr, err := e.runner.Run(ctx, e.config.SysctlPath, args, nil); err != nil {
			return commandError("configure fabric rp_filter", stderr, err)
		}
	}
	return nil
}

// Cleanup removes only resources present in the previous plan and absent from
// the target plan. Managed WireGuard/GRE links are deleted; direct_l3 devices
// are never owned or deleted by Flux.
func (e *Executor) Cleanup(ctx context.Context, previous, target Program) error {
	if !previous.Active {
		return nil
	}
	targetRoutes := make(map[string]struct{}, len(target.Routes))
	for _, route := range target.Routes {
		targetRoutes[routeKey(route)] = struct{}{}
	}
	targetRules := make(map[uint32]RulePlan, len(target.Rules))
	for _, rule := range target.Rules {
		targetRules[rule.Priority] = rule
	}
	targetLinks := make(map[string]LinkPlan, len(target.Links))
	for _, link := range target.Links {
		targetLinks[link.Interface] = link
	}
	var batch strings.Builder
	for _, route := range previous.Routes {
		if _, keep := targetRoutes[routeKey(route)]; !keep {
			writeRoute(&batch, "del", route)
		}
	}
	for _, rule := range previous.Rules {
		if current, keep := targetRules[rule.Priority]; !keep || current != rule {
			fmt.Fprintf(&batch, "rule del priority %d fwmark 0x%08x/0x%08x lookup %d\n", rule.Priority, rule.Mark, rule.Mask, rule.Table)
		}
	}
	for _, link := range previous.Links {
		if _, keep := targetLinks[link.Interface]; keep || link.Transport == spec.FabricDirectL3 {
			continue
		}
		info, exists, err := e.linkInfo(ctx, link.Interface)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if info.Kind != linkKind(link.Transport) || info.Alias != linkAlias(link) {
			return fmt.Errorf("%w: refuse to delete unowned interface %s", ErrResourceConflict, link.Interface)
		}
		fmt.Fprintf(&batch, "link del dev %s\n", link.Interface)
	}
	return e.runIPBatch(ctx, batch.String(), true)
}

func (e *Executor) Verify(ctx context.Context, target Program) error {
	for _, link := range target.Links {
		info, exists, err := e.linkInfo(ctx, link.Interface)
		if err != nil {
			return err
		}
		if !exists || info.MTU != int(link.MTU) {
			return fmt.Errorf("verify fabric interface %s: exists=%t mtu=%d", link.Interface, exists, info.MTU)
		}
		if link.Transport != spec.FabricDirectL3 && (info.Kind != linkKind(link.Transport) || info.Alias != linkAlias(link)) {
			return fmt.Errorf("verify fabric interface %s ownership or kind: got alias=%q kind=%q", link.Interface, info.Alias, info.Kind)
		}
		if err := e.verifyAddress(ctx, link); err != nil {
			return err
		}
		if link.Transport == spec.FabricWireGuard {
			if err := e.verifyWireGuard(ctx, link); err != nil {
				return err
			}
		}
	}
	for _, route := range target.Routes {
		if err := e.verifyOwnedRoute(ctx, route); err != nil {
			return err
		}
	}
	for _, rule := range target.Rules {
		exists, err := e.ruleExists(ctx, rule)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("verify policy rule priority %d: missing", rule.Priority)
		}
	}
	return nil
}

type linkJSON struct {
	IfName   string `json:"ifname"`
	MTU      int    `json:"mtu"`
	IfAlias  string `json:"ifalias"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

type linkState struct {
	MTU   int
	Kind  string
	Alias string
}

func (e *Executor) linkInfo(ctx context.Context, name string) (linkState, bool, error) {
	stdout, stderr, err := e.runner.Run(ctx, e.config.IPPath, []string{"-d", "-j", "link", "show", "dev", name}, nil)
	if err != nil {
		if outputMeansMissing(stderr) {
			return linkState{}, false, nil
		}
		return linkState{}, false, commandError("inspect interface "+name, stderr, err)
	}
	var links []linkJSON
	if err := json.Unmarshal(stdout, &links); err != nil || len(links) != 1 {
		return linkState{}, false, fmt.Errorf("decode interface %s state", name)
	}
	return linkState{MTU: links[0].MTU, Kind: links[0].LinkInfo.Kind, Alias: links[0].IfAlias}, true, nil
}

type addressJSON struct {
	AddressInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func (e *Executor) verifyAddress(ctx context.Context, link LinkPlan) error {
	stdout, stderr, err := e.runner.Run(ctx, e.config.IPPath, []string{"-j", "address", "show", "dev", link.Interface}, nil)
	if err != nil {
		return commandError("inspect address on "+link.Interface, stderr, err)
	}
	var states []addressJSON
	if err := json.Unmarshal(stdout, &states); err != nil || len(states) != 1 {
		return fmt.Errorf("decode addresses on %s", link.Interface)
	}
	want := link.LocalAddress.String()
	for _, address := range states[0].AddressInfo {
		if address.Family == "inet" && fmt.Sprintf("%s/%d", address.Local, address.PrefixLen) == want {
			return nil
		}
	}
	return fmt.Errorf("verify address on %s: %s is missing", link.Interface, want)
}

type routeJSON struct {
	Destination string          `json:"dst"`
	Device      string          `json:"dev"`
	Gateway     string          `json:"gateway"`
	Protocol    json.RawMessage `json:"protocol"`
}

func (e *Executor) routes(ctx context.Context, route RoutePlan) ([]routeJSON, error) {
	args := []string{"-N", "-j", "route", "show", "table", strconv.FormatUint(uint64(route.Table), 10), "exact", route.Destination.String()}
	stdout, stderr, err := e.runner.Run(ctx, e.config.IPPath, args, nil)
	if err != nil {
		if outputMeansMissing(stderr) {
			return nil, nil
		}
		return nil, commandError("inspect route "+route.Destination.String(), stderr, err)
	}
	var routes []routeJSON
	if err := json.Unmarshal(stdout, &routes); err != nil {
		return nil, fmt.Errorf("decode route %s: %w", route.Destination, err)
	}
	return routes, nil
}

func (e *Executor) checkRoute(ctx context.Context, route RoutePlan, previous []RoutePlan) error {
	routes, err := e.routes(ctx, route)
	if err != nil {
		return err
	}
	for _, installed := range routes {
		if routeMatches(installed, route) {
			continue
		}
		ownedPrevious := false
		for _, old := range previous {
			if old.Table == route.Table && old.Destination == route.Destination && routeMatches(installed, old) {
				ownedPrevious = true
				break
			}
		}
		if !ownedPrevious {
			return fmt.Errorf("%w: route %s table %d", ErrResourceConflict, route.Destination, route.Table)
		}
	}
	return nil
}

func (e *Executor) verifyOwnedRoute(ctx context.Context, route RoutePlan) error {
	routes, err := e.routes(ctx, route)
	if err != nil {
		return err
	}
	for _, installed := range routes {
		if routeMatches(installed, route) {
			return nil
		}
	}
	return fmt.Errorf("verify route %s table %d: missing", route.Destination, route.Table)
}

func routeMatches(installed routeJSON, expected RoutePlan) bool {
	if !routeDestinationMatches(installed.Destination, expected.Destination) || installed.Device != expected.Interface {
		return false
	}
	wantGateway := ""
	if expected.Gateway != nil {
		wantGateway = expected.Gateway.String()
	}
	if installed.Gateway != wantGateway {
		return false
	}
	protocol := strings.Trim(string(installed.Protocol), "\"")
	return protocol == strconv.Itoa(int(expected.Protocol)) || protocol == "186"
}

func routeDestinationMatches(installed string, expected netip.Prefix) bool {
	if prefix, err := netip.ParsePrefix(installed); err == nil {
		return prefix.Masked() == expected.Masked()
	}
	address, err := netip.ParseAddr(installed)
	if err != nil {
		return false
	}
	return expected.Bits() == address.BitLen() && expected.Addr() == address
}

func (e *Executor) checkRule(ctx context.Context, rule RulePlan) error {
	installed, err := e.rulesAtPriority(ctx, rule.Priority)
	if err != nil {
		return err
	}
	for _, candidate := range installed {
		if !ruleMatches(candidate, rule) {
			return fmt.Errorf("%w: policy rule priority %d", ErrResourceConflict, rule.Priority)
		}
	}
	return nil
}

func (e *Executor) ruleExists(ctx context.Context, rule RulePlan) (bool, error) {
	installed, err := e.rulesAtPriority(ctx, rule.Priority)
	if err != nil {
		return false, err
	}
	for _, candidate := range installed {
		if ruleMatches(candidate, rule) {
			return true, nil
		}
	}
	return false, nil
}

func (e *Executor) rulesAtPriority(ctx context.Context, priority uint32) ([]map[string]any, error) {
	stdout, stderr, err := e.runner.Run(ctx, e.config.IPPath, []string{"-j", "rule", "show", "priority", strconv.FormatUint(uint64(priority), 10)}, nil)
	if err != nil {
		return nil, commandError("inspect policy rule", stderr, err)
	}
	var rules []map[string]any
	if err := json.Unmarshal(stdout, &rules); err != nil {
		return nil, fmt.Errorf("decode policy rule priority %d: %w", priority, err)
	}
	return rules, nil
}

func ruleMatches(installed map[string]any, expected RulePlan) bool {
	priority, ok := numericJSON(installed["priority"])
	if !ok || priority != uint64(expected.Priority) {
		return false
	}
	table, ok := numericJSON(installed["table"])
	if !ok || table != uint64(expected.Table) {
		return false
	}
	mark, mask, ok := markJSON(installed["fwmark"])
	return ok && mark == expected.Mark && mask == expected.Mask
}

func numericJSON(value any) (uint64, bool) {
	switch typed := value.(type) {
	case float64:
		return uint64(typed), typed >= 0
	case string:
		parsed, err := strconv.ParseUint(typed, 0, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func markJSON(value any) (uint32, uint32, bool) {
	text, ok := value.(string)
	if !ok {
		if numeric, valid := numericJSON(value); valid {
			return uint32(numeric), ^uint32(0), true
		}
		return 0, 0, false
	}
	parts := strings.SplitN(text, "/", 2)
	mark, err := strconv.ParseUint(parts[0], 0, 32)
	if err != nil {
		return 0, 0, false
	}
	mask := uint64(^uint32(0))
	if len(parts) == 2 {
		mask, err = strconv.ParseUint(parts[1], 0, 32)
		if err != nil {
			return 0, 0, false
		}
	}
	return uint32(mark), uint32(mask), true
}

func (e *Executor) verifyWireGuard(ctx context.Context, link LinkPlan) error {
	stdout, stderr, err := e.runner.Run(ctx, e.config.WGPath, []string{"show", link.Interface, "dump"}, nil)
	if err != nil {
		return commandError("inspect WireGuard interface "+link.Interface, stderr, err)
	}
	lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	if len(lines) != 2 {
		return fmt.Errorf("verify WireGuard interface %s: expected exactly one peer", link.Interface)
	}
	interfaceFields := strings.Split(lines[0], "\t")
	peerFields := strings.Split(lines[1], "\t")
	if len(interfaceFields) < 4 || len(peerFields) < 8 {
		return fmt.Errorf("verify WireGuard interface %s: malformed dump", link.Interface)
	}
	if interfaceFields[2] != strconv.Itoa(int(link.WireGuard.ListenPort)) || peerFields[0] != link.WireGuard.PeerPublicKey || peerFields[2] != link.WireGuard.Endpoint {
		return fmt.Errorf("verify WireGuard interface %s: endpoint, key or listen port mismatch", link.Interface)
	}
	wantAllowed := prefixList(link.AllowedIPs)
	gotAllowed := strings.Split(peerFields[3], ",")
	sort.Strings(gotAllowed)
	if strings.Join(gotAllowed, ",") != wantAllowed || peerFields[7] != strconv.Itoa(int(link.WireGuard.PersistentKeepaliveSeconds)) {
		return fmt.Errorf("verify WireGuard interface %s: allowed IPs or keepalive mismatch", link.Interface)
	}
	return nil
}

func (e *Executor) sysctlValue(ctx context.Context, key string) (string, error) {
	stdout, stderr, err := e.runner.Run(ctx, e.config.SysctlPath, []string{"-n", key}, nil)
	if err != nil {
		return "", commandError("read sysctl "+key, stderr, err)
	}
	return strings.TrimSpace(string(stdout)), nil
}

func (e *Executor) runIPBatch(ctx context.Context, batch string, allowMissing bool) error {
	if strings.TrimSpace(batch) == "" {
		return nil
	}
	_, stderr, err := e.runner.Run(ctx, e.config.IPPath, []string{"-force", "-batch", "-"}, []byte(batch))
	if err == nil || allowMissing && outputOnlyMissing(stderr) {
		return nil
	}
	return commandError("apply fabric ip batch", stderr, err)
}

func writeRoute(builder *strings.Builder, operation string, route RoutePlan) {
	fmt.Fprintf(builder, "route %s %s", operation, route.Destination)
	if route.Gateway != nil {
		fmt.Fprintf(builder, " via %s", route.Gateway)
	}
	fmt.Fprintf(builder, " dev %s table %d proto %d", route.Interface, route.Table, route.Protocol)
	if route.Gateway == nil {
		builder.WriteString(" scope link")
	}
	builder.WriteByte('\n')
}

func wireGuardConfiguration(privateKey string, link LinkPlan) string {
	var builder strings.Builder
	builder.WriteString("[Interface]\nPrivateKey = ")
	builder.WriteString(privateKey)
	fmt.Fprintf(&builder, "\nListenPort = %d\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n", link.WireGuard.ListenPort, link.WireGuard.PeerPublicKey, link.WireGuard.Endpoint, prefixList(link.AllowedIPs))
	if link.WireGuard.PersistentKeepaliveSeconds != 0 {
		fmt.Fprintf(&builder, "PersistentKeepalive = %d\n", link.WireGuard.PersistentKeepaliveSeconds)
	}
	return builder.String()
}

func prefixList(prefixes []netip.Prefix) string {
	values := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		values[i] = prefix.String()
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func programUsesWireGuard(program Program) bool {
	for _, link := range program.Links {
		if link.Transport == spec.FabricWireGuard {
			return true
		}
	}
	return false
}

func linkKind(transport spec.FabricTransport) string {
	if transport == spec.FabricGRE {
		return "gre"
	}
	if transport == spec.FabricWireGuard {
		return "wireguard"
	}
	return ""
}

func linkAlias(link LinkPlan) string {
	return "managed-by=flux;fabric=" + link.ID
}

func rpFilterKey(interfaceName string) string {
	return "net.ipv4.conf." + interfaceName + ".rp_filter"
}

func outputMeansMissing(stderr []byte) bool {
	text := strings.ToLower(string(stderr))
	return strings.Contains(text, "does not exist") || strings.Contains(text, "cannot find device") || strings.Contains(text, "no such device")
}

func outputOnlyMissing(stderr []byte) bool {
	text := strings.ToLower(strings.TrimSpace(string(stderr)))
	if text == "" {
		return false
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "no such process") && !strings.Contains(line, "cannot find device") && !strings.Contains(line, "does not exist") {
			return false
		}
	}
	return true
}

func commandError(operation string, stderr []byte, err error) error {
	const maxErrorBytes = 4096
	message := strings.TrimSpace(string(stderr))
	if len(message) > maxErrorBytes {
		message = message[:maxErrorBytes] + "..."
	}
	if message == "" {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s: %w: %s", operation, err, message)
}
