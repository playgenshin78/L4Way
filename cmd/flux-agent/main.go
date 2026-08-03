package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/agent"
	"flux.local/flux/internal/agent/controlclient"
	agentenrollment "flux.local/flux/internal/agent/enrollment"
	"flux.local/flux/internal/agent/maintenance"
	"flux.local/flux/internal/agent/serviceinstall"
	shared "flux.local/flux/internal/control"
	"flux.local/flux/internal/dataplane/conntrack"
	dpfabric "flux.local/flux/internal/dataplane/fabric"
	"flux.local/flux/internal/dataplane/nft"
	dptc "flux.local/flux/internal/dataplane/tc"
	"flux.local/flux/internal/securechannel"
	"flux.local/flux/internal/spec"
)

const maxDesiredFileBytes = int64(64 << 20)

type controlRunner interface {
	Run(context.Context) error
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	var err error
	switch args[0] {
	case "validate":
		err = runValidate(args[1:], stdout, stderr)
	case "render":
		err = runRender(args[1:], stdout, stderr)
	case "render-fabric":
		err = runRenderFabric(args[1:], stdout, stderr)
	case "fabric-key":
		err = runFabricKey(args[1:], stdout, stderr)
	case "apply":
		err = runApply(args[1:], stdout, stderr)
	case "recover":
		err = runRecover(args[1:], stdout, stderr)
	case "counters":
		err = runCounters(args[1:], stdout, stderr)
	case "enroll":
		err = runEnroll(args[1:], stdout, stderr)
	case "install":
		err = runInstall(args[1:], stdout, stderr)
	case "maintenance":
		err = runMaintenance(args[1:], stderr)
	case "run":
		err = runService(args[1:], stderr)
	case "version":
		err = writeJSON(stdout, map[string]any{"agent_version": shared.AgentVersion})
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func runInstall(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundleBase64 := flags.String("bundle-base64", "", "Controller-generated base64url enrollment bundle")
	destinationExecutable := flags.String("destination", "/usr/local/bin/flux-agent", "installed Agent executable")
	unitPath := flags.String("unit", "/etc/systemd/system/flux-agent.service", "systemd unit path")
	maintenanceUnitPath := flags.String("maintenance-unit", "/etc/systemd/system/flux-agent-maintenance.service", "maintenance systemd unit path")
	identityDirectory := flags.String("identity-dir", "/var/lib/flux-agent/identity", "directory for the node Noise identity")
	stateDirectory := flags.String("state-dir", "/var/lib/flux-agent", "durable Agent state directory")
	systemctlPath := flags.String("systemctl", "systemctl", "systemctl executable path")
	enableFabric := flags.Bool("enable-fabric", false, "allow the installed Agent to manage node fabric")
	publicInterface := flags.String("public-interface", "", "public interface for tc rate limiting")
	allowTCRoot := flags.Bool("allow-tc-root-replace", false, "allow Flux to own the public interface root qdisc")
	timeout := flags.Duration("timeout", 20*time.Second, "enrollment request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := serviceinstall.Preflight(*systemctlPath); err != nil {
		return err
	}
	bundleBytes, err := decodeInstallBundle(*bundleBase64)
	if err != nil {
		return err
	}
	var bundle struct {
		Version             int       `json:"version"`
		NodeID              string    `json:"node_id"`
		Token               string    `json:"token"`
		ExpiresAt           time.Time `json:"expires_at"`
		ControllerPublicKey string    `json:"controller_public_key"`
		EnrollmentAddress   string    `json:"enrollment_address"`
		ControlAddress      string    `json:"control_address"`
	}
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil || bundle.Version != 1 {
		return errors.New("installation bundle is invalid or unsupported")
	}
	if bundle.ExpiresAt.IsZero() || !time.Now().UTC().Before(bundle.ExpiresAt) {
		return errors.New("installation bundle has expired")
	}
	controllerPublicKey, err := securechannel.ParsePublicKey(bundle.ControllerPublicKey)
	if err != nil {
		return err
	}
	sourceExecutable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running Agent executable: %w", err)
	}
	installConfig := serviceinstall.Config{
		SourceExecutable: sourceExecutable, DestinationExecutable: *destinationExecutable, UnitPath: *unitPath,
		MaintenanceUnitPath: *maintenanceUnitPath,
		IdentityDirectory:   *identityDirectory, StateDirectory: *stateDirectory, ControllerAddress: bundle.ControlAddress,
		NodeID: bundle.NodeID, EnableFabric: *enableFabric, PublicInterface: *publicInterface, AllowTCRootReplace: *allowTCRoot,
	}
	if err := installConfig.Validate(); err != nil {
		return err
	}
	alreadyEnrolled := false
	if _, pinnedController, loadErr := agentenrollment.LoadIdentity(*identityDirectory, bundle.NodeID); loadErr == nil {
		if subtle.ConstantTimeCompare(pinnedController, controllerPublicKey) != 1 {
			return errors.New("existing Agent identity is pinned to another Controller")
		}
		alreadyEnrolled = true
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return loadErr
	}
	if err := serviceinstall.InstallFiles(installConfig); err != nil {
		return err
	}
	if !alreadyEnrolled {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		if _, err := agentenrollment.Enroll(ctx, agentenrollment.Config{
			ControllerAddress: bundle.EnrollmentAddress, NodeID: bundle.NodeID, Token: bundle.Token,
			ControllerPublicKey: controllerPublicKey, IdentityDir: *identityDirectory,
			AgentVersion: shared.AgentVersion, Timeout: *timeout,
		}); err != nil {
			return err
		}
	}
	activationContext, cancelActivation := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelActivation()
	if err := serviceinstall.Activate(activationContext, *systemctlPath); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{
		"installed": true, "enrolled": !alreadyEnrolled, "node_id": bundle.NodeID,
		"controller": bundle.ControlAddress, "service": serviceinstall.ServiceName,
	})
}

func runMaintenance(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("maintenance", flag.ContinueOnError)
	flags.SetOutput(stderr)
	requestPath := flags.String("request", maintenance.RequestPath(maintenance.DefaultStateDirectory), "root-owned maintenance request")
	systemctlPath := flags.String("systemctl", "systemctl", "systemctl executable path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return maintenance.Apply(ctx, *requestPath, *systemctlPath)
}

func decodeInstallBundle(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128<<10 || strings.ContainsAny(value, "\r\n\t ") {
		return nil, errors.New("--bundle-base64 is required and must be a single base64url value")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		encoded, err = base64.URLEncoding.DecodeString(value)
	}
	if err != nil || len(encoded) == 0 || len(encoded) > 64<<10 {
		return nil, errors.New("installation bundle is not valid base64url")
	}
	return encoded, nil
}

func runEnroll(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(stderr)
	controllerAddress := flags.String("controller", "", "Controller Noise enrollment address, for example controller:8443")
	controllerKey := flags.String("controller-key", "", "pinned Controller Noise public key in base64")
	nodeID := flags.String("node-id", "", "node identity bound to the token")
	tokenFile := flags.String("token-file", "", "Controller-generated enrollment bundle")
	identityDirectory := flags.String("identity-dir", "/var/lib/flux-agent/identity", "directory for the node Noise identity")
	timeout := flags.Duration("timeout", 20*time.Second, "enrollment request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	bundleBytes, err := readLimitedFile(*tokenFile, 64<<10)
	if err != nil {
		return fmt.Errorf("read enrollment bundle: %w", err)
	}
	var bundle struct {
		Version             int    `json:"version"`
		NodeID              string `json:"node_id"`
		Token               string `json:"token"`
		ControllerPublicKey string `json:"controller_public_key"`
		EnrollmentAddress   string `json:"enrollment_address"`
	}
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil || bundle.Version != 1 {
		return errors.New("enrollment bundle is invalid or unsupported")
	}
	if strings.TrimSpace(*nodeID) == "" {
		*nodeID = bundle.NodeID
	}
	if strings.TrimSpace(*controllerAddress) == "" {
		*controllerAddress = bundle.EnrollmentAddress
	}
	if strings.TrimSpace(*controllerKey) == "" {
		*controllerKey = bundle.ControllerPublicKey
	}
	if *nodeID != bundle.NodeID {
		return errors.New("--node-id does not match the enrollment bundle")
	}
	pinnedControllerKey, err := securechannel.ParsePublicKey(*controllerKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	response, err := agentenrollment.Enroll(ctx, agentenrollment.Config{
		ControllerAddress: *controllerAddress, NodeID: *nodeID, Token: bundle.Token,
		ControllerPublicKey: pinnedControllerKey, IdentityDir: *identityDirectory,
		AgentVersion: shared.AgentVersion, Timeout: *timeout,
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{
		"enrolled": true, "node_id": response.NodeID,
		"node_key_fingerprint":       response.NodeKeyFingerprint,
		"controller_key_fingerprint": response.ControllerKeyFingerprint,
		"identity_dir":               *identityDirectory,
	})
}

func runService(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	controllerTarget := flags.String("controller", "", "Controller Noise gRPC target, for example controller:9443")
	nodeID := flags.String("node-id", "", "node identity")
	identityDirectory := flags.String("identity-dir", "/var/lib/flux-agent/identity", "node Noise identity directory")
	stateDirectory := flags.String("state-dir", "/var/lib/flux-agent", "durable agent state directory")
	nftPath := flags.String("nft", "nft", "nft executable path")
	tcPath := flags.String("tc", "tc", "tc executable path")
	ipPath := flags.String("ip", "ip", "ip executable path")
	wgPath := flags.String("wg", "wg", "wg executable path")
	sysctlPath := flags.String("sysctl", "sysctl", "sysctl executable path")
	enableFabric := flags.Bool("enable-fabric", false, "explicitly allow Flux to manage fabric links, routes and policy rules")
	wireGuardKeyFile := flags.String("wireguard-key-file", "", "node-local WireGuard private key path; defaults under state-dir")
	publicInterface := flags.String("public-interface", "", "public data interface; required to advertise tc rate limiting")
	ifbInterface := flags.String("ifb-interface", "flux-ifb0", "Flux-owned IFB interface")
	uploadCapacity := flags.Uint64("upload-link-bps", 10_000_000_000, "physical upload link capacity in bits/s")
	downloadCapacity := flags.Uint64("download-link-bps", 10_000_000_000, "physical download link capacity in bits/s")
	allowTCRoot := flags.Bool("allow-tc-root-replace", false, "explicitly allow Flux to own and replace the public root qdisc")
	applyTimeout := flags.Duration("apply-timeout", 45*time.Second, "per-generation apply timeout")
	recoveryTimeout := flags.Duration("recovery-timeout", 45*time.Second, "startup last-known-good recovery timeout")
	policyInterval := flags.Duration("policy-interval", time.Second, "local expiry/drain policy interval")
	usageInterval := flags.Duration("usage-interval", 10*time.Second, "durable usage collection interval")
	reconcileInterval := flags.Duration("reconcile-interval", 15*time.Second, "offline-capable kernel drift audit interval")
	healthInterval := flags.Duration("health-interval", time.Second, "scheduler tick for due backend health probes")
	heartbeatInterval := flags.Duration("heartbeat-interval", 25*time.Second, "Agent status heartbeat interval")
	if err := flags.Parse(args); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	executor, err := nft.NewExecutor(*nftPath, nil)
	if err != nil {
		return err
	}
	stateStore, err := agent.NewFileStore(*stateDirectory)
	if err != nil {
		return err
	}
	options := []agent.Option{agent.WithConntrackCleaner(conntrack.NewCleaner())}
	capabilities := shared.DefaultCapabilities()
	wireGuardPublicKey := ""
	if *publicInterface != "" && *allowTCRoot {
		trafficExecutor, err := dptc.NewExecutor(*tcPath, *ipPath, nil)
		if err != nil {
			return err
		}
		trafficCompiler := dptc.NewCompiler(dptc.Config{PublicInterface: *publicInterface, IFBInterface: *ifbInterface, UploadLinkBitsPerSecond: *uploadCapacity, DownloadLinkBitsPerSecond: *downloadCapacity, AllowReplaceRoot: true})
		options = append(options, agent.WithTrafficControl(trafficCompiler, trafficExecutor))
	} else {
		capabilities = withoutCapability(capabilities, "tc.rate-limit")
	}
	if *enableFabric {
		keyPath := *wireGuardKeyFile
		if keyPath == "" {
			keyPath = filepath.Join(*stateDirectory, "wireguard.key")
		}
		publicKey, err := dpfabric.EnsurePrivateKey(keyPath)
		if err != nil {
			return err
		}
		fabricExecutor, err := dpfabric.NewExecutor(dpfabric.Config{
			IPPath: *ipPath, WGPath: *wgPath, SysctlPath: *sysctlPath,
			PrivateKeyPath: keyPath, AllowManage: true,
		}, nil)
		if err != nil {
			return err
		}
		options = append(options, agent.WithFabric(dpfabric.DefaultCompiler(), fabricExecutor))
		wireGuardPublicKey = publicKey
		logger.Info("node-local WireGuard key ready", "public_key", publicKey)
	} else {
		capabilities = withoutCapabilityPrefix(capabilities, "fabric.")
		capabilities = withoutCapability(capabilities, "nft.via-exit")
	}
	reconciler, err := agent.NewReconciler(nft.DefaultCompiler(), executor, stateStore, time.Now, options...)
	if err != nil {
		return err
	}
	recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), *recoveryTimeout)
	recovery, err := reconciler.Recover(recoveryContext)
	cancelRecovery()
	if err != nil {
		return fmt.Errorf("recover last-known-good dataplane: %w", err)
	}
	logger.Info("last-known-good recovery complete", "generation", recovery.Generation, "changed", recovery.Changed)
	runnerConfig := controlclient.Config{
		Target: *controllerTarget, NodeID: *nodeID, AgentVersion: shared.AgentVersion,
		Capabilities: capabilities, WireGuardPublicKey: wireGuardPublicKey, ApplyTimeout: *applyTimeout,
		PolicyInterval: *policyInterval, UsageInterval: *usageInterval, ReconcileInterval: *reconcileInterval,
		HealthInterval: *healthInterval, HeartbeatInterval: *heartbeatInterval,
		StateDirectory: *stateDirectory, SystemctlPath: "systemctl",
	}
	nodeIdentity, controllerPublicKey, err := agentenrollment.LoadIdentity(*identityDirectory, *nodeID)
	if err != nil {
		return err
	}
	transportCredentials, err := securechannel.NewClientCredentials(*nodeID, nodeIdentity, controllerPublicKey)
	if err != nil {
		return err
	}
	runnerConfig.Credentials = transportCredentials
	runner, err := controlclient.New(runnerConfig, reconciler, stateStore, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = runner.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func runValidate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "desired-state JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	desired, err := readDesired(*file)
	if err != nil {
		return err
	}
	checksum, err := desired.Checksum()
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{
		"valid":      true,
		"node_id":    desired.NodeID,
		"generation": desired.Generation,
		"checksum":   checksum,
	})
}

func runRender(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("render", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "desired-state JSON file")
	existing := flags.Bool("existing-table", false, "render replacement for an existing managed table")
	if err := flags.Parse(args); err != nil {
		return err
	}
	desired, err := readDesired(*file)
	if err != nil {
		return err
	}
	compiler := nft.DefaultCompiler()
	checksum, err := desired.Checksum()
	if err != nil {
		return err
	}
	program, err := compiler.Compile(desired, checksum, *existing)
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, program.Script)
	return err
}

func runRenderFabric(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("render-fabric", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "desired-state JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	desired, err := readDesired(*file)
	if err != nil {
		return err
	}
	checksum, err := desired.Checksum()
	if err != nil {
		return err
	}
	program, err := dpfabric.DefaultCompiler().Compile(desired, checksum)
	if err != nil {
		return err
	}
	encoded, err := dpfabric.MarshalPlan(program)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(encoded))
	return err
}

func runFabricKey(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("fabric-key", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keyFile := flags.String("key-file", "/var/lib/flux-agent/wireguard.key", "node-local WireGuard private key path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	publicKey, err := dpfabric.EnsurePrivateKey(*keyFile)
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"public_key": publicKey, "private_key_file": *keyFile})
}

func runApply(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "desired-state JSON file")
	stateDirectory := flags.String("state-dir", "/var/lib/flux-agent", "durable agent state directory")
	nftPath := flags.String("nft", "nft", "nft executable path")
	traffic := addStandaloneTrafficFlags(flags)
	fabric := addStandaloneFabricFlags(flags, traffic.ipPath)
	timeout := flags.Duration("timeout", 30*time.Second, "nft operation timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	desired, err := readDesired(*file)
	if err != nil {
		return err
	}
	reconciler, err := buildReconciler(*stateDirectory, *nftPath, traffic, fabric)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := reconciler.Apply(ctx, desired)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runRecover(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("recover", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", "/var/lib/flux-agent", "durable agent state directory")
	nftPath := flags.String("nft", "nft", "nft executable path")
	traffic := addStandaloneTrafficFlags(flags)
	fabric := addStandaloneFabricFlags(flags, traffic.ipPath)
	timeout := flags.Duration("timeout", 30*time.Second, "nft operation timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	reconciler, err := buildReconciler(*stateDirectory, *nftPath, traffic, fabric)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := reconciler.Recover(ctx)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runCounters(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("counters", flag.ContinueOnError)
	flags.SetOutput(stderr)
	nftPath := flags.String("nft", "nft", "nft executable path")
	timeout := flags.Duration("timeout", 15*time.Second, "nft operation timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	executor, err := nft.NewExecutor(*nftPath, nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	counters, err := executor.ReadCounters(ctx)
	if err != nil {
		return err
	}
	return writeJSON(stdout, counters)
}

type standaloneTrafficFlags struct {
	tcPath           *string
	ipPath           *string
	publicInterface  *string
	ifbInterface     *string
	uploadCapacity   *uint64
	downloadCapacity *uint64
	allowReplaceRoot *bool
}

type standaloneFabricFlags struct {
	enable         *bool
	ipPath         *string
	wgPath         *string
	sysctlPath     *string
	privateKeyPath *string
}

func addStandaloneTrafficFlags(flags *flag.FlagSet) *standaloneTrafficFlags {
	return &standaloneTrafficFlags{
		tcPath:           flags.String("tc", "tc", "tc executable path"),
		ipPath:           flags.String("ip", "ip", "ip executable path"),
		publicInterface:  flags.String("public-interface", "", "public data interface for tc rate limiting"),
		ifbInterface:     flags.String("ifb-interface", "flux-ifb0", "Flux-owned IFB interface"),
		uploadCapacity:   flags.Uint64("upload-link-bps", 10_000_000_000, "physical upload link capacity in bits/s"),
		downloadCapacity: flags.Uint64("download-link-bps", 10_000_000_000, "physical download link capacity in bits/s"),
		allowReplaceRoot: flags.Bool("allow-tc-root-replace", false, "explicitly allow Flux to own and replace the public root qdisc"),
	}
}

func addStandaloneFabricFlags(flags *flag.FlagSet, ipPath *string) *standaloneFabricFlags {
	return &standaloneFabricFlags{
		enable:         flags.Bool("enable-fabric", false, "explicitly allow Flux to manage fabric links, routes and policy rules"),
		ipPath:         ipPath,
		wgPath:         flags.String("wg", "wg", "wg executable path"),
		sysctlPath:     flags.String("sysctl", "sysctl", "sysctl executable path"),
		privateKeyPath: flags.String("wireguard-key-file", "", "node-local WireGuard private key path; defaults under state-dir"),
	}
}

func buildReconciler(stateDirectory, nftPath string, traffic *standaloneTrafficFlags, fabricFlags *standaloneFabricFlags) (*agent.Reconciler, error) {
	executor, err := nft.NewExecutor(nftPath, nil)
	if err != nil {
		return nil, err
	}
	store, err := agent.NewFileStore(stateDirectory)
	if err != nil {
		return nil, err
	}
	options := []agent.Option{agent.WithConntrackCleaner(conntrack.NewCleaner())}
	if traffic != nil && *traffic.publicInterface != "" {
		if !*traffic.allowReplaceRoot {
			return nil, errors.New("--allow-tc-root-replace is required with --public-interface")
		}
		trafficExecutor, err := dptc.NewExecutor(*traffic.tcPath, *traffic.ipPath, nil)
		if err != nil {
			return nil, err
		}
		trafficCompiler := dptc.NewCompiler(dptc.Config{PublicInterface: *traffic.publicInterface, IFBInterface: *traffic.ifbInterface, UploadLinkBitsPerSecond: *traffic.uploadCapacity, DownloadLinkBitsPerSecond: *traffic.downloadCapacity, AllowReplaceRoot: true})
		options = append(options, agent.WithTrafficControl(trafficCompiler, trafficExecutor))
	}
	if fabricFlags != nil && *fabricFlags.enable {
		keyPath := *fabricFlags.privateKeyPath
		if keyPath == "" {
			keyPath = filepath.Join(stateDirectory, "wireguard.key")
		}
		if _, err := dpfabric.EnsurePrivateKey(keyPath); err != nil {
			return nil, err
		}
		fabricExecutor, err := dpfabric.NewExecutor(dpfabric.Config{
			IPPath: *fabricFlags.ipPath, WGPath: *fabricFlags.wgPath, SysctlPath: *fabricFlags.sysctlPath,
			PrivateKeyPath: keyPath, AllowManage: true,
		}, nil)
		if err != nil {
			return nil, err
		}
		options = append(options, agent.WithFabric(dpfabric.DefaultCompiler(), fabricExecutor))
	}
	return agent.NewReconciler(nft.DefaultCompiler(), executor, store, time.Now, options...)
}

func withoutCapability(capabilities []*controlv1.Capability, name string) []*controlv1.Capability {
	result := make([]*controlv1.Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		if capability != nil && capability.Name != name {
			result = append(result, capability)
		}
	}
	return result
}

func withoutCapabilityPrefix(capabilities []*controlv1.Capability, prefix string) []*controlv1.Capability {
	result := make([]*controlv1.Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		if capability != nil && !strings.HasPrefix(capability.Name, prefix) {
			result = append(result, capability)
		}
	}
	return result
}

func readDesired(path string) (spec.DesiredState, error) {
	if path == "" {
		return spec.DesiredState{}, errors.New("--file is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return spec.DesiredState{}, fmt.Errorf("open desired state: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return spec.DesiredState{}, fmt.Errorf("stat desired state: %w", err)
	}
	if info.Size() > maxDesiredFileBytes {
		return spec.DesiredState{}, fmt.Errorf("desired state exceeds %d bytes", maxDesiredFileBytes)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxDesiredFileBytes+1))
	if err != nil {
		return spec.DesiredState{}, fmt.Errorf("read desired state: %w", err)
	}
	return spec.DecodeDesiredJSON(encoded)
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file path is required")
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(encoded)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return encoded, nil
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: flux-agent <install|enroll|run|validate|render|render-fabric|fabric-key|apply|recover|counters|version> [flags]")
}
