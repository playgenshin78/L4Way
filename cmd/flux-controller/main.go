package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/cluster"
	shared "flux.local/flux/internal/control"
	"flux.local/flux/internal/controller/archive"
	controllercontrol "flux.local/flux/internal/controller/control"
	"flux.local/flux/internal/controller/enrollment"
	"flux.local/flux/internal/controller/iam"
	"flux.local/flux/internal/controller/instance"
	"flux.local/flux/internal/controller/management"
	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/securechannel"
	"flux.local/flux/internal/spec"

	"google.golang.org/grpc"
)

const maxConfigFileBytes = int64(64 << 20)

var controllerVersion = "dev"

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
	case "key-init":
		err = runKeyInit(args[1:], stdout, stderr)
	case "migrate":
		err = runMigrate(args[1:], stdout, stderr)
	case "owner-init":
		err = runOwnerInit(args[1:], stdout, stderr)
	case "token":
		err = runToken(args[1:], stdout, stderr)
	case "publish":
		err = runPublish(args[1:], stdout, stderr)
	case "plan-validate":
		err = runPlanValidate(args[1:], stdout, stderr)
	case "plan-apply":
		err = runPlanApply(args[1:], stdout, stderr)
	case "plan-status":
		err = runPlanStatus(args[1:], stdout, stderr)
	case "plan-rollback":
		err = runPlanRollback(args[1:], stdout, stderr)
	case "backup":
		err = runBackup(args[1:], stdout, stderr)
	case "restore":
		err = runRestore(args[1:], stdout, stderr)
	case "serve":
		err = runServe(args[1:], stderr)
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

func runKeyInit(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("key-init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("dir", "./state", "Controller state directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	pair, err := securechannel.GenerateKeyPair()
	if err != nil {
		return err
	}
	path := filepath.Join(*directory, "controller-noise.key")
	if err := securechannel.WriteKeyPair(path, pair); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{
		"key_file": path, "public_key": securechannel.EncodePublicKey(pair.Public),
		"fingerprint": securechannel.Fingerprint(pair.Public), "protocol": "Noise_IK_25519_AESGCM_SHA256",
	})
}

func runMigrate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", defaultDatabasePath(), "SQLite database file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := store.Open(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"migrated": true})
}

func runOwnerInit(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("owner-init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", defaultDatabasePath(), "SQLite database file")
	username := flags.String("username", "owner", "Owner login username")
	displayName := flags.String("display-name", "Owner", "Owner display name")
	passwordFile := flags.String("password-file", "", "0600 file containing the initial Owner password")
	ifMissing := flags.Bool("if-missing", false, "succeed without changing credentials when an Owner already exists")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*passwordFile) == "" {
		return errors.New("--password-file is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := openMigrated(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer repository.Close()
	if *ifMissing {
		count, err := repository.OwnerCount(ctx)
		if err != nil {
			return err
		}
		if count != 0 {
			return writeJSON(stdout, map[string]any{"created": false, "reason": "owner_already_exists"})
		}
	}
	encoded, err := readLimited(*passwordFile, 1024)
	if err != nil {
		return err
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(encoded), "\n"), "\r")
	if strings.ContainsAny(password, "\r\n") {
		return errors.New("Owner password file must contain exactly one line")
	}
	passwordHash, err := iam.HashPassword(password)
	if err != nil {
		return err
	}
	account, err := repository.CreateOwner(ctx, *username, *displayName, passwordHash)
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"created": true, "account": account})
}

func runToken(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("token", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", defaultDatabasePath(), "SQLite database file")
	nodeID := flags.String("node-id", "", "node identity bound to this token")
	ttl := flags.Duration("ttl", 15*time.Minute, "single-use token lifetime")
	controllerKeyPath := flags.String("controller-key", "./state/controller-noise.key", "Controller Noise identity file")
	enrollmentAddress := flags.String("enroll-address", "", "optional public enrollment host:port stored in the bundle")
	controlAddress := flags.String("control-address", "", "optional public Noise control host:port stored in the bundle")
	output := flags.String("out", "", "optional 0600 enrollment bundle file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := openMigrated(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer repository.Close()
	token, expiresAt, err := repository.CreateEnrollmentToken(ctx, *nodeID, *ttl)
	if err != nil {
		return err
	}
	controllerIdentity, err := securechannel.LoadKeyPair(*controllerKeyPath)
	if err != nil {
		return err
	}
	bundle := map[string]any{
		"version": 1, "node_id": *nodeID, "token": token, "expires_at": expiresAt,
		"controller_public_key":      securechannel.EncodePublicKey(controllerIdentity.Public),
		"controller_key_fingerprint": securechannel.Fingerprint(controllerIdentity.Public),
	}
	if strings.TrimSpace(*enrollmentAddress) != "" {
		bundle["enrollment_address"] = strings.TrimSpace(*enrollmentAddress)
	}
	if strings.TrimSpace(*controlAddress) != "" {
		bundle["control_address"] = strings.TrimSpace(*controlAddress)
	}
	if *output != "" {
		encoded, err := json.MarshalIndent(bundle, "", "  ")
		if err != nil {
			return err
		}
		if err := writeExclusive(*output, append(encoded, '\n'), 0o600); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"node_id": *nodeID, "bundle_file": *output, "expires_at": expiresAt})
	}
	return writeJSON(stdout, bundle)
}

func runPublish(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("publish", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", defaultDatabasePath(), "SQLite database file")
	file := flags.String("file", "", "desired-state JSON file; Controller assigns its generation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	desired, err := readDesired(*file)
	if err != nil {
		return err
	}
	required, err := json.Marshal(requiredCapabilities(desired))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := openMigrated(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer repository.Close()
	record, err := repository.PublishDesired(ctx, desired.NodeID, desired, required)
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"node_id": record.NodeID, "generation": record.Generation, "checksum": record.DesiredChecksum, "created_at": record.CreatedAt})
}

func runPlanValidate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plan-validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "cluster-plan JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	plan, err := readClusterPlan(*file)
	if err != nil {
		return err
	}
	checksum, err := plan.Checksum()
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"valid": true, "plan_id": plan.ID, "revision": plan.Revision, "checksum": checksum, "nodes": len(plan.Nodes), "forwards": len(plan.Forwards)})
}

func runPlanApply(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plan-apply", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", defaultDatabasePath(), "SQLite database file")
	file := flags.String("file", "", "cluster-plan JSON file")
	actor := flags.String("actor", "", "authenticated operator identity for audit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	plan, err := readClusterPlan(*file)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	repository, err := openMigrated(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer repository.Close()
	result, err := repository.ApplyClusterPlan(ctx, plan, *actor)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runPlanStatus(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plan-status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", defaultDatabasePath(), "SQLite database file")
	planID := flags.String("plan-id", "", "cluster plan identity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := openMigrated(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer repository.Close()
	status, err := repository.ClusterStatus(ctx, *planID)
	if err != nil {
		return err
	}
	return writeJSON(stdout, status)
}

func runPlanRollback(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plan-rollback", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", defaultDatabasePath(), "SQLite database file")
	planID := flags.String("plan-id", "", "cluster plan identity")
	revision := flags.Uint64("revision", 0, "stored cluster revision to reactivate")
	actor := flags.String("actor", "", "authenticated operator identity for audit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	repository, err := openMigrated(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer repository.Close()
	result, err := repository.RollbackClusterPlan(ctx, *planID, *revision, *actor)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runServe(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", defaultDatabasePath(), "SQLite database file")
	controlAddress := flags.String("control-address", ":9443", "Noise/AES-GCM gRPC listen address")
	enrollAddress := flags.String("enroll-address", ":8443", "Noise/AES-GCM enrollment listen address")
	publicControlAddress := flags.String("public-control-address", "", "Agent-reachable control host:port used in install commands")
	publicEnrollAddress := flags.String("public-enroll-address", "", "Agent-reachable enrollment host:port used in install commands")
	nodeInstallerURL := flags.String("node-installer-url", "", "HTTPS URL of install.sh used by one-click node commands")
	nodeReleaseURL := flags.String("node-release-url", "", "HTTPS URL of the verified Flux release archive used by one-click node commands")
	managementAddress := flags.String("management-address", "127.0.0.1:8080", "loopback-only management API listen address")
	managementCookieSecure := flags.Bool("management-cookie-secure", true, "mark management session cookies Secure; disable only for loopback development")
	managementSessionTTL := flags.Duration("management-session-ttl", 24*time.Hour, "Owner/Tenant login session lifetime")
	managementPlanID := flags.String("management-plan-id", "default", "cluster plan managed by the Owner/Tenant API")
	managementBackupDirectory := flags.String("management-backup-directory", "", "directory for online backup archives; defaults beside the SQLite database")
	webRoot := flags.String("web-root", "", "optional built React UI directory; serves it from the management listener")
	controllerKeyPath := flags.String("controller-key", "./state/controller-noise.key", "Controller Noise identity file")
	lockPath := flags.String("lock-file", "", "single-Controller lock file; defaults beside the database")
	pollInterval := flags.Duration("snapshot-poll-interval", 5*time.Second, "fallback desired-state poll interval")
	pingInterval := flags.Duration("ping-interval", 30*time.Second, "Controller ping interval")
	authorizeInterval := flags.Duration("auth-check-interval", 30*time.Second, "node key revocation check interval")
	heartbeatTimeout := flags.Duration("heartbeat-timeout", 95*time.Second, "disconnect agents silent for this duration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *pollInterval <= 0 || *pingInterval <= 0 || *authorizeInterval <= 0 || *heartbeatTimeout <= 0 || *managementSessionTTL <= 0 {
		return errors.New("Controller intervals must be positive")
	}
	if err := validateManagementAddress(*managementAddress); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if strings.TrimSpace(*lockPath) == "" {
		*lockPath = *databasePath + ".controller.lock"
	}
	controllerLock, err := instance.Acquire(*lockPath)
	if err != nil {
		return err
	}
	defer controllerLock.Close()
	repository, err := openMigrated(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer repository.Close()
	if strings.TrimSpace(*managementBackupDirectory) == "" {
		*managementBackupDirectory = filepath.Join(filepath.Dir(repository.Path()), "backups")
	}
	ownerCount, err := repository.OwnerCount(ctx)
	if err != nil {
		return err
	}
	if ownerCount == 0 {
		logger.Warn("management API has no Owner account; run flux-controller owner-init before login")
	}
	controllerIdentity, err := securechannel.LoadKeyPair(*controllerKeyPath)
	if err != nil {
		return err
	}
	transportCredentials, err := securechannel.NewServerCredentials(controllerIdentity, func(authContext context.Context, nodeID string, publicKey []byte) error {
		return repository.AuthorizeNodeKey(authContext, nodeID, publicKey, time.Now().UTC())
	})
	if err != nil {
		return err
	}
	notifier := controllercontrol.NewNotifier()
	commandBroker := controllercontrol.NewCommandBroker()
	controlServer, err := controllercontrol.NewServerWithConfig(repository, notifier, logger, controllercontrol.ServerConfig{
		PollInterval: *pollInterval, PingInterval: *pingInterval,
		AuthorizeInterval: *authorizeInterval, HeartbeatTimeout: *heartbeatTimeout,
		Commands: commandBroker,
	})
	if err != nil {
		return err
	}
	grpcServer := grpc.NewServer(grpc.Creds(transportCredentials), grpc.MaxRecvMsgSize(int(spec.MaxDesiredJSONBytes+1<<20)))
	controlv1.RegisterAgentControlServer(grpcServer, controlServer)
	controlListener, err := net.Listen("tcp", *controlAddress)
	if err != nil {
		return fmt.Errorf("listen for Noise control channel: %w", err)
	}
	defer controlListener.Close()
	enrollmentServer, err := enrollment.NewServer(controllerIdentity, repository, logger, time.Now)
	if err != nil {
		return err
	}
	enrollmentListener, err := net.Listen("tcp", *enrollAddress)
	if err != nil {
		return fmt.Errorf("listen for Noise enrollment: %w", err)
	}
	defer enrollmentListener.Close()
	managementServer, err := management.New(repository, logger, management.Config{
		SessionTTL: *managementSessionTTL, CookieSecure: *managementCookieSecure, PlanID: *managementPlanID,
		ControllerPublicKey:     securechannel.EncodePublicKey(controllerIdentity.Public),
		PublicEnrollmentAddress: strings.TrimSpace(*publicEnrollAddress), PublicControlAddress: strings.TrimSpace(*publicControlAddress),
		NodeInstallerURL: strings.TrimSpace(*nodeInstallerURL), NodeReleaseURL: strings.TrimSpace(*nodeReleaseURL),
		NodeOfflineAfter: *heartbeatTimeout,
		DatabasePath:     repository.Path(), BackupDirectory: *managementBackupDirectory,
		Backup: func(backupContext context.Context, destination string) error {
			return archive.Create(backupContext, repository, *controllerKeyPath, destination)
		},
		ControllerVersion: controllerVersion, AgentMinVersion: shared.AgentVersion,
		NodeCommands: commandBroker,
	})
	if err != nil {
		return err
	}
	managementListener, err := net.Listen("tcp", *managementAddress)
	if err != nil {
		return fmt.Errorf("listen for management API: %w", err)
	}
	defer managementListener.Close()
	managementHandler := managementServer.Handler()
	if strings.TrimSpace(*webRoot) != "" {
		managementHandler, err = withWebUI(managementHandler, *webRoot)
		if err != nil {
			return err
		}
	}
	managementHTTP := &http.Server{
		Handler: managementHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	workerID := makeWorkerID()
	worker, err := controllercontrol.NewWorker(repository, notifier, workerID, logger)
	if err != nil {
		return err
	}
	errCh := make(chan error, 4)
	go func() { errCh <- grpcServer.Serve(controlListener) }()
	go func() { errCh <- enrollmentServer.Serve(enrollmentListener) }()
	go func() { errCh <- managementHTTP.Serve(managementListener) }()
	go func() { errCh <- worker.Run(ctx) }()
	logger.Info("Flux Controller started", "control_address", *controlAddress, "enroll_address", *enrollAddress,
		"management_address", *managementAddress, "management_plan_id", *managementPlanID, "web_root", strings.TrimSpace(*webRoot),
		"worker", workerID, "transport", "Noise_IK_25519_AESGCM_SHA256", "database", repository.Path())
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	stop()
	_ = enrollmentListener.Close()
	_ = managementListener.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = managementHTTP.Shutdown(shutdownCtx)
	grpcStopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(grpcStopped)
	}()
	select {
	case <-grpcStopped:
	case <-shutdownCtx.Done():
		grpcServer.Stop()
	}
	return nil
}

func runBackup(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", defaultDatabasePath(), "SQLite database file")
	controllerKeyPath := flags.String("controller-key", "./state/controller-noise.key", "Controller Noise identity file")
	output := flags.String("out", "", "destination .tar.gz backup archive")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*output) == "" {
		return errors.New("--out is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	repository, err := openMigrated(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer repository.Close()
	if err := archive.Create(ctx, repository, *controllerKeyPath, *output); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"backed_up": true, "archive": *output})
}

func runRestore(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("in", "", "source .tar.gz backup archive")
	databasePath := flags.String("database", defaultDatabasePath(), "restored SQLite database file")
	controllerKeyPath := flags.String("controller-key", "./state/controller-noise.key", "restored Controller Noise identity file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*input) == "" {
		return errors.New("--in is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := archive.Restore(ctx, *input, *databasePath, *controllerKeyPath); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"restored": true, "database": *databasePath, "controller_key": *controllerKeyPath})
}

func openMigrated(ctx context.Context, databasePath string) (*store.Store, error) {
	repository, err := store.Open(ctx, databasePath)
	if err != nil {
		return nil, err
	}
	if err := repository.Migrate(ctx); err != nil {
		repository.Close()
		return nil, err
	}
	return repository, nil
}

func defaultDatabasePath() string {
	if value := strings.TrimSpace(os.Getenv("FLUX_DATABASE_PATH")); value != "" {
		return value
	}
	return "./state/flux.db"
}

func validateManagementAddress(address string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("management address must be loopback host:port: %w", err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("management API must listen on loopback and be exposed only through a trusted same-host reverse proxy")
	}
	return nil
}

func readDesired(path string) (spec.DesiredState, error) {
	if path == "" {
		return spec.DesiredState{}, errors.New("--file is required")
	}
	encoded, err := readLimited(path, maxConfigFileBytes)
	if err != nil {
		return spec.DesiredState{}, err
	}
	return spec.DecodeDesiredJSON(encoded)
}

func readClusterPlan(path string) (cluster.Plan, error) {
	if path == "" {
		return cluster.Plan{}, errors.New("--file is required")
	}
	encoded, err := readLimited(path, cluster.MaxPlanJSONBytes)
	if err != nil {
		return cluster.Plan{}, err
	}
	return cluster.DecodePlanJSON(encoded)
}

func requiredCapabilities(desired spec.DesiredState) []*controlv1.Capability {
	return shared.RequiredCapabilities(desired)
}

func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, limit)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(encoded)) > limit {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, limit)
	}
	return encoded, nil
}

func splitNonEmpty(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func makeWorkerID() string {
	random := make([]byte, 8)
	_, _ = rand.Read(random)
	host, _ := os.Hostname()
	return host + "-" + strconv.Itoa(os.Getpid()) + "-" + hex.EncodeToString(random)
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	remove = false
	return nil
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: flux-controller <key-init|migrate|owner-init|token|publish|plan-validate|plan-apply|plan-status|plan-rollback|backup|restore|serve> [flags]")
}
