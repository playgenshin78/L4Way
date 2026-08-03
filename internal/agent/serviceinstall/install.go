package serviceinstall

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"flux.local/flux/internal/agent/maintenance"
	"flux.local/flux/internal/spec"
)

const (
	ServiceName            = "flux-agent.service"
	MaintenanceServiceName = "flux-agent-maintenance.service"
)

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

type Config struct {
	SourceExecutable      string
	DestinationExecutable string
	UnitPath              string
	MaintenanceUnitPath   string
	IdentityDirectory     string
	StateDirectory        string
	ControllerAddress     string
	NodeID                string
	EnableFabric          bool
	PublicInterface       string
	AllowTCRootReplace    bool
}

func (c Config) Validate() error {
	if err := spec.ValidateIdentifier("node_id", c.NodeID); err != nil {
		return err
	}
	if err := validateControllerAddress(c.ControllerAddress); err != nil {
		return err
	}
	for name, path := range map[string]string{
		"source executable": c.SourceExecutable, "destination executable": c.DestinationExecutable,
		"systemd unit": c.UnitPath, "maintenance systemd unit": c.MaintenanceUnitPath,
		"identity directory": c.IdentityDirectory, "state directory": c.StateDirectory,
	} {
		if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
			return fmt.Errorf("%s path must be absolute and safe", name)
		}
	}
	if strings.ContainsAny(c.DestinationExecutable+c.IdentityDirectory+c.StateDirectory, "\t ") {
		return errors.New("service executable and state paths must not contain whitespace")
	}
	if c.PublicInterface != "" && !interfaceNamePattern.MatchString(c.PublicInterface) {
		return errors.New("public interface name is invalid")
	}
	if c.PublicInterface != "" && !c.AllowTCRootReplace || c.AllowTCRootReplace && c.PublicInterface == "" {
		return errors.New("public interface and tc root replacement permission must be configured together")
	}
	return nil
}

func RenderUnit(config Config) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	arguments := []string{
		config.DestinationExecutable, "run",
		"--controller=" + config.ControllerAddress,
		"--node-id=" + config.NodeID,
		"--identity-dir=" + config.IdentityDirectory,
		"--state-dir=" + config.StateDirectory,
	}
	if config.EnableFabric {
		arguments = append(arguments, "--enable-fabric")
	}
	if config.PublicInterface != "" {
		arguments = append(arguments, "--public-interface="+config.PublicInterface, "--allow-tc-root-replace")
	}
	unit := `[Unit]
Description=Flux Linux forwarding node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
ExecStart=` + strings.Join(arguments, " ") + `
Restart=always
RestartSec=3s
TimeoutStopSec=30s
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=false
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=false
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=` + config.StateDirectory + `

[Install]
WantedBy=multi-user.target
`
	return unit, nil
}

func RenderMaintenanceUnit(config Config) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	unit := `[Unit]
Description=Flux Agent privileged maintenance helper
After=network-online.target

[Service]
Type=oneshot
User=root
UMask=0077
ExecStart=` + config.DestinationExecutable + ` maintenance --request=` + maintenance.RequestPath(config.StateDirectory) + ` --systemctl=systemctl
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX
`
	return unit, nil
}

// InstallFiles atomically installs the current executable and the systemd
// unit. Enrollment is deliberately performed by the caller after this
// succeeds, so a filesystem error cannot consume a one-time token.
func InstallFiles(config Config) error {
	unit, err := RenderUnit(config)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.StateDirectory, 0o700); err != nil {
		return fmt.Errorf("create Agent state directory: %w", err)
	}
	if err := os.MkdirAll(config.IdentityDirectory, 0o700); err != nil {
		return fmt.Errorf("create Agent identity directory: %w", err)
	}
	source, err := filepath.Abs(config.SourceExecutable)
	if err != nil {
		return fmt.Errorf("resolve Agent executable path: %w", err)
	}
	destination := filepath.Clean(config.DestinationExecutable)
	if !samePath(source, destination) {
		if err := copyAtomic(source, destination, 0o755); err != nil {
			return fmt.Errorf("install Agent executable: %w", err)
		}
	}
	if err := writeAtomic(config.UnitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("install systemd unit: %w", err)
	}
	maintenanceUnit, err := RenderMaintenanceUnit(config)
	if err != nil {
		return err
	}
	if err := writeAtomic(config.MaintenanceUnitPath, []byte(maintenanceUnit), 0o644); err != nil {
		return fmt.Errorf("install maintenance systemd unit: %w", err)
	}
	return nil
}

func Activate(ctx context.Context, systemctlPath string) error {
	return activate(ctx, systemctlPath)
}

func Preflight(systemctlPath string) error {
	return preflight(systemctlPath)
}

func validateControllerAddress(value string) error {
	if strings.TrimSpace(value) == "" || strings.Contains(value, "://") || strings.ContainsAny(value, "\r\n\t \x00") {
		return errors.New("Controller control address must be host:port without a URL scheme")
	}
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("Controller control address must be host:port: %w", err)
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return errors.New("Controller control address port is invalid")
	}
	return nil
}

func copyAtomic(sourcePath, destinationPath string, mode os.FileMode) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destinationPath), ".flux-agent-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := io.Copy(temporary, io.LimitReader(source, 512<<20)); err != nil {
		return err
	}
	if info, err := source.Stat(); err != nil {
		return err
	} else if info.Size() > 512<<20 {
		return errors.New("Agent executable exceeds 512 MiB")
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporaryPath, destinationPath); err != nil {
		return err
	}
	committed = true
	return syncDirectory(filepath.Dir(destinationPath))
}

func writeAtomic(destinationPath string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destinationPath), ".flux-unit-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporaryPath, destinationPath); err != nil {
		return err
	}
	committed = true
	return syncDirectory(filepath.Dir(destinationPath))
}

func samePath(left, right string) bool {
	leftAbsolute, leftErr := filepath.Abs(left)
	rightAbsolute, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && strings.EqualFold(filepath.Clean(leftAbsolute), filepath.Clean(rightAbsolute))
}
