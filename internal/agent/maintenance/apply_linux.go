//go:build linux

package maintenance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const MaintenanceServiceName = "flux-agent-maintenance.service"

func Apply(ctx context.Context, requestPath, systemctlPath string) error {
	request, err := LoadRequest(requestPath)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("Agent maintenance must run as root")
	}
	if _, err := exec.LookPath(systemctlPath); err != nil {
		return fmt.Errorf("systemctl is required: %w", err)
	}
	switch request.Action {
	case ActionUpgrade:
		return applyUpgrade(ctx, request, requestPath)
	case ActionUninstall:
		return applyUninstall(ctx, request, requestPath, systemctlPath, DefaultForwardingSysctl)
	default:
		return errors.New("unsupported maintenance action")
	}
}

func Start(ctx context.Context, systemctlPath string) error {
	if _, err := exec.LookPath(systemctlPath); err != nil {
		return fmt.Errorf("systemctl is required: %w", err)
	}
	command := exec.CommandContext(ctx, systemctlPath, "start", MaintenanceServiceName)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("start Agent maintenance service: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func RestartAgent(systemctlPath string) error {
	command := exec.Command(systemctlPath, "restart", "--no-block", "flux-agent.service")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("restart Agent service: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func StopAgent(systemctlPath string) error {
	command := exec.Command(systemctlPath, "stop", "--no-block", "flux-agent.service")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("stop Agent service: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func applyUpgrade(ctx context.Context, request Request, requestPath string) error {
	if _, err := os.Stat(request.StagedBinary); err != nil {
		return fmt.Errorf("read staged Agent: %w", err)
	}
	maintenanceDirectory := filepath.Dir(requestPath)
	previous := filepath.Join(maintenanceDirectory, "flux-agent.previous")
	if err := copyAtomic(request.DestinationExecutable, previous, 0o700); err != nil {
		return fmt.Errorf("backup current Agent: %w", err)
	}
	if err := copyAtomic(request.StagedBinary, request.DestinationExecutable, 0o755); err != nil {
		return fmt.Errorf("install staged Agent: %w", err)
	}
	verifyContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(verifyContext, request.DestinationExecutable, "version")
	output, err := command.Output()
	if err != nil || len(output) == 0 || len(output) > 4096 {
		verificationErr := err
		if verificationErr == nil {
			verificationErr = errors.New("version output is empty or too large")
		}
		rollbackErr := copyAtomic(previous, request.DestinationExecutable, 0o755)
		if rollbackErr != nil {
			return fmt.Errorf("new Agent verification failed and rollback failed: verify=%v rollback=%v", verificationErr, rollbackErr)
		}
		return fmt.Errorf("new Agent verification failed: %w", verificationErr)
	}
	_ = os.Remove(request.StagedBinary)
	_ = os.Remove(requestPath)
	return nil
}

func applyUninstall(ctx context.Context, request Request, requestPath, systemctlPath, forwardingSysctlPath string) error {
	// Do not stop the running Agent here: it must first return a successful
	// command result. The Agent stops itself immediately after that response.
	disable := exec.CommandContext(ctx, systemctlPath, "disable", "flux-agent.service")
	if output, err := disable.CombinedOutput(); err != nil {
		return fmt.Errorf("disable Agent service: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, target := range []string{request.AgentUnitPath, request.MaintenanceUnitPath, request.DestinationExecutable, forwardingSysctlPath} {
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", target, err)
		}
	}
	daemonReload := exec.CommandContext(ctx, systemctlPath, "daemon-reload")
	if output, err := daemonReload.CombinedOutput(); err != nil {
		return fmt.Errorf("reload systemd after Agent uninstall: %w: %s", err, strings.TrimSpace(string(output)))
	}
	_ = os.Remove(requestPath)
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
	temporary, err := os.CreateTemp(filepath.Dir(destinationPath), ".flux-maintenance-")
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
	written, err := io.Copy(temporary, io.LimitReader(source, maxBinaryBytes+1))
	if err != nil {
		return err
	}
	if written > maxBinaryBytes {
		return errors.New("Agent executable exceeds the allowed size")
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destinationPath); err != nil {
		return err
	}
	committed = true
	return nil
}
