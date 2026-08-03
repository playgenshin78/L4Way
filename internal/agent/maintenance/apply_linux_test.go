//go:build linux

package maintenance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyUpgradeInstallsVerifiedExecutable(t *testing.T) {
	root := t.TempDir()
	maintenanceDirectory := filepath.Join(root, "maintenance")
	if err := os.MkdirAll(maintenanceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "flux-agent")
	staged := filepath.Join(maintenanceDirectory, "flux-agent.new")
	requestPath := filepath.Join(maintenanceDirectory, "request.json")
	writeExecutable(t, destination, "#!/bin/sh\nprintf 'old'\n")
	writeExecutable(t, staged, "#!/bin/sh\nprintf '{\"agent_version\":\"new\"}\\n'\n")
	if err := os.WriteFile(requestPath, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := Request{DestinationExecutable: destination, StagedBinary: staged}
	if err := applyUpgrade(context.Background(), request, requestPath); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(destination)
	if err != nil || !strings.Contains(string(installed), "agent_version") {
		t.Fatalf("installed=%q err=%v", installed, err)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged binary still exists: %v", err)
	}
}

func TestApplyUpgradeRollsBackFailedExecutable(t *testing.T) {
	root := t.TempDir()
	maintenanceDirectory := filepath.Join(root, "maintenance")
	if err := os.MkdirAll(maintenanceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "flux-agent")
	staged := filepath.Join(maintenanceDirectory, "flux-agent.new")
	requestPath := filepath.Join(maintenanceDirectory, "request.json")
	writeExecutable(t, destination, "#!/bin/sh\nprintf 'old'\n")
	writeExecutable(t, staged, "#!/bin/sh\nexit 1\n")
	if err := os.WriteFile(requestPath, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := Request{DestinationExecutable: destination, StagedBinary: staged}
	if err := applyUpgrade(context.Background(), request, requestPath); err == nil {
		t.Fatal("expected verification failure")
	}
	installed, err := os.ReadFile(destination)
	if err != nil || !strings.Contains(string(installed), "old") {
		t.Fatalf("rollback=%q err=%v", installed, err)
	}
}

func TestApplyUninstallRemovesInstallationAfterDisablingService(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "systemctl.log")
	t.Setenv("FLUX_TEST_SYSTEMCTL_LOG", logPath)
	systemctl := filepath.Join(root, "systemctl")
	writeExecutable(t, systemctl, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FLUX_TEST_SYSTEMCTL_LOG\"\n")
	request := Request{
		AgentUnitPath:         filepath.Join(root, "flux-agent.service"),
		MaintenanceUnitPath:   filepath.Join(root, "flux-agent-maintenance.service"),
		DestinationExecutable: filepath.Join(root, "flux-agent"),
	}
	sysctlPath := filepath.Join(root, "90-flux-forwarding.conf")
	requestPath := filepath.Join(root, "request.json")
	for _, path := range []string{request.AgentUnitPath, request.MaintenanceUnitPath, request.DestinationExecutable, sysctlPath, requestPath} {
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := applyUninstall(context.Background(), request, requestPath, systemctl, sysctlPath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{request.AgentUnitPath, request.MaintenanceUnitPath, request.DestinationExecutable, sysctlPath, requestPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("uninstall left %s: %v", path, err)
		}
	}
	commands, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(commands), "disable flux-agent.service") || !strings.Contains(string(commands), "daemon-reload") {
		t.Fatalf("systemctl calls=%q", commands)
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}
