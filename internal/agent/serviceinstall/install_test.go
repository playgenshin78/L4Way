package serviceinstall

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderUnitUsesNoiseControlAndRestrictedCapabilities(t *testing.T) {
	root := t.TempDir()
	config := Config{
		SourceExecutable: filepath.Join(root, "source"), DestinationExecutable: filepath.Join(root, "bin", "flux-agent"),
		UnitPath: filepath.Join(root, "systemd", ServiceName), MaintenanceUnitPath: filepath.Join(root, "systemd", MaintenanceServiceName),
		IdentityDirectory: filepath.Join(root, "state", "identity"),
		StateDirectory:    filepath.Join(root, "state"), ControllerAddress: "controller.example:9443", NodeID: "node-a",
		EnableFabric: true, PublicInterface: "ens3", AllowTCRootReplace: true,
	}
	unit, err := RenderUnit(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"ExecStart=" + config.DestinationExecutable + " run", "--controller=controller.example:9443", "--node-id=node-a",
		"--enable-fabric", "--public-interface=ens3", "--allow-tc-root-replace", "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW",
		"NoNewPrivileges=true", "ProtectSystem=strict", "ReadWritePaths=" + config.StateDirectory,
	} {
		if !strings.Contains(unit, expected) {
			t.Fatalf("unit is missing %q:\n%s", expected, unit)
		}
	}
}

func TestRenderMaintenanceUnitUsesFixedOneShotHelper(t *testing.T) {
	root := t.TempDir()
	config := Config{
		SourceExecutable: filepath.Join(root, "source"), DestinationExecutable: filepath.Join(root, "bin", "flux-agent"),
		UnitPath: filepath.Join(root, "systemd", ServiceName), MaintenanceUnitPath: filepath.Join(root, "systemd", MaintenanceServiceName),
		IdentityDirectory: filepath.Join(root, "state", "identity"), StateDirectory: filepath.Join(root, "state"),
		ControllerAddress: "controller.example:9443", NodeID: "node-a",
	}
	unit, err := RenderMaintenanceUnit(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Type=oneshot",
		"ExecStart=" + config.DestinationExecutable + " maintenance",
		"--request=" + filepath.Join(config.StateDirectory, "maintenance", "request.json"),
		"NoNewPrivileges=true",
		"RestrictAddressFamilies=AF_UNIX",
	} {
		if !strings.Contains(unit, expected) {
			t.Fatalf("maintenance unit is missing %q:\n%s", expected, unit)
		}
	}
}

func TestInstallFilesCopiesExecutableAndWritesUnit(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source", "flux-agent")
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("agent-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := Config{
		SourceExecutable: source, DestinationExecutable: filepath.Join(root, "bin", "flux-agent"),
		UnitPath: filepath.Join(root, "systemd", ServiceName), MaintenanceUnitPath: filepath.Join(root, "systemd", MaintenanceServiceName),
		IdentityDirectory: filepath.Join(root, "state", "identity"),
		StateDirectory:    filepath.Join(root, "state"), ControllerAddress: "127.0.0.1:9443", NodeID: "node-a",
	}
	if err := InstallFiles(config); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(config.DestinationExecutable)
	if err != nil || string(installed) != "agent-binary" {
		t.Fatalf("installed executable=%q err=%v", installed, err)
	}
	unit, err := os.ReadFile(config.UnitPath)
	if err != nil || !strings.Contains(string(unit), "flux-agent run") {
		t.Fatalf("installed unit=%q err=%v", unit, err)
	}
	maintenanceUnit, err := os.ReadFile(config.MaintenanceUnitPath)
	if err != nil || !strings.Contains(string(maintenanceUnit), "flux-agent maintenance") {
		t.Fatalf("installed maintenance unit=%q err=%v", maintenanceUnit, err)
	}
}

func TestRenderedUnitsPassSystemdAnalyze(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd unit verification is Linux-only")
	}
	analyzer, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze is not installed")
	}
	root := t.TempDir()
	stateDirectory := filepath.Join(root, "state")
	identityDirectory := filepath.Join(stateDirectory, "identity")
	if err := os.MkdirAll(identityDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	config := Config{
		SourceExecutable: "/bin/true", DestinationExecutable: "/bin/true",
		UnitPath: filepath.Join(root, ServiceName), MaintenanceUnitPath: filepath.Join(root, MaintenanceServiceName),
		IdentityDirectory: identityDirectory, StateDirectory: stateDirectory,
		ControllerAddress: "127.0.0.1:9443", NodeID: "node-a",
	}
	unit, err := RenderUnit(config)
	if err != nil {
		t.Fatal(err)
	}
	maintenanceUnit, err := RenderMaintenanceUnit(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.UnitPath, []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.MaintenanceUnitPath, []byte(maintenanceUnit), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(analyzer, "verify", config.UnitPath, config.MaintenanceUnitPath).CombinedOutput(); err != nil {
		t.Fatalf("systemd unit verification failed: %v\n%s", err, output)
	}
}
