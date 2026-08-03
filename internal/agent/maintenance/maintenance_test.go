package maintenance

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExtractAgentVerifiesReleaseLayout(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "release.tar.gz")
	binaryName := "flux-agent-linux-" + runtime.GOARCH
	binary := []byte("test-agent-binary")
	checksum := sha256.Sum256(binary)
	entries := map[string][]byte{
		"flux-test/bin/" + binaryName: binary,
		"flux-test/SHA256SUMS":        []byte(fmt.Sprintf("%x  bin/%s\n", checksum, binaryName)),
		"flux-test/VERSION":           []byte("beta.test\n"),
	}
	writeTestArchive(t, archivePath, entries)

	destination := filepath.Join(root, "agent")
	manifest, version, err := extractAgent(archivePath, binaryName, destination)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(destination)
	if err != nil || string(installed) != string(binary) {
		t.Fatalf("installed=%q err=%v", installed, err)
	}
	if version != "beta.test" || !strings.Contains(string(manifest), "bin/"+binaryName) {
		t.Fatalf("version=%q manifest=%q", version, manifest)
	}
}

func TestLoadRequestRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, []byte(`{"version":1} {"action":"upgrade"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRequest(path); err == nil || !strings.Contains(err.Error(), "exactly one JSON object") {
		t.Fatalf("error=%v", err)
	}
}

func TestRequestIsRestrictedToStandardInstallationPaths(t *testing.T) {
	request := Request{
		Version:               RequestVersion,
		Action:                ActionUninstall,
		DestinationExecutable: "/tmp/flux-agent",
		AgentUnitPath:         DefaultAgentUnitPath,
		MaintenanceUnitPath:   DefaultMaintenanceUnitPath,
		IdentityDirectory:     DefaultIdentityDirectory,
		StateDirectory:        DefaultStateDirectory,
	}
	if err := request.Validate(); err == nil || !strings.Contains(err.Error(), "standard Flux installation paths") {
		t.Fatalf("error=%v", err)
	}
}

func writeTestArchive(t *testing.T, destination string, entries map[string][]byte) {
	t.Helper()
	file, err := os.Create(destination)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range entries {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
