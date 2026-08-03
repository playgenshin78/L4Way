package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const validDesiredJSON = `{
  "schema_version": 1,
  "node_id": "node-a",
  "generation": 1,
  "forwards": [{
    "id": "web",
    "user_id": "user-a",
    "protocols": ["tcp"],
    "ingress_node_id": "node-a",
    "listen": {"address": "192.0.2.10", "port": 443},
    "target": {"address": "198.51.100.20", "port": 8443},
    "path_mode": "direct",
    "snat": {"mode": "masquerade"},
    "lifecycle": "active",
    "resource_version": 1
  }]
}`

func writeDesiredForTest(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "desired.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunValidateAndRender(t *testing.T) {
	path := writeDesiredForTest(t, validDesiredJSON)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"validate", "--file", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("validate code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"valid": true`) || !strings.Contains(stdout.String(), `"checksum":`) {
		t.Fatalf("validate output=%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"render", "--file", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("render code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "table inet flux") || !strings.Contains(stdout.String(), "map dnat_addresses_tcp") {
		t.Fatalf("render output=%s", stdout.String())
	}
}

func TestRunRejectsUnknownDesiredField(t *testing.T) {
	content := strings.Replace(validDesiredJSON, `"schema_version": 1,`, `"schema_version": 1, "surprise": true,`, 1)
	path := writeDesiredForTest(t, content)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"validate", "--file", path}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d output=%s error=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "unknown field") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunRenderFabricAndCreateNodeKey(t *testing.T) {
	path := writeDesiredForTest(t, validDesiredJSON)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"render-fabric", "--file", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("render-fabric code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"active": false`) || !strings.Contains(stdout.String(), `"checksum":`) {
		t.Fatalf("render-fabric output=%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	keyPath := filepath.Join(t.TempDir(), "wireguard.key")
	if code := run([]string{"fabric-key", "--key-file", keyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("fabric-key code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"public_key":`) {
		t.Fatalf("fabric-key output=%s", stdout.String())
	}
	if info, err := os.Stat(keyPath); err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("key info=%v err=%v", info, err)
	}
}

func TestRunVersionReportsAgentVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"agent_version"`) {
		t.Fatalf("version output=%s", stdout.String())
	}
}
