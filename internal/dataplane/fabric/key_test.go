package fabric

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsurePrivateKeyIsStableAndReturnsOnlyPublicMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity", "wireguard.key")
	first, err := EnsurePrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnsurePrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("public key changed: %q != %q", first, second)
	}
	decoded, err := base64.StdEncoding.DecodeString(first)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("public key is invalid: %q", first)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(contents)) == first {
		t.Fatal("private key file unexpectedly contains the public key")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private key permissions = %o", info.Mode().Perm())
	}
}

func TestEnsurePrivateKeyRejectsMalformedExistingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireguard.key")
	if err := os.WriteFile(path, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsurePrivateKey(path); err == nil {
		t.Fatal("EnsurePrivateKey accepted malformed existing material")
	}
}
