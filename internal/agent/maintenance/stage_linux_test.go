//go:build linux

package maintenance

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStageUpgradeDownloadsAndVerifiesRelease(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "release.tar.gz")
	binaryName := "flux-agent-linux-" + runtime.GOARCH
	binary := []byte("downloaded-test-agent")
	innerChecksum := sha256.Sum256(binary)
	writeTestArchive(t, archivePath, map[string][]byte{
		"flux-test/bin/" + binaryName: binary,
		"flux-test/SHA256SUMS":        []byte(fmt.Sprintf("%x  bin/%s\n", innerChecksum, binaryName)),
		"flux-test/VERSION":           []byte("beta.download-test\n"),
	})
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	outerChecksum := sha256.Sum256(archive)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/release.tar.gz":
			_, _ = writer.Write(archive)
		case "/release.tar.gz.sha256":
			_, _ = fmt.Fprintf(writer, "%x  release.tar.gz\n", outerChecksum)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	stateDirectory := filepath.Join(root, "state")
	result, err := stageUpgrade(
		context.Background(),
		server.URL+"/release.tar.gz",
		server.URL+"/release.tar.gz.sha256",
		stateDirectory,
		server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(result.Path)
	if err != nil || string(staged) != string(binary) {
		t.Fatalf("staged=%q err=%v", staged, err)
	}
	if result.Version != "beta.download-test" {
		t.Fatalf("version=%q", result.Version)
	}
}
