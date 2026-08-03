package maintenance

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	RequestVersion  = 1
	ActionUpgrade   = "upgrade"
	ActionUninstall = "uninstall"

	DefaultExecutable          = "/usr/local/bin/flux-agent"
	DefaultAgentUnitPath       = "/etc/systemd/system/flux-agent.service"
	DefaultMaintenanceUnitPath = "/etc/systemd/system/flux-agent-maintenance.service"
	DefaultIdentityDirectory   = "/var/lib/flux-agent/identity"
	DefaultStateDirectory      = "/var/lib/flux-agent"
	DefaultForwardingSysctl    = "/etc/sysctl.d/90-flux-forwarding.conf"

	maxArchiveBytes  = 512 << 20
	maxBinaryBytes   = 256 << 20
	maxChecksumBytes = 16 << 10
)

type Request struct {
	Version               int    `json:"version"`
	Action                string `json:"action"`
	StagedBinary          string `json:"staged_binary,omitempty"`
	DestinationExecutable string `json:"destination_executable"`
	AgentUnitPath         string `json:"agent_unit_path"`
	MaintenanceUnitPath   string `json:"maintenance_unit_path"`
	IdentityDirectory     string `json:"identity_directory"`
	StateDirectory        string `json:"state_directory"`
}

type StageResult struct {
	Path    string
	Version string
}

func RequestPath(stateDirectory string) string {
	return filepath.Join(stateDirectory, "maintenance", "request.json")
}

func StageUpgrade(ctx context.Context, releaseURL, checksumURL, stateDirectory string) (StageResult, error) {
	return stageUpgrade(ctx, releaseURL, checksumURL, stateDirectory, secureHTTPClient())
}

func stageUpgrade(ctx context.Context, releaseURL, checksumURL, stateDirectory string, client *http.Client) (StageResult, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return StageResult{}, errors.New("online Agent upgrade supports Linux amd64 and arm64 only")
	}
	if err := validateHTTPSURL(releaseURL); err != nil {
		return StageResult{}, fmt.Errorf("release URL: %w", err)
	}
	if err := validateHTTPSURL(checksumURL); err != nil {
		return StageResult{}, fmt.Errorf("checksum URL: %w", err)
	}
	maintenanceDirectory := filepath.Join(stateDirectory, "maintenance")
	if err := os.MkdirAll(maintenanceDirectory, 0o700); err != nil {
		return StageResult{}, fmt.Errorf("create maintenance directory: %w", err)
	}
	temporaryDirectory, err := os.MkdirTemp(maintenanceDirectory, ".download-")
	if err != nil {
		return StageResult{}, fmt.Errorf("create upgrade staging directory: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)

	checksumBytes, err := downloadBytes(ctx, client, checksumURL, maxChecksumBytes)
	if err != nil {
		return StageResult{}, fmt.Errorf("download release checksum: %w", err)
	}
	expectedOuter, err := parseFirstChecksum(checksumBytes)
	if err != nil {
		return StageResult{}, fmt.Errorf("parse release checksum: %w", err)
	}
	archivePath := filepath.Join(temporaryDirectory, "release.tar.gz")
	if err := downloadFile(ctx, client, releaseURL, archivePath, maxArchiveBytes); err != nil {
		return StageResult{}, fmt.Errorf("download release archive: %w", err)
	}
	actualOuter, err := fileChecksum(archivePath)
	if err != nil {
		return StageResult{}, fmt.Errorf("hash release archive: %w", err)
	}
	if actualOuter != expectedOuter {
		return StageResult{}, errors.New("release archive SHA-256 does not match")
	}

	binaryName := "flux-agent-linux-" + runtime.GOARCH
	temporaryBinary := filepath.Join(temporaryDirectory, binaryName)
	internalChecksums, version, err := extractAgent(archivePath, binaryName, temporaryBinary)
	if err != nil {
		return StageResult{}, err
	}
	expectedInner, err := checksumFor(internalChecksums, "bin/"+binaryName)
	if err != nil {
		return StageResult{}, err
	}
	actualInner, err := fileChecksum(temporaryBinary)
	if err != nil {
		return StageResult{}, fmt.Errorf("hash staged Agent: %w", err)
	}
	if actualInner != expectedInner {
		return StageResult{}, errors.New("Agent binary does not match the archive checksum manifest")
	}
	if err := os.Chmod(temporaryBinary, 0o755); err != nil {
		return StageResult{}, fmt.Errorf("set staged Agent permissions: %w", err)
	}
	stagedPath := filepath.Join(maintenanceDirectory, "flux-agent.new")
	if err := replaceFile(temporaryBinary, stagedPath); err != nil {
		return StageResult{}, fmt.Errorf("commit staged Agent: %w", err)
	}
	return StageResult{Path: stagedPath, Version: version}, nil
}

func WriteRequest(request Request) (string, error) {
	if err := request.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("encode maintenance request: %w", err)
	}
	destination := RequestPath(request.StateDirectory)
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return "", fmt.Errorf("create maintenance request directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".request-")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := replaceFile(temporaryPath, destination); err != nil {
		return "", err
	}
	committed = true
	return destination, nil
}

func LoadRequest(requestPath string) (Request, error) {
	encoded, err := os.ReadFile(filepath.Clean(requestPath))
	if err != nil {
		return Request{}, fmt.Errorf("read maintenance request: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > 64<<10 {
		return Request{}, errors.New("maintenance request size is invalid")
	}
	var request Request
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("decode maintenance request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("maintenance request must contain exactly one JSON object")
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	if filepath.Clean(requestPath) != filepath.Clean(RequestPath(request.StateDirectory)) {
		return Request{}, errors.New("maintenance request is outside its state directory")
	}
	return request, nil
}

func (r Request) Validate() error {
	if r.Version != RequestVersion {
		return errors.New("maintenance request version is unsupported")
	}
	if r.Action != ActionUpgrade && r.Action != ActionUninstall {
		return errors.New("maintenance action is unsupported")
	}
	for name, value := range map[string]string{
		"destination executable": r.DestinationExecutable,
		"Agent unit":             r.AgentUnitPath,
		"maintenance unit":       r.MaintenanceUnitPath,
		"identity directory":     r.IdentityDirectory,
		"state directory":        r.StateDirectory,
	} {
		if !safeAbsolutePath(value) {
			return fmt.Errorf("%s path is invalid", name)
		}
	}
	if r.DestinationExecutable != DefaultExecutable || r.AgentUnitPath != DefaultAgentUnitPath || r.MaintenanceUnitPath != DefaultMaintenanceUnitPath || r.IdentityDirectory != DefaultIdentityDirectory || r.StateDirectory != DefaultStateDirectory {
		return errors.New("online maintenance is restricted to the standard Flux installation paths")
	}
	if r.Action == ActionUpgrade {
		if !safeAbsolutePath(r.StagedBinary) || !pathWithin(r.StateDirectory, r.StagedBinary) {
			return errors.New("staged Agent must be inside the Agent state directory")
		}
	} else if r.StagedBinary != "" {
		return errors.New("uninstall request must not include a staged binary")
	}
	return nil
}

func validateHTTPSURL(value string) error {
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "'\"#\\\r\n\t \x00") {
		return errors.New("URL contains unsafe characters")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL must be an HTTPS address without credentials or fragments")
	}
	return nil
}

func secureHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: transport,
		Timeout:   2 * time.Minute,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many release redirects")
			}
			return validateHTTPSURL(request.URL.String())
		},
	}
}

func downloadBytes(ctx context.Context, client *http.Client, source string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned HTTP %d", response.StatusCode)
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(encoded)) > limit {
		return nil, errors.New("download exceeds the allowed size")
	}
	return encoded, nil
}

func downloadFile(ctx context.Context, client *http.Client, source, destination string, limit int64) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("server returned HTTP %d", response.StatusCode)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, limit+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if written > limit {
		return errors.New("release archive exceeds the allowed size")
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func extractAgent(archivePath, binaryName, destination string) ([]byte, string, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return nil, "", err
	}
	defer archive.Close()
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return nil, "", fmt.Errorf("open release gzip stream: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var checksums []byte
	version := ""
	foundBinary := false
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("read release archive: %w", err)
		}
		clean := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if clean == "." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
			return nil, "", errors.New("release archive contains an unsafe path")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		switch {
		case strings.HasSuffix(clean, "/SHA256SUMS") || clean == "SHA256SUMS":
			if checksums != nil || header.Size < 1 || header.Size > maxChecksumBytes {
				return nil, "", errors.New("release checksum manifest is missing or duplicated")
			}
			checksums, err = io.ReadAll(io.LimitReader(tarReader, maxChecksumBytes+1))
			if err != nil || int64(len(checksums)) > maxChecksumBytes {
				return nil, "", errors.New("release checksum manifest is invalid")
			}
		case strings.HasSuffix(clean, "/VERSION") || clean == "VERSION":
			if header.Size > 256 {
				return nil, "", errors.New("release version file is too large")
			}
			value, readErr := io.ReadAll(io.LimitReader(tarReader, 257))
			if readErr != nil {
				return nil, "", readErr
			}
			version = strings.TrimSpace(string(value))
		case strings.HasSuffix(clean, "/bin/"+binaryName) || clean == "bin/"+binaryName:
			if foundBinary || header.Size < 1 || header.Size > maxBinaryBytes {
				return nil, "", errors.New("release Agent binary is missing, duplicated, or too large")
			}
			file, createErr := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
			if createErr != nil {
				return nil, "", createErr
			}
			written, copyErr := io.Copy(file, io.LimitReader(tarReader, maxBinaryBytes+1))
			syncErr := file.Sync()
			closeErr := file.Close()
			if copyErr != nil || written > maxBinaryBytes || syncErr != nil || closeErr != nil {
				return nil, "", errors.New("extract Agent binary failed")
			}
			foundBinary = true
		}
	}
	if !foundBinary || len(checksums) == 0 {
		return nil, "", errors.New("release does not contain the required Agent binary and checksum manifest")
	}
	return checksums, version, nil
}

func parseFirstChecksum(encoded []byte) (string, error) {
	fields := strings.Fields(string(encoded))
	if len(fields) == 0 {
		return "", errors.New("checksum file is empty")
	}
	return normalizeChecksum(fields[0])
}

func checksumFor(manifest []byte, name string) (string, error) {
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		entry := strings.TrimPrefix(fields[1], "*")
		if entry == name {
			return normalizeChecksum(fields[0])
		}
	}
	return "", fmt.Errorf("release checksum manifest does not contain %s", name)
}

func normalizeChecksum(value string) (string, error) {
	if len(value) != sha256.Size*2 {
		return "", errors.New("SHA-256 value has an invalid length")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("SHA-256 value is not hexadecimal")
	}
	return strings.ToLower(value), nil
}

func fileChecksum(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func safeAbsolutePath(value string) bool {
	return value != "" && filepath.IsAbs(value) && !strings.ContainsAny(value, "\r\n\x00") && filepath.Clean(value) == value
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func replaceFile(source, destination string) error {
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}
