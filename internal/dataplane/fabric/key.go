package fabric

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const privateKeyBytes = 32

// EnsurePrivateKey creates a node-local WireGuard-compatible X25519 private
// key when absent and returns only its public key. Private bytes never enter
// Desired State or Controller storage.
func EnsurePrivateKey(path string) (string, error) {
	if path == "" {
		return "", errors.New("wireguard private key path must not be empty")
	}
	if encoded, err := loadPrivateKey(path); err == nil {
		return publicKey(encoded)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate WireGuard private key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(private.Bytes())
	if err := writePrivateKey(path, encoded); err != nil {
		if existing, loadErr := loadPrivateKey(path); loadErr == nil {
			return publicKey(existing)
		}
		return "", err
	}
	return publicKey(encoded)
}

func loadPrivateKey(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("wireguard private key is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("wireguard private key permissions must be 0600 or stricter")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read WireGuard private key: %w", err)
	}
	encoded := strings.TrimSpace(string(contents))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != privateKeyBytes {
		return "", errors.New("wireguard private key must be a base64-encoded 32-byte value")
	}
	if _, err := ecdh.X25519().NewPrivateKey(decoded); err != nil {
		return "", fmt.Errorf("parse WireGuard private key: %w", err)
	}
	return encoded, nil
}

func publicKey(encodedPrivate string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedPrivate)
	if err != nil || len(decoded) != privateKeyBytes {
		return "", errors.New("wireguard private key is invalid")
	}
	private, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return "", fmt.Errorf("parse WireGuard private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), nil
}

func writePrivateKey(path, encoded string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create WireGuard key directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".wireguard-key-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary WireGuard key: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary WireGuard key: %w", err)
	}
	if _, err := temporary.WriteString(encoded + "\n"); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary WireGuard key: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary WireGuard key: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary WireGuard key: %w", err)
	}
	// Link publishes the complete temporary inode without replacing a key that
	// another Agent process may have won concurrently.
	if err := os.Link(temporaryPath, path); err != nil {
		return fmt.Errorf("commit WireGuard private key: %w", err)
	}
	if runtime.GOOS != "windows" {
		dir, err := os.Open(directory)
		if err != nil {
			return fmt.Errorf("open WireGuard key directory: %w", err)
		}
		defer dir.Close()
		if err := dir.Sync(); err != nil {
			return fmt.Errorf("sync WireGuard key directory: %w", err)
		}
	}
	return nil
}
