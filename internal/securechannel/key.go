package securechannel

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

const KeySize = 32

// KeyPair is an X25519 static identity used by the Noise handshake. The
// transport cipher negotiated by this package is always AES-256-GCM.
type KeyPair struct {
	Private []byte
	Public  []byte
}

type encodedKeyPair struct {
	Version    int    `json:"version"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func GenerateKeyPair() (KeyPair, error) {
	pair, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate X25519 identity: %w", err)
	}
	return KeyPair{Private: append([]byte(nil), pair.Private...), Public: append([]byte(nil), pair.Public...)}, nil
}

func ParsePublicKey(encoded string) ([]byte, error) {
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil || len(key) != KeySize {
		return nil, errors.New("Noise public key must be a base64-encoded 32-byte key")
	}
	return key, nil
}

func EncodePublicKey(key []byte) string {
	return base64.RawStdEncoding.EncodeToString(key)
}

func Fingerprint(key []byte) string {
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:])
}

func LoadKeyPair(path string) (KeyPair, error) {
	encoded, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return KeyPair{}, fmt.Errorf("read Noise identity: %w", err)
	}
	var stored encodedKeyPair
	decoderError := json.Unmarshal(encoded, &stored)
	if decoderError != nil || stored.Version != 1 {
		return KeyPair{}, errors.New("Noise identity file is invalid or unsupported")
	}
	private, err := base64.RawStdEncoding.DecodeString(stored.PrivateKey)
	if err != nil {
		private, err = base64.StdEncoding.DecodeString(stored.PrivateKey)
	}
	if err != nil || len(private) != KeySize {
		return KeyPair{}, errors.New("Noise private key is invalid")
	}
	public, err := ParsePublicKey(stored.PublicKey)
	if err != nil {
		return KeyPair{}, err
	}
	derived, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil || !equalKey(derived, public) {
		return KeyPair{}, errors.New("Noise public key does not match the private key")
	}
	return KeyPair{Private: private, Public: public}, nil
}

func WriteKeyPair(path string, pair KeyPair) error {
	if err := ValidateKeyPair(pair); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(encodedKeyPair{
		Version: 1, PrivateKey: base64.RawStdEncoding.EncodeToString(pair.Private),
		PublicKey: EncodePublicKey(pair.Public),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Noise identity: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create Noise identity directory: %w", err)
	}
	return writeExclusive(path, encoded, 0o600)
}

func ValidateKeyPair(pair KeyPair) error {
	if len(pair.Private) != KeySize || len(pair.Public) != KeySize {
		return errors.New("Noise identity must contain 32-byte private and public keys")
	}
	derived, err := curve25519.X25519(pair.Private, curve25519.Basepoint)
	if err != nil || !equalKey(derived, pair.Public) {
		return errors.New("Noise identity public key does not match its private key")
	}
	return nil
}

func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".flux-identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary identity: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set temporary identity permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary identity: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary identity: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary identity: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace identity: %w", err)
	}
	if runtime.GOOS != "windows" {
		directoryHandle, err := os.Open(directory)
		if err != nil {
			return fmt.Errorf("open identity directory for sync: %w", err)
		}
		defer directoryHandle.Close()
		if err := directoryHandle.Sync(); err != nil {
			return fmt.Errorf("sync identity directory: %w", err)
		}
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	remove = false
	return nil
}

func equalKey(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
