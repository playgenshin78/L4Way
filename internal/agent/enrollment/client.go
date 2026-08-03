package enrollment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	controller "flux.local/flux/internal/controller/enrollment"
	"flux.local/flux/internal/securechannel"
	"flux.local/flux/internal/spec"
)

const (
	identityFileName = "identity.json"
	pendingFileName  = "enrollment.pending.json"
)

type Config struct {
	ControllerAddress   string
	NodeID              string
	Token               string
	ControllerPublicKey []byte
	IdentityDir         string
	AgentVersion        string
	Timeout             time.Duration
}

type Identity struct {
	Version             int       `json:"version"`
	NodeID              string    `json:"node_id"`
	PrivateKey          string    `json:"private_key"`
	PublicKey           string    `json:"public_key"`
	ControllerPublicKey string    `json:"controller_public_key"`
	EnrolledAt          time.Time `json:"enrolled_at"`
}

func Enroll(ctx context.Context, config Config) (controller.Response, error) {
	if err := validateConfig(config); err != nil {
		return controller.Response{}, err
	}
	if config.Timeout <= 0 {
		config.Timeout = 20 * time.Second
	}
	pair, err := loadOrCreatePending(config.IdentityDir, config.NodeID, config.ControllerPublicKey)
	if err != nil {
		return controller.Response{}, err
	}
	requestPayload, err := json.Marshal(controller.Request{
		NodeID: config.NodeID, Token: config.Token,
		PublicKey: securechannel.EncodePublicKey(pair.Public), AgentVersion: config.AgentVersion,
	})
	if err != nil {
		return controller.Response{}, fmt.Errorf("encode enrollment request: %w", err)
	}
	dialer := net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", config.ControllerAddress)
	if err != nil {
		return controller.Response{}, fmt.Errorf("connect to Controller enrollment service: %w", err)
	}
	defer connection.Close()
	responsePayload, err := securechannel.EnrollClient(ctx, connection, config.ControllerPublicKey, requestPayload)
	if err != nil {
		return controller.Response{}, err
	}
	response, err := controller.DecodeResponse(responsePayload)
	if err != nil {
		return controller.Response{}, fmt.Errorf("enrollment rejected: %w", err)
	}
	if response.NodeID != config.NodeID || response.NodeKeyFingerprint != securechannel.Fingerprint(pair.Public) {
		return controller.Response{}, errors.New("enrollment response does not match the local node identity")
	}
	returnedControllerKey, err := securechannel.ParsePublicKey(response.ControllerPublicKey)
	if err != nil || !sameKey(returnedControllerKey, config.ControllerPublicKey) {
		return controller.Response{}, errors.New("enrollment response does not match the pinned Controller identity")
	}
	identity := Identity{
		Version: 1, NodeID: config.NodeID,
		PrivateKey:          base64.RawStdEncoding.EncodeToString(pair.Private),
		PublicKey:           securechannel.EncodePublicKey(pair.Public),
		ControllerPublicKey: securechannel.EncodePublicKey(config.ControllerPublicKey),
		EnrolledAt:          response.EnrolledAt,
	}
	encoded, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return controller.Response{}, fmt.Errorf("encode node identity: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := securechannel.WriteAtomic(filepath.Join(config.IdentityDir, identityFileName), encoded, 0o600); err != nil {
		return controller.Response{}, err
	}
	_ = os.Remove(filepath.Join(config.IdentityDir, pendingFileName))
	return response, nil
}

func LoadIdentity(identityDirectory, expectedNodeID string) (securechannel.KeyPair, []byte, error) {
	encoded, err := os.ReadFile(filepath.Join(identityDirectory, identityFileName))
	if err != nil {
		return securechannel.KeyPair{}, nil, fmt.Errorf("read node identity: %w", err)
	}
	var identity Identity
	if err := json.Unmarshal(encoded, &identity); err != nil || identity.Version != 1 {
		return securechannel.KeyPair{}, nil, errors.New("node identity file is invalid or unsupported")
	}
	if err := spec.ValidateIdentifier("node_id", identity.NodeID); err != nil {
		return securechannel.KeyPair{}, nil, err
	}
	if expectedNodeID != "" && identity.NodeID != expectedNodeID {
		return securechannel.KeyPair{}, nil, fmt.Errorf("node identity belongs to %q, not %q", identity.NodeID, expectedNodeID)
	}
	private, err := decodePrivateKey(identity.PrivateKey)
	if err != nil {
		return securechannel.KeyPair{}, nil, err
	}
	public, err := securechannel.ParsePublicKey(identity.PublicKey)
	if err != nil {
		return securechannel.KeyPair{}, nil, err
	}
	pair := securechannel.KeyPair{Private: private, Public: public}
	if err := securechannel.ValidateKeyPair(pair); err != nil {
		return securechannel.KeyPair{}, nil, err
	}
	controllerPublic, err := securechannel.ParsePublicKey(identity.ControllerPublicKey)
	if err != nil {
		return securechannel.KeyPair{}, nil, fmt.Errorf("load pinned Controller public key: %w", err)
	}
	return pair, controllerPublic, nil
}

func validateConfig(config Config) error {
	if err := spec.ValidateIdentifier("node_id", config.NodeID); err != nil {
		return err
	}
	if strings.TrimSpace(config.ControllerAddress) == "" || strings.Contains(config.ControllerAddress, "://") {
		return errors.New("Controller enrollment address must be host:port without a URL scheme")
	}
	if len(config.Token) < 32 || strings.ContainsAny(config.Token, "\r\n\t ") {
		return errors.New("enrollment token is invalid")
	}
	if len(config.ControllerPublicKey) != securechannel.KeySize {
		return errors.New("pinned Controller Noise public key is required")
	}
	if strings.TrimSpace(config.IdentityDir) == "" {
		return errors.New("identity directory is required")
	}
	return nil
}

func loadOrCreatePending(directory, nodeID string, controllerPublic []byte) (securechannel.KeyPair, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return securechannel.KeyPair{}, fmt.Errorf("create identity directory: %w", err)
	}
	if _, err := os.Stat(filepath.Join(directory, identityFileName)); err == nil {
		return securechannel.KeyPair{}, errors.New("node identity already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return securechannel.KeyPair{}, fmt.Errorf("inspect node identity: %w", err)
	}
	pendingPath := filepath.Join(directory, pendingFileName)
	if encoded, err := os.ReadFile(pendingPath); err == nil {
		var pending Identity
		if json.Unmarshal(encoded, &pending) != nil || pending.Version != 1 || pending.NodeID != nodeID {
			return securechannel.KeyPair{}, errors.New("pending enrollment identity is invalid or belongs to another node")
		}
		pinned, err := securechannel.ParsePublicKey(pending.ControllerPublicKey)
		if err != nil || !sameKey(pinned, controllerPublic) {
			return securechannel.KeyPair{}, errors.New("pending enrollment is pinned to another Controller")
		}
		private, err := decodePrivateKey(pending.PrivateKey)
		if err != nil {
			return securechannel.KeyPair{}, err
		}
		public, err := securechannel.ParsePublicKey(pending.PublicKey)
		if err != nil {
			return securechannel.KeyPair{}, err
		}
		pair := securechannel.KeyPair{Private: private, Public: public}
		return pair, securechannel.ValidateKeyPair(pair)
	} else if !errors.Is(err, os.ErrNotExist) {
		return securechannel.KeyPair{}, fmt.Errorf("read pending enrollment identity: %w", err)
	}
	pair, err := securechannel.GenerateKeyPair()
	if err != nil {
		return securechannel.KeyPair{}, err
	}
	pending := Identity{
		Version: 1, NodeID: nodeID,
		PrivateKey:          base64.RawStdEncoding.EncodeToString(pair.Private),
		PublicKey:           securechannel.EncodePublicKey(pair.Public),
		ControllerPublicKey: securechannel.EncodePublicKey(controllerPublic),
	}
	encoded, _ := json.MarshalIndent(pending, "", "  ")
	encoded = append(encoded, '\n')
	if err := securechannel.WriteAtomic(pendingPath, encoded, 0o600); err != nil {
		return securechannel.KeyPair{}, err
	}
	return pair, nil
}

func decodePrivateKey(encoded string) ([]byte, error) {
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil || len(key) != securechannel.KeySize {
		return nil, errors.New("node Noise private key is invalid")
	}
	return key, nil
}

func sameKey(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
