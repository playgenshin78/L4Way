package securechannel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/flynn/noise"
	"google.golang.org/grpc/credentials"
)

const (
	controlPrologue = "flux/control/noise-aesgcm/v1"
	protocolVersion = 1
	handshakeLimit  = 15 * time.Second
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

type NodeAuthorizer func(context.Context, string, []byte) error

type AuthInfo struct {
	NodeID          string
	PeerPublicKey   []byte
	PeerFingerprint string
	Controller      bool
}

func (AuthInfo) AuthType() string { return "noise-aes256-gcm" }

type clientCredentials struct {
	nodeID           string
	identity         KeyPair
	controllerPublic []byte
}

type serverCredentials struct {
	identity  KeyPair
	authorize NodeAuthorizer
}

type controlHello struct {
	Version      int    `json:"version"`
	NodeID       string `json:"node_id"`
	IssuedAtUnix int64  `json:"issued_at_unix"`
}

type controlWelcome struct {
	Version      int   `json:"version"`
	IssuedAtUnix int64 `json:"issued_at_unix"`
}

func NewClientCredentials(nodeID string, identity KeyPair, controllerPublic []byte) (credentials.TransportCredentials, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, errors.New("Noise client node ID is required")
	}
	if err := ValidateKeyPair(identity); err != nil {
		return nil, err
	}
	if len(controllerPublic) != KeySize {
		return nil, errors.New("Controller Noise public key must be 32 bytes")
	}
	return &clientCredentials{nodeID: nodeID, identity: clonePair(identity), controllerPublic: append([]byte(nil), controllerPublic...)}, nil
}

func NewServerCredentials(identity KeyPair, authorize NodeAuthorizer) (credentials.TransportCredentials, error) {
	if err := ValidateKeyPair(identity); err != nil {
		return nil, err
	}
	if authorize == nil {
		return nil, errors.New("Noise server node authorizer is required")
	}
	return &serverCredentials{identity: clonePair(identity), authorize: authorize}, nil
}

func (c *clientCredentials) ClientHandshake(ctx context.Context, _ string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	deadline := time.Now().Add(handshakeLimit)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Pattern: noise.HandshakeIK, Initiator: true,
		Prologue: []byte(controlPrologue), StaticKeypair: toNoiseKey(c.identity),
		PeerStatic: c.controllerPublic,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("initialize Noise client handshake: %w", err)
	}
	payload, _ := json.Marshal(controlHello{Version: protocolVersion, NodeID: c.nodeID, IssuedAtUnix: time.Now().UTC().Unix()})
	request, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("create Noise client hello: %w", err)
	}
	if err := writeFrame(raw, request); err != nil {
		return nil, nil, fmt.Errorf("send Noise client hello: %w", err)
	}
	response, err := readFrame(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("receive Noise server welcome: %w", err)
	}
	welcomePayload, send, receive, err := hs.ReadMessage(nil, response)
	if err != nil {
		return nil, nil, fmt.Errorf("authenticate Noise server: %w", err)
	}
	var welcome controlWelcome
	if err := json.Unmarshal(welcomePayload, &welcome); err != nil || welcome.Version != protocolVersion || !freshTimestamp(welcome.IssuedAtUnix, time.Now().UTC()) {
		return nil, nil, errors.New("Noise server welcome is invalid or stale")
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, nil, err
	}
	secured, err := newEncryptedConn(raw, send, receive)
	if err != nil {
		return nil, nil, err
	}
	return secured, AuthInfo{PeerPublicKey: append([]byte(nil), c.controllerPublic...), PeerFingerprint: Fingerprint(c.controllerPublic), Controller: true}, nil
}

func (*clientCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("Noise client credentials cannot accept server handshakes")
}

func (s *serverCredentials) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if err := raw.SetDeadline(time.Now().Add(handshakeLimit)); err != nil {
		return nil, nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Pattern: noise.HandshakeIK,
		Prologue: []byte(controlPrologue), StaticKeypair: toNoiseKey(s.identity),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("initialize Noise server handshake: %w", err)
	}
	request, err := readFrame(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("receive Noise client hello: %w", err)
	}
	payload, _, _, err := hs.ReadMessage(nil, request)
	if err != nil {
		return nil, nil, fmt.Errorf("authenticate Noise client handshake: %w", err)
	}
	var hello controlHello
	now := time.Now().UTC()
	if err := json.Unmarshal(payload, &hello); err != nil || hello.Version != protocolVersion || strings.TrimSpace(hello.NodeID) == "" || !freshTimestamp(hello.IssuedAtUnix, now) {
		return nil, nil, errors.New("Noise client hello is invalid or stale")
	}
	peerPublic := append([]byte(nil), hs.PeerStatic()...)
	if len(peerPublic) != KeySize {
		return nil, nil, errors.New("Noise client did not present a valid static identity")
	}
	authorizationContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = s.authorize(authorizationContext, hello.NodeID, peerPublic)
	cancel()
	if err != nil {
		return nil, nil, fmt.Errorf("authorize Noise client: %w", err)
	}
	welcomePayload, _ := json.Marshal(controlWelcome{Version: protocolVersion, IssuedAtUnix: now.Unix()})
	response, inbound, outbound, err := hs.WriteMessage(nil, welcomePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("create Noise server welcome: %w", err)
	}
	if err := writeFrame(raw, response); err != nil {
		return nil, nil, fmt.Errorf("send Noise server welcome: %w", err)
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, nil, err
	}
	secured, err := newEncryptedConn(raw, outbound, inbound)
	if err != nil {
		return nil, nil, err
	}
	return secured, AuthInfo{NodeID: hello.NodeID, PeerPublicKey: peerPublic, PeerFingerprint: Fingerprint(peerPublic)}, nil
}

func (*serverCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("Noise server credentials cannot initiate client handshakes")
}

func (c *clientCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "noise", SecurityVersion: "Noise_IK_25519_AESGCM_SHA256"}
}

func (s *serverCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "noise", SecurityVersion: "Noise_IK_25519_AESGCM_SHA256"}
}

func (c *clientCredentials) Clone() credentials.TransportCredentials {
	clone, _ := NewClientCredentials(c.nodeID, c.identity, c.controllerPublic)
	return clone
}

func (s *serverCredentials) Clone() credentials.TransportCredentials {
	clone, _ := NewServerCredentials(s.identity, s.authorize)
	return clone
}

func (*clientCredentials) OverrideServerName(string) error { return nil }
func (*serverCredentials) OverrideServerName(string) error { return nil }

func freshTimestamp(unix int64, now time.Time) bool {
	observed := time.Unix(unix, 0)
	difference := now.Sub(observed)
	return difference >= -5*time.Minute && difference <= 5*time.Minute
}

func toNoiseKey(pair KeyPair) noise.DHKey {
	return noise.DHKey{Private: append([]byte(nil), pair.Private...), Public: append([]byte(nil), pair.Public...)}
}

func clonePair(pair KeyPair) KeyPair {
	return KeyPair{Private: append([]byte(nil), pair.Private...), Public: append([]byte(nil), pair.Public...)}
}
