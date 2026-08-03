package enrollment

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/securechannel"
)

type fakeEnrollmentStore struct {
	nodeID    string
	token     string
	publicKey []byte
	createdAt time.Time
}

func (s *fakeEnrollmentStore) CompleteEnrollment(_ context.Context, nodeID, token string, publicKey []byte) (store.NodeKeyRecord, error) {
	if nodeID != s.nodeID || token != s.token {
		return store.NodeKeyRecord{}, store.ErrInvalidEnrollment
	}
	s.publicKey = append([]byte(nil), publicKey...)
	return store.NodeKeyRecord{
		NodeID: nodeID, Fingerprint: securechannel.Fingerprint(publicKey),
		PublicKey: append([]byte(nil), publicKey...), CreatedAt: s.createdAt,
	}, nil
}

func TestNoiseEnrollmentAuthenticatesControllerAndStoresNodeKey(t *testing.T) {
	controllerIdentity, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nodeIdentity, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	token := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	repository := &fakeEnrollmentStore{nodeID: "node-a", token: token, createdAt: time.Now().UTC()}
	server, err := NewServer(controllerIdentity, repository, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(Request{
		NodeID: "node-a", Token: token, PublicKey: securechannel.EncodePublicKey(nodeIdentity.Public), AgentVersion: "test",
	})
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	serverDone := make(chan error, 1)
	go func() {
		defer serverConnection.Close()
		serverDone <- securechannel.EnrollServer(serverConnection, controllerIdentity, func(payload []byte) []byte {
			return server.process(context.Background(), payload)
		})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload, err := securechannel.EnrollClient(ctx, clientConnection, controllerIdentity.Public, request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := DecodeResponse(payload)
	if err != nil {
		t.Fatal(err)
	}
	if response.NodeID != "node-a" || response.NodeKeyFingerprint != securechannel.Fingerprint(nodeIdentity.Public) {
		t.Fatalf("unexpected enrollment response: %+v", response)
	}
	if !sameTestKey(repository.publicKey, nodeIdentity.Public) {
		t.Fatal("Controller did not store the node Noise key")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestEnrollmentRejectsInvalidTokenInsideEncryptedResponse(t *testing.T) {
	controllerIdentity, _ := securechannel.GenerateKeyPair()
	nodeIdentity, _ := securechannel.GenerateKeyPair()
	repository := &fakeEnrollmentStore{nodeID: "node-a", token: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG", createdAt: time.Now().UTC()}
	server, _ := NewServer(controllerIdentity, repository, nil, time.Now)
	request, _ := json.Marshal(Request{NodeID: "node-a", Token: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", PublicKey: securechannel.EncodePublicKey(nodeIdentity.Public)})
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	go func() {
		defer serverConnection.Close()
		_ = securechannel.EnrollServer(serverConnection, controllerIdentity, func(payload []byte) []byte {
			return server.process(context.Background(), payload)
		})
	}()
	payload, err := securechannel.EnrollClient(context.Background(), clientConnection, controllerIdentity.Public, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(payload); err == nil {
		t.Fatal("invalid enrollment token was accepted")
	}
}

func TestEnrollmentRejectsTrailingJSONValues(t *testing.T) {
	controllerIdentity, _ := securechannel.GenerateKeyPair()
	nodeIdentity, _ := securechannel.GenerateKeyPair()
	token := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	repository := &fakeEnrollmentStore{nodeID: "node-a", token: token, createdAt: time.Now().UTC()}
	server, _ := NewServer(controllerIdentity, repository, nil, time.Now)
	request, _ := json.Marshal(Request{
		NodeID: "node-a", Token: token, PublicKey: securechannel.EncodePublicKey(nodeIdentity.Public),
	})
	request = append(request, []byte(`{}`)...)
	if _, err := DecodeResponse(server.process(context.Background(), request)); err == nil {
		t.Fatal("enrollment request with a trailing JSON value was accepted")
	}

	response, _ := json.Marshal(wireResponse{
		OK: true,
		Response: &Response{
			NodeID: "node-a", NodeKeyFingerprint: securechannel.Fingerprint(nodeIdentity.Public),
		},
	})
	response = append(response, []byte(`{}`)...)
	if _, err := DecodeResponse(response); err == nil {
		t.Fatal("enrollment response with a trailing JSON value was accepted")
	}
}

func sameTestKey(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
