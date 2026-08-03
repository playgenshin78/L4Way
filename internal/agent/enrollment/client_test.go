package enrollment

import (
	"context"
	"net"
	"testing"
	"time"

	controllerenrollment "flux.local/flux/internal/controller/enrollment"
	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/securechannel"
)

type enrollmentRepository struct {
	nodeID string
	token  string
	key    []byte
}

func (r *enrollmentRepository) CompleteEnrollment(_ context.Context, nodeID, token string, publicKey []byte) (store.NodeKeyRecord, error) {
	if nodeID != r.nodeID || token != r.token {
		return store.NodeKeyRecord{}, store.ErrInvalidEnrollment
	}
	r.key = append([]byte(nil), publicKey...)
	return store.NodeKeyRecord{NodeID: nodeID, Fingerprint: securechannel.Fingerprint(publicKey), PublicKey: publicKey, CreatedAt: time.Now().UTC()}, nil
}

func TestEnrollPersistsNoiseIdentityAndPinnedControllerKey(t *testing.T) {
	controllerIdentity, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	token := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	repository := &enrollmentRepository{nodeID: "node-a", token: token}
	server, err := controllerenrollment.NewServer(controllerIdentity, repository, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = server.Serve(listener) }()

	identityDirectory := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := Enroll(ctx, Config{
		ControllerAddress: listener.Addr().String(), NodeID: "node-a", Token: token,
		ControllerPublicKey: controllerIdentity.Public, IdentityDir: identityDirectory,
		AgentVersion: "test", Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pair, controllerPublic, err := LoadIdentity(identityDirectory, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if response.NodeKeyFingerprint != securechannel.Fingerprint(pair.Public) || !sameKey(pair.Public, repository.key) {
		t.Fatal("persisted node key does not match the enrolled key")
	}
	if !sameKey(controllerPublic, controllerIdentity.Public) {
		t.Fatal("Controller public key was not pinned in the node identity")
	}
}
