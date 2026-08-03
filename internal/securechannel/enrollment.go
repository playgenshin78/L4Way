package securechannel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/flynn/noise"
)

const enrollmentPrologue = "flux/enrollment/noise-aesgcm/v1"

// EnrollClient performs a responder-authenticated Noise_NK handshake. The
// request and response payloads are both protected with AES-256-GCM; the
// caller pins controllerPublic out of band.
func EnrollClient(ctx context.Context, raw net.Conn, controllerPublic, requestPayload []byte) ([]byte, error) {
	if raw == nil || len(controllerPublic) != KeySize || len(requestPayload) == 0 {
		return nil, errors.New("Noise enrollment client configuration is invalid")
	}
	deadline := time.Now().Add(handshakeLimit)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Pattern: noise.HandshakeNK, Initiator: true,
		Prologue: []byte(enrollmentPrologue), PeerStatic: controllerPublic,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize Noise enrollment handshake: %w", err)
	}
	request, _, _, err := hs.WriteMessage(nil, requestPayload)
	if err != nil {
		return nil, fmt.Errorf("encrypt enrollment request: %w", err)
	}
	if err := writeFrame(raw, request); err != nil {
		return nil, fmt.Errorf("send enrollment request: %w", err)
	}
	response, err := readFrame(raw)
	if err != nil {
		return nil, fmt.Errorf("receive enrollment response: %w", err)
	}
	payload, _, _, err := hs.ReadMessage(nil, response)
	if err != nil {
		return nil, fmt.Errorf("authenticate enrollment response: %w", err)
	}
	return payload, nil
}

// EnrollServer authenticates the Controller to an enrolling node and passes
// the decrypted request to handle. Enrollment tokens authenticate the node at
// the application layer because the node's new static key is not trusted yet.
func EnrollServer(raw net.Conn, controllerIdentity KeyPair, handle func([]byte) []byte) error {
	if raw == nil || handle == nil {
		return errors.New("Noise enrollment server configuration is invalid")
	}
	if err := ValidateKeyPair(controllerIdentity); err != nil {
		return err
	}
	if err := raw.SetDeadline(time.Now().Add(handshakeLimit)); err != nil {
		return err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Pattern: noise.HandshakeNK,
		Prologue: []byte(enrollmentPrologue), StaticKeypair: toNoiseKey(controllerIdentity),
	})
	if err != nil {
		return fmt.Errorf("initialize Noise enrollment server: %w", err)
	}
	request, err := readFrame(raw)
	if err != nil {
		return fmt.Errorf("receive enrollment request: %w", err)
	}
	payload, _, _, err := hs.ReadMessage(nil, request)
	if err != nil {
		return fmt.Errorf("decrypt enrollment request: %w", err)
	}
	responsePayload := handle(payload)
	if len(responsePayload) == 0 {
		return errors.New("enrollment handler returned an empty response")
	}
	response, _, _, err := hs.WriteMessage(nil, responsePayload)
	if err != nil {
		return fmt.Errorf("encrypt enrollment response: %w", err)
	}
	if err := writeFrame(raw, response); err != nil {
		return fmt.Errorf("send enrollment response: %w", err)
	}
	return nil
}
