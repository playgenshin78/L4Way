package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/securechannel"
	"flux.local/flux/internal/spec"
)

type enrollmentStore interface {
	CompleteEnrollment(context.Context, string, string, []byte) (store.NodeKeyRecord, error)
}

type Server struct {
	identity securechannel.KeyPair
	store    enrollmentStore
	logger   *slog.Logger
	now      func() time.Time
	slots    chan struct{}
}

const maxConcurrentEnrollments = 64

type Request struct {
	NodeID       string `json:"node_id"`
	Token        string `json:"token"`
	PublicKey    string `json:"public_key"`
	AgentVersion string `json:"agent_version"`
}

type Response struct {
	NodeID                   string    `json:"node_id"`
	NodeKeyFingerprint       string    `json:"node_key_fingerprint"`
	ControllerPublicKey      string    `json:"controller_public_key"`
	ControllerKeyFingerprint string    `json:"controller_key_fingerprint"`
	EnrolledAt               time.Time `json:"enrolled_at"`
}

type wireResponse struct {
	OK       bool      `json:"ok"`
	Response *Response `json:"response,omitempty"`
	Code     string    `json:"code,omitempty"`
	Message  string    `json:"message,omitempty"`
}

func NewServer(identity securechannel.KeyPair, repository enrollmentStore, logger *slog.Logger, now func() time.Time) (*Server, error) {
	if err := securechannel.ValidateKeyPair(identity); err != nil {
		return nil, err
	}
	if repository == nil {
		return nil, errors.New("enrollment store must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &Server{
		identity: identity, store: repository, logger: logger, now: now,
		slots: make(chan struct{}, maxConcurrentEnrollments),
	}, nil
}

func (s *Server) Serve(listener net.Listener) error {
	if listener == nil {
		return errors.New("enrollment listener must not be nil")
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case s.slots <- struct{}{}:
		default:
			s.logger.Warn("Noise enrollment connection rejected", "remote_address", connection.RemoteAddr(), "error", "concurrency limit reached")
			_ = connection.Close()
			continue
		}
		go func() {
			defer func() { <-s.slots }()
			defer connection.Close()
			if err := securechannel.EnrollServer(connection, s.identity, func(payload []byte) []byte {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return s.process(ctx, payload)
			}); err != nil {
				s.logger.Warn("Noise enrollment connection rejected", "remote_address", connection.RemoteAddr(), "error", err)
			}
		}()
	}
}

func (s *Server) process(ctx context.Context, payload []byte) []byte {
	failure := func(code, message string) []byte {
		encoded, _ := json.Marshal(wireResponse{OK: false, Code: code, Message: message})
		return encoded
	}
	if len(payload) == 0 || len(payload) > 64<<10 {
		return failure("invalid_request", "enrollment request size is invalid")
	}
	var request Request
	if err := decodeSingleJSON(payload, &request); err != nil {
		return failure("invalid_request", "enrollment request is invalid")
	}
	if err := validateRequest(request); err != nil {
		return failure("invalid_request", err.Error())
	}
	publicKey, err := securechannel.ParsePublicKey(request.PublicKey)
	if err != nil {
		return failure("invalid_request", err.Error())
	}
	record, err := s.store.CompleteEnrollment(ctx, request.NodeID, request.Token, publicKey)
	if errors.Is(err, store.ErrInvalidEnrollment) {
		return failure("enrollment_denied", "enrollment credentials were rejected")
	}
	if err != nil {
		s.logger.Error("complete node enrollment", "node_id", request.NodeID, "error", err)
		return failure("enrollment_unavailable", "enrollment is temporarily unavailable")
	}
	response := &Response{
		NodeID: request.NodeID, NodeKeyFingerprint: record.Fingerprint,
		ControllerPublicKey:      securechannel.EncodePublicKey(s.identity.Public),
		ControllerKeyFingerprint: securechannel.Fingerprint(s.identity.Public),
		EnrolledAt:               record.CreatedAt,
	}
	encoded, err := json.Marshal(wireResponse{OK: true, Response: response})
	if err != nil {
		return failure("internal_error", "enrollment response could not be encoded")
	}
	return encoded
}

func DecodeResponse(payload []byte) (Response, error) {
	var envelope wireResponse
	if err := decodeSingleJSON(payload, &envelope); err != nil {
		return Response{}, fmt.Errorf("decode enrollment response: %w", err)
	}
	if !envelope.OK {
		if envelope.Message == "" {
			envelope.Message = "Controller rejected enrollment"
		}
		return Response{}, errors.New(envelope.Message)
	}
	if envelope.Response == nil || envelope.Response.NodeID == "" || envelope.Response.NodeKeyFingerprint == "" {
		return Response{}, errors.New("Controller returned an incomplete enrollment response")
	}
	return *envelope.Response, nil
}

func decodeSingleJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("payload must contain exactly one JSON value")
	}
	return nil
}

func validateRequest(request Request) error {
	if err := spec.ValidateIdentifier("node_id", request.NodeID); err != nil {
		return err
	}
	if len(request.Token) < 32 || len(request.Token) > 256 || strings.ContainsAny(request.Token, "\r\n\t ") {
		return errors.New("token is invalid")
	}
	if len(request.PublicKey) < 40 || len(request.PublicKey) > 64 {
		return errors.New("node public key is invalid")
	}
	if len(request.AgentVersion) > 128 {
		return errors.New("agent_version is too long")
	}
	return nil
}
