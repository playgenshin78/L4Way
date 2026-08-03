package control

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
)

var (
	ErrNodeOffline           = errors.New("node is not connected")
	ErrCommandQueueFull      = errors.New("node command queue is full")
	ErrCommandConnectionLost = errors.New("node control connection was lost")
)

type CommandRequest struct {
	Kind        controlv1.NodeCommandKind
	Deadline    time.Time
	Address     string
	Port        uint32
	ReleaseURL  string
	ChecksumURL string
}

type commandOutcome struct {
	result *controlv1.NodeCommandResult
	err    error
}

type pendingCommand struct {
	nodeID string
	kind   controlv1.NodeCommandKind
	done   chan commandOutcome
}

type commandConnection struct {
	id       uint64
	outbound chan *controlv1.NodeCommand
}

// CommandBroker connects short-lived management requests to the already
// authenticated Agent stream. It is intentionally in-memory: commands are
// user-triggered operations and are never replayed after Controller restart.
type CommandBroker struct {
	mu          sync.Mutex
	nextID      uint64
	connections map[string]*commandConnection
	pending     map[string]pendingCommand
}

func NewCommandBroker() *CommandBroker {
	return &CommandBroker{
		connections: make(map[string]*commandConnection),
		pending:     make(map[string]pendingCommand),
	}
}

func (b *CommandBroker) Register(nodeID string) (<-chan *controlv1.NodeCommand, func()) {
	b.mu.Lock()
	b.nextID++
	connection := &commandConnection{id: b.nextID, outbound: make(chan *controlv1.NodeCommand, 8)}
	previous := b.connections[nodeID]
	b.connections[nodeID] = connection
	if previous != nil {
		b.failNodeLocked(nodeID, ErrCommandConnectionLost)
	}
	b.mu.Unlock()

	return connection.outbound, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if current := b.connections[nodeID]; current != nil && current.id == connection.id {
			delete(b.connections, nodeID)
			b.failNodeLocked(nodeID, ErrCommandConnectionLost)
		}
	}
}

func (b *CommandBroker) Dispatch(ctx context.Context, nodeID string, request CommandRequest) (*controlv1.NodeCommandResult, error) {
	requestID, err := newCommandID()
	if err != nil {
		return nil, err
	}
	if request.Deadline.IsZero() {
		request.Deadline = time.Now().UTC().Add(10 * time.Second)
	}
	message := &controlv1.NodeCommand{
		RequestId: requestID, Kind: request.Kind, DeadlineUnix: request.Deadline.Unix(),
		Address: request.Address, Port: request.Port, ReleaseUrl: request.ReleaseURL, ChecksumUrl: request.ChecksumURL,
	}
	done := make(chan commandOutcome, 1)

	b.mu.Lock()
	connection := b.connections[nodeID]
	if connection == nil {
		b.mu.Unlock()
		return nil, ErrNodeOffline
	}
	b.pending[requestID] = pendingCommand{nodeID: nodeID, kind: request.Kind, done: done}
	select {
	case connection.outbound <- message:
		b.mu.Unlock()
	default:
		delete(b.pending, requestID)
		b.mu.Unlock()
		return nil, ErrCommandQueueFull
	}

	select {
	case outcome := <-done:
		return outcome.result, outcome.err
	case <-ctx.Done():
		b.mu.Lock()
		delete(b.pending, requestID)
		b.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (b *CommandBroker) Complete(nodeID string, result *controlv1.NodeCommandResult) error {
	if result == nil || result.RequestId == "" {
		return errors.New("command result is empty")
	}
	b.mu.Lock()
	pending, exists := b.pending[result.RequestId]
	if !exists {
		b.mu.Unlock()
		return errors.New("command result does not match an active request")
	}
	if pending.nodeID != nodeID || pending.kind != result.Kind {
		b.mu.Unlock()
		return errors.New("command result identity does not match its request")
	}
	delete(b.pending, result.RequestId)
	b.mu.Unlock()
	pending.done <- commandOutcome{result: result}
	return nil
}

func (b *CommandBroker) failNodeLocked(nodeID string, err error) {
	for requestID, pending := range b.pending {
		if pending.nodeID != nodeID {
			continue
		}
		delete(b.pending, requestID)
		pending.done <- commandOutcome{err: err}
	}
}

func newCommandID() (string, error) {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate command identity: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
