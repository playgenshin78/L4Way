package controlclient

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
)

func TestExecuteTCPCheckOpensOneTCPConnection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			err = connection.Close()
		}
		accepted <- err
	}()

	endpoint := listener.Addr().(*net.TCPAddr)
	now := time.Now().UTC()
	runner := &Runner{now: func() time.Time { return now }}
	completion := runner.executeTCPCheck(context.Background(), &controlv1.NodeCommand{
		RequestId: "check-1",
		Kind:      controlv1.NodeCommandKind_NODE_COMMAND_KIND_TCP_CHECK,
		Address:   netip.MustParseAddr(endpoint.IP.String()).String(),
		Port:      uint32(endpoint.Port),
	})
	if completion.finalize != nil || completion.result == nil || !completion.result.Success || completion.result.LatencyMicros == 0 {
		t.Fatalf("unexpected completion: %+v", completion)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP check did not reach the listener")
	}
}

func TestCommandKindRemainsActiveUntilResultIsConsumed(t *testing.T) {
	now := time.Now().UTC()
	runner := &Runner{now: func() time.Time { return now }}
	results := make(chan commandCompletion, 1)
	command := &controlv1.NodeCommand{
		RequestId: "unsupported-1", Kind: controlv1.NodeCommandKind(99), DeadlineUnix: now.Add(time.Minute).Unix(),
	}
	if err := runner.startCommand(context.Background(), command, results); err != nil {
		t.Fatal(err)
	}
	completion := <-results
	if !runner.commandKindInProgress(controlv1.NodeCommandKind(99)) {
		t.Fatal("command kind was cleared before its result was consumed")
	}
	completion.release()
	if runner.commandInProgress() {
		t.Fatal("command remained active after its result was consumed")
	}
}

func TestExecuteTCPCheckRejectsNonIPv4Target(t *testing.T) {
	runner := &Runner{now: time.Now}
	completion := runner.executeTCPCheck(context.Background(), &controlv1.NodeCommand{
		RequestId: "check-2",
		Kind:      controlv1.NodeCommandKind_NODE_COMMAND_KIND_TCP_CHECK,
		Address:   "::1",
		Port:      443,
	})
	if completion.result == nil || completion.result.Success || completion.result.ErrorCode != "invalid_target" {
		t.Fatalf("unexpected completion: %+v", completion)
	}
}
