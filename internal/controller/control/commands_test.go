package control

import (
	"context"
	"errors"
	"testing"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
)

func TestCommandBrokerDispatchesAndCompletesOneShotCommand(t *testing.T) {
	broker := NewCommandBroker()
	outbound, unregister := broker.Register("node-a")
	defer unregister()

	type dispatchOutcome struct {
		result *controlv1.NodeCommandResult
		err    error
	}
	finished := make(chan dispatchOutcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		result, err := broker.Dispatch(ctx, "node-a", CommandRequest{
			Kind:     controlv1.NodeCommandKind_NODE_COMMAND_KIND_TCP_CHECK,
			Deadline: time.Now().UTC().Add(time.Second),
			Address:  "192.0.2.10",
			Port:     443,
		})
		finished <- dispatchOutcome{result: result, err: err}
	}()

	var command *controlv1.NodeCommand
	select {
	case command = <-outbound:
	case <-ctx.Done():
		t.Fatal("timed out waiting for command")
	}
	if command.RequestId == "" || command.Address != "192.0.2.10" || command.Port != 443 {
		t.Fatalf("unexpected command: %+v", command)
	}
	completed := &controlv1.NodeCommandResult{
		RequestId: command.RequestId,
		Kind:      command.Kind,
		Success:   true,
	}
	if err := broker.Complete("node-a", completed); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-finished:
		if outcome.err != nil || outcome.result != completed {
			t.Fatalf("unexpected outcome: result=%+v err=%v", outcome.result, outcome.err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for command completion")
	}
}

func TestCommandBrokerFailsPendingCommandWhenAgentDisconnects(t *testing.T) {
	broker := NewCommandBroker()
	outbound, unregister := broker.Register("node-a")
	finished := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		_, err := broker.Dispatch(ctx, "node-a", CommandRequest{
			Kind:     controlv1.NodeCommandKind_NODE_COMMAND_KIND_AGENT_UNINSTALL,
			Deadline: time.Now().UTC().Add(time.Second),
		})
		finished <- err
	}()

	select {
	case <-outbound:
	case <-ctx.Done():
		t.Fatal("timed out waiting for command")
	}
	unregister()
	select {
	case err := <-finished:
		if !errors.Is(err, ErrCommandConnectionLost) {
			t.Fatalf("disconnect error=%v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for disconnect result")
	}
	if _, err := broker.Dispatch(ctx, "node-a", CommandRequest{Kind: controlv1.NodeCommandKind_NODE_COMMAND_KIND_TCP_CHECK}); !errors.Is(err, ErrNodeOffline) {
		t.Fatalf("offline dispatch error=%v", err)
	}
}
