package usage

import (
	"errors"
	"fmt"
	"time"

	"flux.local/flux/internal/spec"
)

type Delta struct {
	ForwardID       string                `json:"forward_id"`
	Protocol        spec.Protocol         `json:"protocol"`
	Direction       spec.TrafficDirection `json:"direction"`
	ResourceVersion uint64                `json:"resource_version"`
	Packets         uint64                `json:"packets"`
	Bytes           uint64                `json:"bytes"`
	Reset           bool                  `json:"reset,omitempty"`
}

type Batch struct {
	NodeID     string    `json:"node_id"`
	Epoch      string    `json:"epoch"`
	Sequence   uint64    `json:"sequence"`
	Generation uint64    `json:"generation"`
	ObservedAt time.Time `json:"observed_at"`
	Deltas     []Delta   `json:"deltas"`
}

func (b Batch) Validate() error {
	if err := spec.ValidateIdentifier("usage.node_id", b.NodeID); err != nil {
		return err
	}
	if !validChecksum(b.Epoch) || b.Sequence == 0 || b.Generation == 0 || b.ObservedAt.IsZero() {
		return errors.New("usage batch epoch, sequence, generation, or observed_at is invalid")
	}
	seen := make(map[string]struct{}, len(b.Deltas))
	for i, delta := range b.Deltas {
		if err := spec.ValidateIdentifier("usage.forward_id", delta.ForwardID); err != nil {
			return err
		}
		if delta.Protocol != spec.ProtocolTCP && delta.Protocol != spec.ProtocolUDP {
			return fmt.Errorf("usage delta %d protocol is invalid", i)
		}
		if delta.Direction != spec.DirectionUpload && delta.Direction != spec.DirectionDownload {
			return fmt.Errorf("usage delta %d direction is invalid", i)
		}
		if delta.ResourceVersion == 0 {
			return fmt.Errorf("usage delta %d resource_version is invalid", i)
		}
		key := fmt.Sprintf("%s/%s/%s/%d", delta.ForwardID, delta.Protocol, delta.Direction, delta.ResourceVersion)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("usage delta %d is duplicated", i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validChecksum(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
