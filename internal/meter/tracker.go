package meter

import (
	"errors"
	"fmt"
	"sort"
)

type Sample struct {
	Name    string `json:"name"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type Value struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type State struct {
	Epoch    string           `json:"epoch"`
	Sequence uint64           `json:"sequence"`
	Values   map[string]Value `json:"values"`
}

type Delta struct {
	Name    string `json:"name"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	Reset   bool   `json:"reset,omitempty"`
}

type Batch struct {
	Epoch    string  `json:"epoch"`
	Sequence uint64  `json:"sequence"`
	Deltas   []Delta `json:"deltas"`
}

type Tracker struct {
	state State
}

func NewTracker(state State) (*Tracker, error) {
	if state.Values == nil {
		state.Values = make(map[string]Value)
	}
	if state.Sequence > 0 && state.Epoch == "" {
		return nil, errors.New("meter state with a sequence must have an epoch")
	}
	return &Tracker{state: cloneState(state)}, nil
}

// Observe produces deltas and advances the durable state. The caller must
// persist State() and enqueue Batch atomically before acknowledging usage.
func (t *Tracker) Observe(epoch string, samples []Sample) (Batch, error) {
	if epoch == "" {
		return Batch{}, errors.New("counter epoch must not be empty")
	}
	current := make(map[string]Value, len(samples))
	for _, sample := range samples {
		if sample.Name == "" {
			return Batch{}, errors.New("counter name must not be empty")
		}
		if _, exists := current[sample.Name]; exists {
			return Batch{}, fmt.Errorf("duplicate counter sample %s", sample.Name)
		}
		current[sample.Name] = Value{Packets: sample.Packets, Bytes: sample.Bytes}
	}

	epochChanged := t.state.Epoch != epoch
	names := make([]string, 0, len(current))
	for name := range current {
		names = append(names, name)
	}
	sort.Strings(names)
	deltas := make([]Delta, 0, len(names))
	for _, name := range names {
		value := current[name]
		previous, existed := t.state.Values[name]
		reset := epochChanged || !existed || value.Packets < previous.Packets || value.Bytes < previous.Bytes
		delta := Delta{Name: name, Reset: reset}
		if reset {
			delta.Packets = value.Packets
			delta.Bytes = value.Bytes
		} else {
			delta.Packets = value.Packets - previous.Packets
			delta.Bytes = value.Bytes - previous.Bytes
		}
		deltas = append(deltas, delta)
	}

	emit := false
	for _, delta := range deltas {
		if delta.Packets != 0 || delta.Bytes != 0 {
			emit = true
			break
		}
	}
	t.state.Epoch = epoch
	t.state.Values = current
	if !emit {
		return Batch{Epoch: epoch, Deltas: deltas}, nil
	}
	t.state.Sequence++
	return Batch{Epoch: epoch, Sequence: t.state.Sequence, Deltas: deltas}, nil
}

func (t *Tracker) State() State {
	return cloneState(t.state)
}

func cloneState(state State) State {
	result := state
	result.Values = make(map[string]Value, len(state.Values))
	for name, value := range state.Values {
		result.Values[name] = value
	}
	return result
}
