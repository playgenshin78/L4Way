package meter

import "testing"

func TestTrackerHandlesNormalDeltaAndReset(t *testing.T) {
	tracker, err := NewTracker(State{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := tracker.Observe("epoch-1", []Sample{{Name: "counter-a", Packets: 10, Bytes: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Deltas[0].Reset || first.Deltas[0].Bytes != 1000 || first.Sequence != 1 {
		t.Fatalf("first batch = %+v", first)
	}
	second, err := tracker.Observe("epoch-1", []Sample{{Name: "counter-a", Packets: 15, Bytes: 1600}})
	if err != nil {
		t.Fatal(err)
	}
	if second.Deltas[0].Reset || second.Deltas[0].Packets != 5 || second.Deltas[0].Bytes != 600 {
		t.Fatalf("second batch = %+v", second)
	}
	third, err := tracker.Observe("epoch-1", []Sample{{Name: "counter-a", Packets: 2, Bytes: 200}})
	if err != nil {
		t.Fatal(err)
	}
	if !third.Deltas[0].Reset || third.Deltas[0].Bytes != 200 {
		t.Fatalf("reset batch = %+v", third)
	}
}

func TestTrackerEpochChangeStartsFromZero(t *testing.T) {
	tracker, _ := NewTracker(State{Epoch: "old", Sequence: 3, Values: map[string]Value{"counter-a": {Packets: 100, Bytes: 10000}}})
	batch, err := tracker.Observe("new", []Sample{{Name: "counter-a", Packets: 3, Bytes: 300}})
	if err != nil {
		t.Fatal(err)
	}
	if !batch.Deltas[0].Reset || batch.Deltas[0].Bytes != 300 || batch.Sequence != 4 {
		t.Fatalf("batch = %+v", batch)
	}
}

func TestTrackerRejectsDuplicateSamplesWithoutMutation(t *testing.T) {
	tracker, _ := NewTracker(State{})
	_, err := tracker.Observe("epoch", []Sample{{Name: "same"}, {Name: "same"}})
	if err == nil {
		t.Fatal("Observe() accepted duplicate samples")
	}
	if tracker.State().Sequence != 0 {
		t.Fatal("failed observation mutated tracker state")
	}
}

func TestTrackerDoesNotSpendSequenceForZeroDelta(t *testing.T) {
	tracker, _ := NewTracker(State{})
	first, err := tracker.Observe("epoch", []Sample{{Name: "counter-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 0 || tracker.State().Sequence != 0 {
		t.Fatalf("zero baseline consumed a sequence: batch=%+v state=%+v", first, tracker.State())
	}
	second, err := tracker.Observe("epoch", []Sample{{Name: "counter-a", Packets: 1, Bytes: 100}})
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != 1 || len(second.Deltas) != 1 || second.Deltas[0].Bytes != 100 {
		t.Fatalf("first nonzero batch = %+v", second)
	}
}
