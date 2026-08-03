package instance

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestControllerStateAllowsOnlyOneOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.lock")
	first, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := Acquire(path); !errors.Is(err, ErrAlreadyRunning) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("second Controller lock err=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := Acquire(path)
	if err != nil {
		t.Fatalf("released Controller lock could not be reacquired: %v", err)
	}
	_ = third.Close()
}
