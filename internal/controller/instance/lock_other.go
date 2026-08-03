//go:build !linux && !darwin && !freebsd && !windows

package instance

import (
	"errors"
	"os"
)

var errLockBusy = errors.New("Controller state lock is busy")

func lockFile(*os.File) error   { return nil }
func unlockFile(*os.File) error { return nil }
