//go:build linux || darwin || freebsd

package instance

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var errLockBusy = errors.New("Controller state lock is busy")

func lockFile(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return errLockBusy
	}
	return err
}

func unlockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
