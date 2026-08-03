//go:build !linux

package serviceinstall

import (
	"context"
	"errors"
)

func preflight(string) error {
	return errors.New("flux-agent service installation is supported only on Linux with systemd")
}

func activate(context.Context, string) error {
	return errors.New("flux-agent service installation is supported only on Linux with systemd")
}
