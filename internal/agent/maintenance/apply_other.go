//go:build !linux

package maintenance

import (
	"context"
	"errors"
)

const MaintenanceServiceName = "flux-agent-maintenance.service"

func Apply(context.Context, string, string) error {
	return errors.New("Agent maintenance is supported on Linux only")
}

func Start(context.Context, string) error {
	return errors.New("Agent maintenance is supported on Linux only")
}

func RestartAgent(string) error {
	return errors.New("Agent maintenance is supported on Linux only")
}

func StopAgent(string) error {
	return errors.New("Agent maintenance is supported on Linux only")
}
