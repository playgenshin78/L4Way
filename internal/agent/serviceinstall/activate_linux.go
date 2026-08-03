//go:build linux

package serviceinstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func preflight(systemctlPath string) error {
	if os.Geteuid() != 0 {
		return errors.New("flux-agent install must run as root")
	}
	if strings.TrimSpace(systemctlPath) == "" {
		return errors.New("systemctl path is required")
	}
	if _, err := exec.LookPath(systemctlPath); err != nil {
		return fmt.Errorf("systemd is required: %w", err)
	}
	return nil
}

func activate(ctx context.Context, systemctlPath string) error {
	if err := preflight(systemctlPath); err != nil {
		return err
	}
	for _, arguments := range [][]string{{"daemon-reload"}, {"enable", "--now", ServiceName}} {
		command := exec.CommandContext(ctx, systemctlPath, arguments...)
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s failed: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}
