package tc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type Runner interface {
	Run(context.Context, string, []string, []byte) (stdout, stderr []byte, err error)
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, path string, args []string, stdin []byte) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type Executor struct {
	tcPath string
	ipPath string
	runner Runner
}

func NewExecutor(tcPath, ipPath string, runner Runner) (*Executor, error) {
	if strings.TrimSpace(tcPath) == "" || strings.TrimSpace(ipPath) == "" {
		return nil, errors.New("tc and ip executable paths must not be empty")
	}
	if runner == nil {
		runner = OSRunner{}
	}
	return &Executor{tcPath: tcPath, ipPath: ipPath, runner: runner}, nil
}

func (e *Executor) Check(ctx context.Context, program Program) error {
	if !program.Active {
		return nil
	}
	if _, stderr, err := e.runner.Run(ctx, e.ipPath, []string{"link", "show", "dev", program.Config.PublicInterface}, nil); err != nil {
		return commandError("inspect public interface", stderr, err)
	}
	return nil
}

func (e *Executor) Apply(ctx context.Context, program Program) error {
	if program.Batch == "" {
		return nil
	}
	if program.Active {
		if _, _, err := e.runner.Run(ctx, e.ipPath, []string{"link", "show", "dev", program.Config.IFBInterface}, nil); err != nil {
			if _, stderr, addErr := e.runner.Run(ctx, e.ipPath, []string{"link", "add", "dev", program.Config.IFBInterface, "type", "ifb"}, nil); addErr != nil {
				return commandError("create IFB interface", stderr, addErr)
			}
		}
		if _, stderr, err := e.runner.Run(ctx, e.ipPath, []string{"link", "set", "dev", program.Config.IFBInterface, "up"}, nil); err != nil {
			return commandError("enable IFB interface", stderr, err)
		}
	}
	_, stderr, err := e.runner.Run(ctx, e.tcPath, []string{"-force", "-batch", "-"}, []byte(program.Batch))
	allowedMissingDevice := ""
	if !program.Active {
		allowedMissingDevice = program.Config.IFBInterface
	}
	if err != nil && !onlyMissingQdiscErrors(stderr, allowedMissingDevice, program.Batch) {
		return commandError("apply tc batch", stderr, err)
	}
	return nil
}

func onlyMissingQdiscErrors(stderr []byte, allowedMissingDevice, batch string) bool {
	text := strings.ToLower(strings.TrimSpace(string(stderr)))
	if text == "" {
		return false
	}
	allowedMissingDevice = strings.ToLower(strings.TrimSpace(allowedMissingDevice))
	batchLines := strings.Split(strings.ToLower(batch), "\n")
	foundMissing := false
	var pending []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "warning:"):
			continue
		case strings.HasPrefix(line, "command failed -:"):
			lineNumber, err := strconv.Atoi(strings.TrimPrefix(line, "command failed -:"))
			if err != nil || lineNumber < 1 || lineNumber > len(batchLines) || len(pending) == 0 {
				return false
			}
			command := strings.Fields(strings.TrimSpace(batchLines[lineNumber-1]))
			if !benignCleanupFailure(command, pending, allowedMissingDevice) {
				return false
			}
			foundMissing = true
			pending = nil
		default:
			pending = append(pending, line)
		}
	}
	return foundMissing && len(pending) == 0
}

func benignCleanupFailure(command, messages []string, allowedMissingDevice string) bool {
	if len(command) != 5 || command[0] != "qdisc" || command[1] != "del" || command[2] != "dev" ||
		command[3] == "" || command[4] != "root" && command[4] != "clsact" {
		return false
	}
	for _, message := range messages {
		switch {
		case strings.Contains(message, "cannot delete qdisc with handle of zero"):
		case strings.Contains(message, "cannot find specified qdisc"):
		case command[4] == "clsact" && strings.Contains(message, "invalid handle"):
		case allowedMissingDevice != "" && command[3] == allowedMissingDevice && missingDeviceName(message) == allowedMissingDevice:
		default:
			return false
		}
	}
	return true
}

func missingDeviceName(line string) string {
	const prefix = "cannot find device "
	line = strings.TrimSpace(strings.ToLower(line))
	line = strings.TrimSpace(strings.TrimPrefix(line, "error:"))
	if !strings.HasPrefix(line, prefix) {
		return ""
	}
	name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, prefix), "."))
	if len(name) >= 2 && (name[0] == '"' && name[len(name)-1] == '"' || name[0] == '\'' && name[len(name)-1] == '\'') {
		name = name[1 : len(name)-1]
	}
	return name
}

func (e *Executor) Verify(ctx context.Context, program Program) error {
	if !program.Active {
		return nil
	}
	byInterface := make(map[string]map[string]struct{})
	for _, expected := range program.ExpectedClasses {
		classes := byInterface[expected.Interface]
		if classes == nil {
			classes = make(map[string]struct{})
			byInterface[expected.Interface] = classes
		}
		classes[fmt.Sprintf("1:%x", expected.ClassID)] = struct{}{}
	}
	for device, expected := range byInterface {
		stdout, stderr, err := e.runner.Run(ctx, e.tcPath, []string{"-j", "class", "show", "dev", device}, nil)
		if err != nil {
			return commandError("verify tc classes", stderr, err)
		}
		handles, err := decodeClassHandles(stdout)
		if err != nil {
			return fmt.Errorf("decode tc classes for %s: %w", device, err)
		}
		for handle := range handles {
			delete(expected, handle)
		}
		if len(expected) != 0 {
			return fmt.Errorf("tc classes are missing on %s: %v", device, expected)
		}
	}
	return nil
}

func decodeClassHandles(output []byte) (map[string]struct{}, error) {
	handles := make(map[string]struct{})
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return handles, nil
	}
	if trimmed[0] == '[' {
		var classes []struct {
			Handle string `json:"handle"`
		}
		if err := json.Unmarshal(trimmed, &classes); err != nil {
			return nil, err
		}
		for _, class := range classes {
			handle := strings.ToLower(strings.TrimSpace(class.Handle))
			if handle != "" {
				handles[handle] = struct{}{}
			}
		}
		return handles, nil
	}

	// iproute2 5.5 accepts -j for `tc class show` but silently emits the
	// traditional text format. Each class line starts with: class KIND HANDLE.
	for lineNumber, line := range strings.Split(string(trimmed), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 3 || fields[0] != "class" {
			return nil, fmt.Errorf("unrecognized tc class output on line %d: %q", lineNumber+1, line)
		}
		handles[strings.ToLower(fields[2])] = struct{}{}
	}
	return handles, nil
}

func commandError(operation string, stderr []byte, err error) error {
	message := strings.TrimSpace(string(stderr))
	if len(message) > 4096 {
		message = message[:4096] + "..."
	}
	if message == "" {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s: %w: %s", operation, err, message)
}
