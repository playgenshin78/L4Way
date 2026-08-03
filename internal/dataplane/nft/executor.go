package nft

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
	Run(ctx context.Context, path string, args []string, stdin []byte) (stdout, stderr []byte, err error)
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, path string, args []string, stdin []byte) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type Executor struct {
	path   string
	runner Runner
}

func NewExecutor(path string, runner Runner) (*Executor, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("nft executable path must not be empty")
	}
	if runner == nil {
		runner = OSRunner{}
	}
	return &Executor{path: path, runner: runner}, nil
}

type InstalledState struct {
	Exists          bool
	Managed         bool
	Generation      uint64
	DesiredChecksum string
	ProgramChecksum string
}

func (e *Executor) Inspect(ctx context.Context) (InstalledState, error) {
	stdout, stderr, err := e.runner.Run(ctx, e.path, []string{"-j", "list", "tables"}, nil)
	if err != nil {
		return InstalledState{}, commandError("inspect tables", stderr, err)
	}
	var document struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(stdout, &document); err != nil {
		return InstalledState{}, fmt.Errorf("decode nft table list: %w", err)
	}
	for _, raw := range document.Nftables {
		var envelope struct {
			Table *struct {
				Family  string `json:"family"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"table"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return InstalledState{}, fmt.Errorf("decode nft table entry: %w", err)
		}
		if envelope.Table == nil || envelope.Table.Family != TableFamily || envelope.Table.Name != TableName {
			continue
		}
		generation, desiredChecksum, programChecksum, managed := parseTableComment(envelope.Table.Comment)
		if !managed {
			counters, err := e.ReadCounters(ctx)
			if err != nil {
				return InstalledState{}, fmt.Errorf("inspect metadata counters: %w", err)
			}
			generation, desiredChecksum, programChecksum, managed = parseMetadataCounters(counters)
		}
		return InstalledState{
			Exists:          true,
			Managed:         managed,
			Generation:      generation,
			DesiredChecksum: desiredChecksum,
			ProgramChecksum: programChecksum,
		}, nil
	}
	return InstalledState{}, nil
}

func parseMetadataCounters(counters []RawCounter) (generation uint64, desiredChecksum, programChecksum string, managed bool) {
	const (
		generationPrefix = "flux_generation_"
		desiredPrefix    = "flux_desired_"
		programPrefix    = "flux_program_"
	)
	var generationFound, desiredFound, programFound bool
	for _, counter := range counters {
		switch {
		case strings.HasPrefix(counter.Name, generationPrefix):
			if generationFound {
				return 0, "", "", false
			}
			value := strings.TrimPrefix(counter.Name, generationPrefix)
			parsed, err := strconv.ParseUint(value, 10, 64)
			if err != nil || parsed == 0 {
				return 0, "", "", false
			}
			generation, generationFound = parsed, true
		case strings.HasPrefix(counter.Name, desiredPrefix):
			if desiredFound {
				return 0, "", "", false
			}
			value := strings.TrimPrefix(counter.Name, desiredPrefix)
			if !checksumPattern.MatchString(value) {
				return 0, "", "", false
			}
			desiredChecksum, desiredFound = value, true
		case strings.HasPrefix(counter.Name, programPrefix):
			if programFound {
				return 0, "", "", false
			}
			value := strings.TrimPrefix(counter.Name, programPrefix)
			if !checksumPattern.MatchString(value) {
				return 0, "", "", false
			}
			programChecksum, programFound = value, true
		}
	}
	return generation, desiredChecksum, programChecksum, generationFound && desiredFound && programFound
}

func (e *Executor) Check(ctx context.Context, script string) error {
	_, stderr, err := e.runner.Run(ctx, e.path, []string{"-c", "-f", "-"}, []byte(script))
	if err != nil {
		return commandError("preflight nft program", stderr, err)
	}
	return nil
}

func (e *Executor) Apply(ctx context.Context, script string) error {
	_, stderr, err := e.runner.Run(ctx, e.path, []string{"-f", "-"}, []byte(script))
	if err != nil {
		return commandError("apply nft program", stderr, err)
	}
	return nil
}

type RawCounter struct {
	Name    string `json:"name"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

func (e *Executor) ReadCounters(ctx context.Context) ([]RawCounter, error) {
	stdout, stderr, err := e.runner.Run(ctx, e.path, []string{"-j", "list", "counters"}, nil)
	if err != nil {
		return nil, commandError("read nft counters", stderr, err)
	}
	var document struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(stdout, &document); err != nil {
		return nil, fmt.Errorf("decode nft counters: %w", err)
	}
	counters := make([]RawCounter, 0, len(document.Nftables))
	for _, raw := range document.Nftables {
		var envelope struct {
			Counter *struct {
				Family  string `json:"family"`
				Table   string `json:"table"`
				Name    string `json:"name"`
				Packets uint64 `json:"packets"`
				Bytes   uint64 `json:"bytes"`
			} `json:"counter"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil, fmt.Errorf("decode nft counter entry: %w", err)
		}
		if envelope.Counter == nil || envelope.Counter.Family != TableFamily || envelope.Counter.Table != TableName {
			continue
		}
		counters = append(counters, RawCounter{
			Name:    envelope.Counter.Name,
			Packets: envelope.Counter.Packets,
			Bytes:   envelope.Counter.Bytes,
		})
	}
	return counters, nil
}

func parseTableComment(comment string) (generation uint64, desiredChecksum, programChecksum string, managed bool) {
	const prefix = "managed-by=flux;generation="
	if !strings.HasPrefix(comment, prefix) {
		return 0, "", "", false
	}
	remainder := strings.TrimPrefix(comment, prefix)
	generationParts := strings.SplitN(remainder, ";desired=", 2)
	if len(generationParts) != 2 {
		return 0, "", "", false
	}
	checksumParts := strings.SplitN(generationParts[1], ";program=", 2)
	if len(checksumParts) != 2 || !checksumPattern.MatchString(checksumParts[0]) || !checksumPattern.MatchString(checksumParts[1]) {
		return 0, "", "", false
	}
	generation, err := strconv.ParseUint(generationParts[0], 10, 64)
	if err != nil || generation == 0 {
		return 0, "", "", false
	}
	return generation, checksumParts[0], checksumParts[1], true
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
