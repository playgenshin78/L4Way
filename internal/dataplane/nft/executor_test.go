package nft

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type runnerCall struct {
	path  string
	args  []string
	stdin string
}

type fakeRunner struct {
	stdout  []byte
	outputs [][]byte
	stderr  []byte
	err     error
	calls   []runnerCall
}

func (f *fakeRunner) Run(_ context.Context, path string, args []string, stdin []byte) ([]byte, []byte, error) {
	f.calls = append(f.calls, runnerCall{path: path, args: append([]string(nil), args...), stdin: string(stdin)})
	stdout := f.stdout
	if len(f.outputs) != 0 {
		stdout = f.outputs[0]
		f.outputs = f.outputs[1:]
	}
	return stdout, f.stderr, f.err
}

func TestInspectRecognizesManagedTable(t *testing.T) {
	runner := &fakeRunner{stdout: []byte(`{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"flux","comment":"managed-by=flux;generation=9;desired=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;program=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]}`)}
	executor, err := NewExecutor("nft", runner)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := executor.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !installed.Exists || !installed.Managed || installed.Generation != 9 {
		t.Fatalf("Inspect() = %+v", installed)
	}
}

func TestInspectTreatsUnmarkedFluxTableAsForeign(t *testing.T) {
	runner := &fakeRunner{stdout: []byte(`{"nftables":[{"table":{"family":"inet","name":"flux"}}]}`)}
	executor, _ := NewExecutor("nft", runner)
	installed, err := executor.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !installed.Exists || installed.Managed {
		t.Fatalf("Inspect() = %+v, want foreign table", installed)
	}
}

func TestInspectRecognizesMetadataCountersWithoutTableComments(t *testing.T) {
	runner := &fakeRunner{outputs: [][]byte{
		[]byte(`{"nftables":[{"table":{"family":"inet","name":"flux"}}]}`),
		[]byte(`{"nftables":[{"counter":{"family":"inet","table":"flux","name":"flux_generation_11","packets":0,"bytes":0}},{"counter":{"family":"inet","table":"flux","name":"flux_desired_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","packets":0,"bytes":0}},{"counter":{"family":"inet","table":"flux","name":"flux_program_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","packets":0,"bytes":0}}]}`),
	}}
	executor, _ := NewExecutor("nft", runner)
	installed, err := executor.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !installed.Exists || !installed.Managed || installed.Generation != 11 || installed.DesiredChecksum != strings.Repeat("a", 64) || installed.ProgramChecksum != strings.Repeat("b", 64) {
		t.Fatalf("Inspect() = %+v", installed)
	}
}

func TestCheckAndApplyUseWholeScriptOnStdin(t *testing.T) {
	runner := &fakeRunner{}
	executor, _ := NewExecutor("/usr/sbin/nft", runner)
	if err := executor.Check(context.Background(), "table inet flux {}\n"); err != nil {
		t.Fatal(err)
	}
	if err := executor.Apply(context.Background(), "table inet flux {}\n"); err != nil {
		t.Fatal(err)
	}
	want := []runnerCall{
		{path: "/usr/sbin/nft", args: []string{"-c", "-f", "-"}, stdin: "table inet flux {}\n"},
		{path: "/usr/sbin/nft", args: []string{"-f", "-"}, stdin: "table inet flux {}\n"},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestReadCountersParsesOnlyOwnedTable(t *testing.T) {
	runner := &fakeRunner{stdout: []byte(`{"nftables":[{"counter":{"family":"inet","table":"flux","name":"c_one_t","packets":2,"bytes":120}},{"counter":{"family":"ip","table":"other","name":"ignored","packets":3,"bytes":42}}]}`)}
	executor, _ := NewExecutor("nft", runner)
	counters, err := executor.ReadCounters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []RawCounter{{Name: "c_one_t", Packets: 2, Bytes: 120}}
	if !reflect.DeepEqual(counters, want) {
		t.Fatalf("ReadCounters() = %#v, want %#v", counters, want)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(runner.calls[0].args, []string{"-j", "list", "counters"}) {
		t.Fatalf("ReadCounters() calls = %#v", runner.calls)
	}
}

func TestExecutorReturnsBoundedStderr(t *testing.T) {
	runner := &fakeRunner{stderr: []byte("bad syntax"), err: errors.New("exit status 1")}
	executor, _ := NewExecutor("nft", runner)
	err := executor.Apply(context.Background(), "bad")
	if err == nil || err.Error() != "apply nft program: exit status 1: bad syntax" {
		t.Fatalf("Apply() error = %v", err)
	}
}
