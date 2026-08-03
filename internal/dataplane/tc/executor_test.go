package tc

import (
	"context"
	"errors"
	"testing"
)

type applyRunner struct {
	stderr []byte
}

func (r applyRunner) Run(context.Context, string, []string, []byte) ([]byte, []byte, error) {
	return nil, r.stderr, errors.New("exit status 1")
}

func TestApplyToleratesOnlyMissingIdempotentQdiscDeletes(t *testing.T) {
	runner := applyRunner{stderr: []byte("Error: Cannot delete qdisc with handle of zero.\nCommand failed -:1\nError: Invalid handle.\nCommand failed -:2\nError: Cannot find specified qdisc on specified device.\nCommand failed -:3\nWarning: sch_htb: quantum of class 10001 is big. Consider r2q change.\n")}
	executor, err := NewExecutor("tc", "ip", runner)
	if err != nil {
		t.Fatal(err)
	}
	batch := "qdisc del dev eth0 root\nqdisc del dev eth0 clsact\nqdisc del dev flux-ifb0 root\n"
	if err := executor.Apply(context.Background(), Program{Batch: batch}); err != nil {
		t.Fatal(err)
	}
}

func TestApplyToleratesMissingConfiguredIFBDuringInactiveCleanup(t *testing.T) {
	for _, missingLine := range []string{`Cannot find device "flux-ifb0"`, `Error: Cannot find device "flux-ifb0"`} {
		t.Run(missingLine, func(t *testing.T) {
			runner := applyRunner{stderr: []byte("Error: Cannot delete qdisc with handle of zero.\nCommand failed -:1\n" + missingLine + "\nCommand failed -:3\n")}
			executor, err := NewExecutor("tc", "ip", runner)
			if err != nil {
				t.Fatal(err)
			}
			program := Program{
				Batch:  "qdisc del dev eth0 root\nqdisc del dev eth0 clsact\nqdisc del dev flux-ifb0 root\n",
				Config: Config{PublicInterface: "eth0", IFBInterface: "flux-ifb0"},
			}
			if err := executor.Apply(context.Background(), program); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestApplyDoesNotHideMissingUnexpectedDevice(t *testing.T) {
	runner := applyRunner{stderr: []byte("Cannot find device \"ens33\"\nCommand failed -:1\n")}
	executor, err := NewExecutor("tc", "ip", runner)
	if err != nil {
		t.Fatal(err)
	}
	program := Program{
		Batch:  "qdisc del dev ens33 root\n",
		Config: Config{PublicInterface: "ens33", IFBInterface: "flux-ifb0"},
	}
	if err := executor.Apply(context.Background(), program); err == nil {
		t.Fatal("missing public interface was ignored")
	}
}

func TestApplyDoesNotHideOtherBatchFailures(t *testing.T) {
	runner := applyRunner{stderr: []byte("Error: Cannot delete qdisc with handle of zero.\nCommand failed -:1\nRTNETLINK answers: Invalid argument\nCommand failed -:4\n")}
	executor, err := NewExecutor("tc", "ip", runner)
	if err != nil {
		t.Fatal(err)
	}
	batch := "qdisc del dev eth0 root\nqdisc del dev eth0 clsact\nqdisc del dev flux-ifb0 root\nfilter add dev eth0 ingress protocol ip\n"
	if err := executor.Apply(context.Background(), Program{Batch: batch}); err == nil {
		t.Fatal("non-cleanup tc failure was ignored")
	}
}

func TestApplyDoesNotHideInvalidHandleOutsideClsactCleanup(t *testing.T) {
	runner := applyRunner{stderr: []byte("Error: Invalid handle.\nCommand failed -:1\n")}
	executor, err := NewExecutor("tc", "ip", runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Apply(context.Background(), Program{Batch: "qdisc del dev eth0 root\n"}); err == nil {
		t.Fatal("invalid root cleanup failure was ignored")
	}
}

func TestDecodeClassHandlesSupportsJSONAndLegacyText(t *testing.T) {
	for name, output := range map[string]string{
		"json":        `[{"kind":"htb","handle":"1:a"},{"kind":"htb","handle":"1:b"}]`,
		"legacy text": "class htb 1:a parent 1:1 rate 2Mbit\nclass htb 1:b parent 1:1 rate 3Mbit\n",
	} {
		t.Run(name, func(t *testing.T) {
			handles, err := decodeClassHandles([]byte(output))
			if err != nil {
				t.Fatal(err)
			}
			for _, handle := range []string{"1:a", "1:b"} {
				if _, ok := handles[handle]; !ok {
					t.Fatalf("missing handle %s in %v", handle, handles)
				}
			}
		})
	}
}

func TestDecodeClassHandlesRejectsUnknownOutput(t *testing.T) {
	if _, err := decodeClassHandles([]byte("warning: unsupported output\n")); err == nil {
		t.Fatal("unknown tc output was accepted")
	}
}
