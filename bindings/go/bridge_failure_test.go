//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package phantom

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompletionPumpFailurePreservesCauseForEveryWaiter(t *testing.T) {
	const marker = "PHANTOM_TEST_ISOLATED_PUMP_FAILURE"
	if os.Getenv(marker) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCompletionPumpFailurePreservesCauseForEveryWaiter$")
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "PHANTOM_GO_LIBRARY=") && !strings.HasPrefix(value, marker+"=") {
				child.Env = append(child.Env, value)
			}
		}
		missing := filepath.Join(t.TempDir(), "private-missing-library")
		child.Env = append(child.Env, "PHANTOM_GO_LIBRARY="+missing, marker+"=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("isolated pump failure: %v\n%s", err, output)
		}
		return
	}

	waiters := []chan completion{make(chan completion, 1), make(chan completion, 1)}
	pump.pending = map[uint64]chan completion{1: waiters[0], 2: waiters[1]}
	completionPump()

	var original *Error
	if !errors.As(pump.failure, &original) || original.Kind != "native_library_unavailable" || errors.Unwrap(original) == nil {
		t.Fatalf("pump did not retain the loader failure: %T", pump.failure)
	}
	if len(pump.pending) != 0 {
		t.Fatal("failed pump retained pending operations")
	}
	for index, waiter := range waiters {
		select {
		case event := <-waiter:
			var failure *Error
			if !errors.As(event.Error, &failure) || failure.Kind != "native_abi" {
				t.Fatalf("waiter %d lost the pump failure category: %T", index, event.Error)
			}
			if !errors.Is(event.Error, pump.failure) || errors.Unwrap(failure) != pump.failure {
				t.Fatalf("waiter %d lost the original pump failure", index)
			}
			if event.Error.Error() != "phantom: native_abi" {
				t.Fatalf("waiter %d exposed the loader path", index)
			}
		default:
			t.Fatalf("waiter %d was not released after pump failure", index)
		}
	}
}
