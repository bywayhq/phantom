//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"errors"
	"testing"
)

func TestSSECapabilityNegotiationRejectsOldAndPartialPayloads(t *testing.T) {
	for _, missing := range []string{"phantom_go_sse_version", "phantom_go_sse_request", "phantom_go_sse_next", "phantom_go_sse_result"} {
		called := false
		_, err := bindSSESymbols(func(name string) (uintptr, error) {
			if name == missing {
				return 0, errors.New("missing symbol")
			}
			return 1, nil
		}, func(uintptr) (uint64, error) { called = true; return 1, nil })
		if failureKind(err) != "native_sse_unavailable" || called {
			t.Fatalf("partial payload %s: %v, version called=%v", missing, err, called)
		}
	}
	_, err := bindSSESymbols(func(string) (uintptr, error) { return 1, nil }, func(uintptr) (uint64, error) { return 2, nil })
	if failureKind(err) != "native_sse_abi_mismatch" {
		t.Fatalf("unknown SSE ABI accepted: %v", err)
	}
}

func failureKind(err error) string {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Kind
	}
	return ""
}
