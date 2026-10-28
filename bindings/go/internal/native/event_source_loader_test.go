//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"errors"
	"testing"
)

func TestEventSourceCapabilityRequiresEverySymbolBeforeAdmission(t *testing.T) {
	cause := errors.New("missing source export")
	for _, missing := range []string{"phantom_go_event_source_version", "phantom_go_event_source_open", "phantom_go_event_source_operation", "phantom_go_event_source_result"} {
		_, err := bindEventSourceSymbols(func(name string) (uintptr, error) {
			if name == missing {
				return 0, cause
			}
			return 1, nil
		}, func(uintptr) (uint64, error) { return 1, nil })
		var failure *Failure
		if !errors.As(err, &failure) || failure.Kind != "native_event_source_unavailable" || !errors.Is(err, cause) {
			t.Fatalf("missing %s: %v", missing, err)
		}
	}
	_, err := bindEventSourceSymbols(func(string) (uintptr, error) { return 1, nil }, func(uintptr) (uint64, error) { return 2, nil })
	if failureKind(err) != "native_event_source_abi_mismatch" {
		t.Fatalf("wrong version: %v", err)
	}
}
