//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"errors"
	"testing"
	"unsafe"
)

func TestEventSourceHooksRequireCompleteCapabilityBeforeAdmission(t *testing.T) {
	cause := errors.New("missing source hook export")
	for _, missing := range []string{
		"phantom_go_event_source_hooks_version", "phantom_go_event_source_hooks_open",
		"phantom_go_event_source_hooks_operation", "phantom_go_event_source_hooks_failure",
		"phantom_go_event_source_hooks_active",
	} {
		_, err := bindEventSourceHookSymbols(func(name string) (uintptr, error) {
			if name == missing {
				return 0, cause
			}
			return 1, nil
		}, func(uintptr) (uint64, error) { return 1, nil })
		if failureKind(err) != "native_event_source_hooks_unavailable" || !errors.Is(err, cause) {
			t.Fatalf("missing %s: %v", missing, err)
		}
	}
	_, err := bindEventSourceHookSymbols(func(string) (uintptr, error) { return 1, nil }, func(uintptr) (uint64, error) { return 2, nil })
	if failureKind(err) != "native_event_source_hooks_abi_mismatch" {
		t.Fatalf("version: %v", err)
	}
	if unsafe.Sizeof(EventSourceHooksReply{}) != 208 {
		t.Fatal("source hook reply layout changed")
	}
}
