//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"errors"
	"testing"
	"unsafe"
)

func TestHeaderHooksCapabilityRequiresAllSymbolsBeforeAdmission(t *testing.T) {
	cause := errors.New("missing header export")
	for _, missing := range []string{"phantom_go_header_hook_version", "phantom_go_header_hook_request", "phantom_go_header_hook_copy", "phantom_go_header_hook_reply", "phantom_go_header_hook_cancel"} {
		_, err := bindHeaderHookSymbols(func(name string) (uintptr, error) {
			if name == missing {
				return 0, cause
			}
			return 1, nil
		}, func(uintptr) (uint64, error) { return 1, nil })
		if failureKind(err) != "native_header_hooks_unavailable" || !errors.Is(err, cause) {
			t.Fatalf("missing %s: %v", missing, err)
		}
	}
	_, err := bindHeaderHookSymbols(func(string) (uintptr, error) { return 1, nil }, func(uintptr) (uint64, error) { return 2, nil })
	if failureKind(err) != "native_header_hooks_abi_mismatch" {
		t.Fatalf("wrong version: %v", err)
	}
	if unsafe.Sizeof(HeaderInvocation{}) != 248 || unsafe.Sizeof(HeaderEdit{}) != 48 {
		t.Fatal("header hook descriptor layout changed")
	}
}
