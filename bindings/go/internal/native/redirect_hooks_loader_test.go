//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"errors"
	"testing"
	"unsafe"
)

func TestRedirectHooksCapabilityRequiresEverySymbolBeforeAdmission(t *testing.T) {
	cause := errors.New("missing redirect export")
	for _, missing := range []string{"phantom_go_redirect_hook_version", "phantom_go_redirect_hook_request", "phantom_go_redirect_hook_copy", "phantom_go_redirect_hook_reply"} {
		_, err := bindRedirectHookSymbols(func(name string) (uintptr, error) {
			if name == missing {
				return 0, cause
			}
			return 1, nil
		}, func(uintptr) (uint64, error) { return 1, nil })
		if failureKind(err) != "native_redirect_hooks_unavailable" || !errors.Is(err, cause) {
			t.Fatalf("missing %s: %v", missing, err)
		}
	}
	_, err := bindRedirectHookSymbols(func(string) (uintptr, error) { return 1, nil }, func(uintptr) (uint64, error) { return 2, nil })
	if failureKind(err) != "native_redirect_hooks_abi_mismatch" {
		t.Fatalf("wrong version: %v", err)
	}
	if unsafe.Sizeof(RedirectInvocation{}) != 280 || unsafe.Sizeof(CallbackSSELimits{}) != 16 {
		t.Fatal("redirect descriptors changed layout")
	}
}
