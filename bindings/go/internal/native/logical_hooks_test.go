//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"errors"
	"testing"
	"unsafe"
)

func TestLogicalHookCapabilityRequiresEverySymbolAndVersion(t *testing.T) {
	names := []string{"phantom_go_logical_hook_version", "phantom_go_logical_hook_request", "phantom_go_logical_hook_copy", "phantom_go_logical_hook_reply", "phantom_go_logical_hook_source_open"}
	for _, missing := range names {
		_, err := bindLogicalHookSymbols(func(name string) (uintptr, error) {
			if name == missing {
				return 0, errors.New("missing")
			}
			return 1, nil
		}, func(uintptr) (uint64, error) { return 1, nil })
		if err == nil {
			t.Fatalf("accepted missing %s", missing)
		}
	}
	if _, err := bindLogicalHookSymbols(func(string) (uintptr, error) { return 1, nil }, func(uintptr) (uint64, error) { return 2, nil }); err == nil {
		t.Fatal("accepted incompatible ABI")
	}
	if _, err := bindLogicalHookSymbols(func(string) (uintptr, error) { return 1, nil }, func(uintptr) (uint64, error) { return 1, nil }); err != nil {
		t.Fatal(err)
	}
}
func TestLogicalHookLayoutsMatchCABI(t *testing.T) {
	if unsafe.Sizeof(LogicalHookOptions{}) != 32 || unsafe.Sizeof(LogicalInvocation{}) != 504 {
		t.Fatalf("layout options=%d invocation=%d", unsafe.Sizeof(LogicalHookOptions{}), unsafe.Sizeof(LogicalInvocation{}))
	}
}
