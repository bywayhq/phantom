//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"errors"
	"testing"
)

func TestStateTransferNegotiatesAllSymbolsBeforeAdmission(t *testing.T) {
	want := errors.New("missing symbol")
	for _, missing := range []string{"phantom_go_state_transfer_version", "phantom_go_state_transfer_submit", "phantom_go_state_transfer_result"} {
		_, err := bindStateTransferSymbols(func(name string) (uintptr, error) {
			if name == missing {
				return 0, want
			}
			return 1, nil
		}, func(uintptr) (uint64, error) { return 1, nil })
		var failure *Failure
		if !errors.As(err, &failure) || failure.Kind != "native_state_transfer_unavailable" || !errors.Is(err, want) {
			t.Fatalf("missing symbol: %v", err)
		}
	}
	if _, err := bindStateTransferSymbols(func(string) (uintptr, error) { return 1, nil }, func(uintptr) (uint64, error) { return 2, nil }); err == nil {
		t.Fatal("incompatible ABI admitted")
	}
}
