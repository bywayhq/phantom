package native

import (
	"testing"
	"unsafe"
)

func TestStateTransferResultBoundsAndLayout(t *testing.T) {
	for _, value := range []StateResult{
		{Kind: 1, Enabled: 1, CookieCount: 3300, ArenaLength: 3300 * 4096},
		{Kind: 3, Enabled: 1, AlternativeCount: MaxStateAlternatives, ArenaLength: MaxStateText},
		{Kind: 5, Enabled: 1, ArenaLength: MaxStateTickets},
		{Kind: 1},
	} {
		if err := StateResultBounds(value); err != nil {
			t.Fatalf("valid state rejected: %v", err)
		}
	}
	for _, value := range []StateResult{
		{}, {Kind: 7}, {Kind: 1, Enabled: 2}, {Kind: 1, Enabled: 1, CookieCount: MaxStateCookies + 1},
		{Kind: 3, Enabled: 1, AlternativeCount: MaxStateAlternatives + 1}, {Kind: 5, Enabled: 1, ArenaLength: MaxStateTickets + 1},
		{Kind: 2, Enabled: 1, ArenaLength: 1}, {Kind: 3, CookieCount: 1}, {Kind: 1, ArenaLength: 1},
	} {
		if err := StateResultBounds(value); err == nil {
			t.Fatalf("invalid state admitted: %+v", value)
		}
	}
	// C ABI is fixed-width on all supported x64/arm64 targets.
	if unsafe.Sizeof(StateTimestamp{}) != 16 || unsafe.Sizeof(StateCookie{}) != 120 ||
		unsafe.Sizeof(StateAlternative{}) != 56 || unsafe.Sizeof(StateTransfer{}) != 96 || unsafe.Sizeof(StateResult{}) != 240 {
		t.Fatalf("state ABI layout: timestamp=%d cookie=%d alternative=%d transfer=%d result=%d",
			unsafe.Sizeof(StateTimestamp{}), unsafe.Sizeof(StateCookie{}), unsafe.Sizeof(StateAlternative{}), unsafe.Sizeof(StateTransfer{}), unsafe.Sizeof(StateResult{}))
	}
}
