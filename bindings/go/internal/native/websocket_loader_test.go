//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"errors"
	"testing"
)

func TestWebSocketCapabilityRejectsOldPartialAndUnknownPayloads(t *testing.T) {
	for _, missing := range []string{"phantom_go_websocket_version", "phantom_go_websocket_open", "phantom_go_websocket_operation", "phantom_go_websocket_result"} {
		called := false
		_, err := bindWebSocketSymbols(func(name string) (uintptr, error) {
			if name == missing {
				return 0, errors.New("missing symbol")
			}
			return 1, nil
		}, func(uintptr) (uint64, error) { called = true; return 1, nil })
		if failureKind(err) != "native_websocket_unavailable" || called {
			t.Fatalf("partial payload %s: %v, version called=%v", missing, err, called)
		}
	}
	_, err := bindWebSocketSymbols(func(string) (uintptr, error) { return 1, nil }, func(uintptr) (uint64, error) { return 2, nil })
	if failureKind(err) != "native_websocket_abi_mismatch" {
		t.Fatalf("unknown ABI: %v", err)
	}
}

func TestWebSocketResultRejectsMalformedDescriptors(t *testing.T) {
	for _, value := range []WebSocketResult{
		{Kind: 0}, {Kind: 8}, {Kind: 2, Length: MaxWebSocketMessage + 1},
		{Kind: 2, Code: 1000}, {Kind: 4, Length: 126}, {Kind: 6, Code: 0, Length: 1},
		{Kind: 7, Length: 1}, {Kind: 3, Compression: 1}, {Kind: 1, Compression: 2},
		{Kind: 1, Compression: 1, ServerWindow: 7, ClientWindow: 15},
	} {
		if _, err := WebSocketResultLength(value); failureKind(err) != "native_abi" {
			t.Fatalf("malformed result accepted: %+v, %v", value, err)
		}
	}
	if length, err := WebSocketResultLength(WebSocketResult{Kind: 3, Length: 9 * 1024 * 1024}); err != nil || length != 9*1024*1024 {
		t.Fatalf("message above HTTP upload limit: %d, %v", length, err)
	}
}
