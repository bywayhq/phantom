//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"errors"
	"testing"
	"unsafe"
)

func TestWebSocketRouteExtensionRejectsOldPartialAndUnknownLibraries(t *testing.T) {
	missingError := errors.New("missing route extension")
	for _, missing := range []string{"phantom_go_websocket_route_version", "phantom_go_websocket_open_with_route"} {
		called := false
		_, err := bindWebSocketRouteSymbols(func(name string) (uintptr, error) {
			if name == missing {
				return 0, missingError
			}
			return 1, nil
		}, func(uintptr) (uint64, error) { called = true; return 1, nil })
		if failureKind(err) != "native_websocket_route_unavailable" || !errors.Is(err, missingError) || called {
			t.Fatalf("old/partial payload: %v version called=%v", err, called)
		}
	}
	_, err := bindWebSocketRouteSymbols(func(string) (uintptr, error) { return 1, nil }, func(uintptr) (uint64, error) { return 2, nil })
	if failureKind(err) != "native_websocket_route_abi_mismatch" {
		t.Fatalf("unknown route extension: %v", err)
	}
	address, err := bindWebSocketRouteSymbols(func(string) (uintptr, error) { return 7, nil }, func(uintptr) (uint64, error) { return 1, nil })
	if err != nil || address != 7 {
		t.Fatalf("route extension load: %d %v", address, err)
	}
}

func TestWebSocketRouteExtensionPreservesOriginalOpeningLayout(t *testing.T) {
	if unsafe.Sizeof(WebSocketOpening{}) != 136 || unsafe.Sizeof(WebSocketRoute{}) != 56 {
		t.Fatalf("opening=%d route=%d", unsafe.Sizeof(WebSocketOpening{}), unsafe.Sizeof(WebSocketRoute{}))
	}
}
