//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

var websocketRouteLibrary struct {
	once sync.Once
	open uintptr
	err  error
}

func bindWebSocketRouteSymbols(resolve func(string) (uintptr, error), version func(uintptr) (uint64, error)) (uintptr, error) {
	entry, err := resolve("phantom_go_websocket_route_version")
	if err != nil || entry == 0 {
		return 0, &Failure{Kind: "native_websocket_route_unavailable", Cause: err}
	}
	open, err := resolve("phantom_go_websocket_open_with_route")
	if err != nil || open == 0 {
		return 0, &Failure{Kind: "native_websocket_route_unavailable", Cause: err}
	}
	value, err := version(entry)
	if err != nil || value != 1 {
		return 0, &Failure{Kind: "native_websocket_route_abi_mismatch", Cause: err}
	}
	return open, nil
}

func LoadWebSocketRoute() error {
	if err := LoadWebSocket(); err != nil {
		return err
	}
	websocketRouteLibrary.once.Do(func() {
		websocketRouteLibrary.open, websocketRouteLibrary.err = bindWebSocketRouteSymbols(func(name string) (uintptr, error) {
			return nativeSymbol(library.handle, name)
		}, func(address uintptr) (uint64, error) {
			value, _, _ := purego.SyscallN(address)
			return uint64(value), nil
		})
	})
	return websocketRouteLibrary.err
}

func WebSocketOpenWithRoute(opening *WebSocketOpening, route *WebSocketRoute, reply *Reply) error {
	if err := LoadWebSocketRoute(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(websocketRouteLibrary.open, uintptr(unsafe.Pointer(opening)), uintptr(unsafe.Pointer(route)), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(opening)
	runtime.KeepAlive(route)
	runtime.KeepAlive(reply)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
