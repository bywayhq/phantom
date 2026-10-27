//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type websocketBindings struct{ open, operation, result uintptr }

var websocketLibrary struct {
	once sync.Once
	websocketBindings
	err error
}

func bindWebSocketSymbols(resolve func(string) (uintptr, error), version func(uintptr) (uint64, error)) (websocketBindings, error) {
	var result websocketBindings
	var entry uintptr
	for _, symbol := range []struct {
		name    string
		address *uintptr
	}{
		{"phantom_go_websocket_version", &entry},
		{"phantom_go_websocket_open", &result.open},
		{"phantom_go_websocket_operation", &result.operation},
		{"phantom_go_websocket_result", &result.result},
	} {
		address, err := resolve(symbol.name)
		if err != nil || address == 0 {
			return websocketBindings{}, &Failure{Kind: "native_websocket_unavailable", Cause: err}
		}
		*symbol.address = address
	}
	value, err := version(entry)
	if err != nil || value != 1 {
		return websocketBindings{}, &Failure{Kind: "native_websocket_abi_mismatch", Cause: err}
	}
	return result, nil
}

func LoadWebSocket() error {
	if err := loadHot(); err != nil {
		return err
	}
	websocketLibrary.once.Do(func() {
		websocketLibrary.websocketBindings, websocketLibrary.err = bindWebSocketSymbols(func(name string) (uintptr, error) {
			return nativeSymbol(library.handle, name)
		}, func(address uintptr) (uint64, error) {
			value, _, _ := purego.SyscallN(address)
			return uint64(value), nil
		})
	})
	return websocketLibrary.err
}

func WebSocketOpen(opening *WebSocketOpening, reply *Reply) error {
	if err := LoadWebSocket(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(websocketLibrary.open, uintptr(unsafe.Pointer(opening)), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(opening)
	runtime.KeepAlive(reply)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func WebSocketOperation(verb, socket, kind, code uint64, data []byte, reply *Reply) error {
	if err := LoadWebSocket(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(websocketLibrary.operation, uintptr(verb), uintptr(socket), uintptr(kind), uintptr(code), uintptr(unsafe.Pointer(unsafe.SliceData(data))), uintptr(len(data)), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(data)
	runtime.KeepAlive(reply)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func WebSocketCopy(operation uint64, value *WebSocketResult, output []byte) error {
	if err := LoadWebSocket(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(websocketLibrary.result, uintptr(operation), uintptr(unsafe.Pointer(value)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(value)
	runtime.KeepAlive(output)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
