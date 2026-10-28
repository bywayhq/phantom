//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type eventSourceBindings struct{ open, operation, result uintptr }

var eventSourceLibrary struct {
	once sync.Once
	eventSourceBindings
	err error
}

func bindEventSourceSymbols(resolve func(string) (uintptr, error), version func(uintptr) (uint64, error)) (eventSourceBindings, error) {
	var result eventSourceBindings
	var entry uintptr
	for _, symbol := range []struct {
		name    string
		address *uintptr
	}{
		{"phantom_go_event_source_version", &entry}, {"phantom_go_event_source_open", &result.open}, {"phantom_go_event_source_operation", &result.operation}, {"phantom_go_event_source_result", &result.result},
	} {
		address, err := resolve(symbol.name)
		if err != nil || address == 0 {
			return eventSourceBindings{}, &Failure{Kind: "native_event_source_unavailable", Cause: err}
		}
		*symbol.address = address
	}
	value, err := version(entry)
	if err != nil || value != 1 {
		return eventSourceBindings{}, &Failure{Kind: "native_event_source_abi_mismatch", Cause: err}
	}
	return result, nil
}

func LoadEventSource() error {
	if err := loadHot(); err != nil {
		return err
	}
	eventSourceLibrary.once.Do(func() {
		eventSourceLibrary.eventSourceBindings, eventSourceLibrary.err = bindEventSourceSymbols(func(name string) (uintptr, error) { return nativeSymbol(library.handle, name) }, func(address uintptr) (uint64, error) {
			value, _, _ := purego.SyscallN(address)
			return uint64(value), nil
		})
	})
	return eventSourceLibrary.err
}
func EventSourceOpen(value *EventSourceOpening, reply *Reply) error {
	if err := LoadEventSource(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(eventSourceLibrary.open, uintptr(unsafe.Pointer(value)), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(value)
	runtime.KeepAlive(reply)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
func EventSourceOperation(verb, handle uint64, reply *Reply) error {
	if err := LoadEventSource(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(eventSourceLibrary.operation, uintptr(verb), uintptr(handle), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(reply)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
func EventSourceCopy(operation uint64, value *EventSourceResult, output []byte) error {
	if err := LoadEventSource(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(eventSourceLibrary.result, uintptr(operation), uintptr(unsafe.Pointer(value)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(value)
	runtime.KeepAlive(output)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
