//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type eventSourceHookBindings struct{ open, operation, failure, active uintptr }

var eventSourceHookLibrary struct {
	once sync.Once
	eventSourceHookBindings
	err error
}

func bindEventSourceHookSymbols(resolve func(string) (uintptr, error), version func(uintptr) (uint64, error)) (eventSourceHookBindings, error) {
	var bindings eventSourceHookBindings
	var entry uintptr
	for _, symbol := range []struct {
		name    string
		address *uintptr
	}{
		{"phantom_go_event_source_hooks_version", &entry},
		{"phantom_go_event_source_hooks_open", &bindings.open},
		{"phantom_go_event_source_hooks_operation", &bindings.operation},
		{"phantom_go_event_source_hooks_failure", &bindings.failure},
		{"phantom_go_event_source_hooks_active", &bindings.active},
	} {
		address, err := resolve(symbol.name)
		if err != nil || address == 0 {
			return eventSourceHookBindings{}, &Failure{Kind: "native_event_source_hooks_unavailable", Cause: err}
		}
		*symbol.address = address
	}
	value, err := version(entry)
	if err != nil || value != 1 {
		return eventSourceHookBindings{}, &Failure{Kind: "native_event_source_hooks_abi_mismatch", Cause: err}
	}
	return bindings, nil
}
func LoadEventSourceHooks() error {
	if err := LoadEventSource(); err != nil {
		return err
	}
	if err := LoadHeaderHooks(); err != nil {
		return err
	}
	eventSourceHookLibrary.once.Do(func() {
		eventSourceHookLibrary.eventSourceHookBindings, eventSourceHookLibrary.err = bindEventSourceHookSymbols(
			func(name string) (uintptr, error) { return nativeSymbol(library.handle, name) },
			func(address uintptr) (uint64, error) {
				value, _, _ := purego.SyscallN(address)
				return uint64(value), nil
			},
		)
	})
	return eventSourceHookLibrary.err
}
func EventSourceHooksOpen(value *EventSourceOpening, count uint64, reply *EventSourceHooksReply) error {
	if err := LoadEventSourceHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(eventSourceHookLibrary.open, uintptr(unsafe.Pointer(value)), uintptr(count), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(value)
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
func EventSourceHooksOperation(verb, owner uint64, reply *Reply) error {
	if err := LoadEventSourceHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(eventSourceHookLibrary.operation, uintptr(verb), uintptr(owner), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
func EventSourceHooksFailure(operation uint64, result *uint64, reply *Reply) error {
	if err := LoadEventSourceHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(eventSourceHookLibrary.failure, uintptr(operation), uintptr(unsafe.Pointer(result)), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(result)
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func EventSourceHooksActive(operation, ticket uint64, reply *Reply) error {
	if err := LoadEventSourceHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(eventSourceHookLibrary.active, uintptr(operation), uintptr(ticket), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
