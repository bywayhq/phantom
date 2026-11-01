//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type logicalHookBindings struct{ request, copy, reply, source uintptr }

var logicalHookLibrary struct {
	once sync.Once
	logicalHookBindings
	err error
}

func bindLogicalHookSymbols(resolve func(string) (uintptr, error), version func(uintptr) (uint64, error)) (logicalHookBindings, error) {
	var result logicalHookBindings
	var entry uintptr
	for _, symbol := range []struct {
		name    string
		address *uintptr
	}{
		{"phantom_go_logical_hook_version", &entry},
		{"phantom_go_logical_hook_request", &result.request},
		{"phantom_go_logical_hook_copy", &result.copy},
		{"phantom_go_logical_hook_reply", &result.reply},
		{"phantom_go_logical_hook_source_open", &result.source},
	} {
		address, err := resolve(symbol.name)
		if err != nil || address == 0 {
			return logicalHookBindings{}, &Failure{Kind: "native_request_hooks_unavailable", Cause: err}
		}
		*symbol.address = address
	}
	value, err := version(entry)
	if err != nil || value != 1 {
		return logicalHookBindings{}, &Failure{Kind: "native_request_hooks_abi_mismatch", Cause: err}
	}
	return result, nil
}
func LoadLogicalHooks() error {
	if err := LoadHeaderHooks(); err != nil {
		return err
	}
	logicalHookLibrary.once.Do(func() {
		logicalHookLibrary.logicalHookBindings, logicalHookLibrary.err = bindLogicalHookSymbols(func(name string) (uintptr, error) { return nativeSymbol(library.handle, name) }, func(address uintptr) (uint64, error) {
			value, _, _ := purego.SyscallN(address)
			return uint64(value), nil
		})
	})
	return logicalHookLibrary.err
}
func LogicalHookRequest(request *Request, body []byte, options *LogicalHookOptions, reply *Reply) error {
	if err := LoadLogicalHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(logicalHookLibrary.request, uintptr(unsafe.Pointer(request)), uintptr(unsafe.Pointer(unsafe.SliceData(body))), uintptr(len(body)), uintptr(unsafe.Pointer(options)), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(request)
	runtime.KeepAlive(body)
	runtime.KeepAlive(options)
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
func LogicalHookCopy(operation, ticket uint64, invocation *LogicalInvocation, fields []OutputField, arena []byte) error {
	if err := LoadLogicalHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(logicalHookLibrary.copy, uintptr(operation), uintptr(ticket), uintptr(unsafe.Pointer(invocation)), uintptr(unsafe.Pointer(unsafe.SliceData(fields))), uintptr(len(fields)), uintptr(unsafe.Pointer(unsafe.SliceData(arena))), uintptr(len(arena)))
	runtime.KeepAlive(invocation)
	runtime.KeepAlive(fields)
	runtime.KeepAlive(arena)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
func LogicalHookReply(operation, ticket, outcome uint64, reply *Reply) error {
	if err := LoadLogicalHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(logicalHookLibrary.reply, uintptr(operation), uintptr(ticket), uintptr(outcome), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
func LogicalHookSourceOpen(opening *EventSourceOpening, count, phases uint64, reply *EventSourceHooksReply) error {
	if err := LoadLogicalHooks(); err != nil {
		return err
	}
	if err := LoadEventSourceHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(logicalHookLibrary.source, uintptr(unsafe.Pointer(opening)), uintptr(count), uintptr(phases), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(opening)
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
