//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type headerHookBindings struct{ request, copy, reply, cancel uintptr }

var headerHookLibrary struct {
	once sync.Once
	headerHookBindings
	err error
}

func bindHeaderHookSymbols(resolve func(string) (uintptr, error), version func(uintptr) (uint64, error)) (headerHookBindings, error) {
	var result headerHookBindings
	var entry uintptr
	for _, symbol := range []struct {
		name    string
		address *uintptr
	}{
		{"phantom_go_header_hook_version", &entry},
		{"phantom_go_header_hook_request", &result.request},
		{"phantom_go_header_hook_copy", &result.copy},
		{"phantom_go_header_hook_reply", &result.reply},
		{"phantom_go_header_hook_cancel", &result.cancel},
	} {
		address, err := resolve(symbol.name)
		if err != nil || address == 0 {
			return headerHookBindings{}, &Failure{Kind: "native_header_hooks_unavailable", Cause: err}
		}
		*symbol.address = address
	}
	value, err := version(entry)
	if err != nil || value != 1 {
		return headerHookBindings{}, &Failure{Kind: "native_header_hooks_abi_mismatch", Cause: err}
	}
	return result, nil
}

func LoadHeaderHooks() error {
	if err := loadHot(); err != nil {
		return err
	}
	headerHookLibrary.once.Do(func() {
		headerHookLibrary.headerHookBindings, headerHookLibrary.err = bindHeaderHookSymbols(
			func(name string) (uintptr, error) { return nativeSymbol(library.handle, name) },
			func(address uintptr) (uint64, error) {
				value, _, _ := purego.SyscallN(address)
				return uint64(value), nil
			},
		)
	})
	return headerHookLibrary.err
}

func HeaderHookRequest(request *Request, body []byte, count uint64, reply *Reply) error {
	if err := LoadHeaderHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(headerHookLibrary.request, uintptr(unsafe.Pointer(request)), uintptr(unsafe.Pointer(unsafe.SliceData(body))), uintptr(len(body)), uintptr(count), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(request)
	runtime.KeepAlive(body)
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func HeaderHookCopy(operation, ticket uint64, invocation *HeaderInvocation, fields []OutputField, arena []byte) error {
	if err := LoadHeaderHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(headerHookLibrary.copy, uintptr(operation), uintptr(ticket), uintptr(unsafe.Pointer(invocation)), uintptr(unsafe.Pointer(unsafe.SliceData(fields))), uintptr(len(fields)), uintptr(unsafe.Pointer(unsafe.SliceData(arena))), uintptr(len(arena)))
	runtime.KeepAlive(invocation)
	runtime.KeepAlive(fields)
	runtime.KeepAlive(arena)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func HeaderHookReply(operation, ticket, outcome uint64, edits []HeaderEdit, reply *Reply) error {
	if err := LoadHeaderHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(headerHookLibrary.reply, uintptr(operation), uintptr(ticket), uintptr(outcome), uintptr(unsafe.Pointer(unsafe.SliceData(edits))), uintptr(len(edits)), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(edits)
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func HeaderHookCancel(operation uint64, reply *Reply) error {
	if err := LoadHeaderHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(headerHookLibrary.cancel, uintptr(operation), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
