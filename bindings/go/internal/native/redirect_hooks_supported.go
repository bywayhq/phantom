//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type redirectHookBindings struct{ request, copy, reply uintptr }

var redirectHookLibrary struct {
	once sync.Once
	redirectHookBindings
	err error
}

func bindRedirectHookSymbols(resolve func(string) (uintptr, error), version func(uintptr) (uint64, error)) (redirectHookBindings, error) {
	var result redirectHookBindings
	var entry uintptr
	for _, symbol := range []struct {
		name    string
		address *uintptr
	}{
		{"phantom_go_redirect_hook_version", &entry},
		{"phantom_go_redirect_hook_request", &result.request},
		{"phantom_go_redirect_hook_copy", &result.copy},
		{"phantom_go_redirect_hook_reply", &result.reply},
	} {
		address, err := resolve(symbol.name)
		if err != nil || address == 0 {
			return redirectHookBindings{}, &Failure{Kind: "native_redirect_hooks_unavailable", Cause: err}
		}
		*symbol.address = address
	}
	value, err := version(entry)
	if err != nil || value != 1 {
		return redirectHookBindings{}, &Failure{Kind: "native_redirect_hooks_abi_mismatch", Cause: err}
	}
	return result, nil
}

func LoadRedirectHooks() error {
	if err := LoadHeaderHooks(); err != nil {
		return err
	}
	redirectHookLibrary.once.Do(func() {
		redirectHookLibrary.redirectHookBindings, redirectHookLibrary.err = bindRedirectHookSymbols(
			func(name string) (uintptr, error) { return nativeSymbol(library.handle, name) },
			func(address uintptr) (uint64, error) {
				value, _, _ := purego.SyscallN(address)
				return uint64(value), nil
			},
		)
	})
	return redirectHookLibrary.err
}

func RedirectHookRequest(request *Request, body []byte, count uint64, limits *CallbackSSELimits, reply *Reply) error {
	if err := LoadRedirectHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(redirectHookLibrary.request, uintptr(unsafe.Pointer(request)), uintptr(unsafe.Pointer(unsafe.SliceData(body))), uintptr(len(body)), uintptr(count), uintptr(unsafe.Pointer(limits)), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(request)
	runtime.KeepAlive(body)
	runtime.KeepAlive(limits)
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func RedirectHookCopy(operation, ticket uint64, invocation *RedirectInvocation, arena []byte) error {
	if err := LoadRedirectHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(redirectHookLibrary.copy, uintptr(operation), uintptr(ticket), uintptr(unsafe.Pointer(invocation)), uintptr(unsafe.Pointer(unsafe.SliceData(arena))), uintptr(len(arena)))
	runtime.KeepAlive(invocation)
	runtime.KeepAlive(arena)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func RedirectHookReply(operation, ticket, outcome, decision uint64, reply *Reply) error {
	if err := LoadRedirectHooks(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(redirectHookLibrary.reply, uintptr(operation), uintptr(ticket), uintptr(outcome), uintptr(decision), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(reply)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
