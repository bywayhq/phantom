//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type sseBindings struct{ request, next, result uintptr }

var sseLibrary struct {
	once sync.Once
	sseBindings
	err error
}

func bindSSESymbols(resolve func(string) (uintptr, error), version func(uintptr) (uint64, error)) (sseBindings, error) {
	var result sseBindings
	var entry uintptr
	for _, symbol := range []struct {
		name    string
		address *uintptr
	}{
		{"phantom_go_sse_version", &entry},
		{"phantom_go_sse_request", &result.request},
		{"phantom_go_sse_next", &result.next},
		{"phantom_go_sse_result", &result.result},
	} {
		address, err := resolve(symbol.name)
		if err != nil || address == 0 {
			return sseBindings{}, &Failure{Kind: "native_sse_unavailable", Cause: err}
		}
		*symbol.address = address
	}
	value, err := version(entry)
	if err != nil || value != 1 {
		return sseBindings{}, &Failure{Kind: "native_sse_abi_mismatch", Cause: err}
	}
	return result, nil
}

func LoadSSE() error {
	if err := loadHot(); err != nil {
		return err
	}
	sseLibrary.once.Do(func() {
		sseLibrary.sseBindings, sseLibrary.err = bindSSESymbols(func(name string) (uintptr, error) {
			return nativeSymbol(library.handle, name)
		}, func(address uintptr) (uint64, error) {
			value, _, _ := purego.SyscallN(address)
			return uint64(value), nil
		})
	})
	return sseLibrary.err
}

func SSESubmit(request *Request, body []byte, line, event uint64, reply *Reply) error {
	if err := LoadSSE(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(sseLibrary.request, uintptr(unsafe.Pointer(request)), uintptr(unsafe.Pointer(unsafe.SliceData(body))), uintptr(len(body)), uintptr(line), uintptr(event), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(request)
	runtime.KeepAlive(body)
	runtime.KeepAlive(reply)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func SSENext(body uint64, reply *Reply) error {
	if err := LoadSSE(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(sseLibrary.next, uintptr(body), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(reply)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func SSEResult(operation uint64, event *SSEEvent, output []byte) error {
	if err := LoadSSE(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(sseLibrary.result, uintptr(operation), uintptr(unsafe.Pointer(event)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(event)
	runtime.KeepAlive(output)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
