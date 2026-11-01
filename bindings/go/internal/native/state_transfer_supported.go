//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type stateTransferBindings struct{ submit, result uintptr }

var stateTransferLibrary struct {
	once sync.Once
	stateTransferBindings
	err error
}

func bindStateTransferSymbols(resolve func(string) (uintptr, error), version func(uintptr) (uint64, error)) (stateTransferBindings, error) {
	var result stateTransferBindings
	var entry uintptr
	for _, symbol := range []struct {
		name    string
		address *uintptr
	}{
		{"phantom_go_state_transfer_version", &entry},
		{"phantom_go_state_transfer_submit", &result.submit},
		{"phantom_go_state_transfer_result", &result.result},
	} {
		address, err := resolve(symbol.name)
		if err != nil || address == 0 {
			return stateTransferBindings{}, &Failure{Kind: "native_state_transfer_unavailable", Cause: err}
		}
		*symbol.address = address
	}
	value, err := version(entry)
	if err != nil || value != 1 {
		return stateTransferBindings{}, &Failure{Kind: "native_state_transfer_abi_mismatch", Cause: err}
	}
	return result, nil
}

func LoadStateTransfer() error {
	if err := loadHot(); err != nil {
		return err
	}
	stateTransferLibrary.once.Do(func() {
		stateTransferLibrary.stateTransferBindings, stateTransferLibrary.err = bindStateTransferSymbols(
			func(name string) (uintptr, error) { return nativeSymbol(library.handle, name) },
			func(address uintptr) (uint64, error) {
				value, _, _ := purego.SyscallN(address)
				return uint64(value), nil
			})
	})
	return stateTransferLibrary.err
}

func SubmitStateTransfer(value *StateTransfer, reply *Reply) error {
	if err := LoadStateTransfer(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(stateTransferLibrary.submit, uintptr(unsafe.Pointer(value)), uintptr(unsafe.Pointer(reply)))
	runtime.KeepAlive(value)
	runtime.KeepAlive(reply)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func StateTransferCopy(operation uint64, value *StateResult, cookies []StateCookie, alternatives []StateAlternative, arena []byte) error {
	if err := LoadStateTransfer(); err != nil {
		return err
	}
	result, _, _ := purego.SyscallN(stateTransferLibrary.result, uintptr(operation), uintptr(unsafe.Pointer(value)),
		uintptr(unsafe.Pointer(unsafe.SliceData(cookies))), uintptr(len(cookies)),
		uintptr(unsafe.Pointer(unsafe.SliceData(alternatives))), uintptr(len(alternatives)),
		uintptr(unsafe.Pointer(unsafe.SliceData(arena))), uintptr(len(arena)))
	runtime.KeepAlive(value)
	runtime.KeepAlive(cookies)
	runtime.KeepAlive(alternatives)
	runtime.KeepAlive(arena)
	if result != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
