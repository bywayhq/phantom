//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

func Dispatch(command, body, output []byte) (int, error) {
	if err := Load(); err != nil {
		return 0, err
	}
	length, _, _ := purego.SyscallN(library.dispatch, uintptr(unsafe.Pointer(unsafe.SliceData(command))), uintptr(len(command)), uintptr(unsafe.Pointer(unsafe.SliceData(body))), uintptr(len(body)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(command)
	runtime.KeepAlive(body)
	runtime.KeepAlive(output)
	return int(length), nil
}

func Profile(command, document, metadata, output []byte) (int, error) {
	if err := Load(); err != nil {
		return 0, err
	}
	length, _, _ := purego.SyscallN(library.profile, uintptr(unsafe.Pointer(unsafe.SliceData(command))), uintptr(len(command)), uintptr(unsafe.Pointer(unsafe.SliceData(document))), uintptr(len(document)), uintptr(unsafe.Pointer(unsafe.SliceData(metadata))), uintptr(len(metadata)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(command)
	runtime.KeepAlive(document)
	runtime.KeepAlive(metadata)
	runtime.KeepAlive(output)
	return int(length), nil
}

func Session(command, key, ciphertext, metadata, output []byte) (int, error) {
	if err := Load(); err != nil {
		return 0, err
	}
	length, _, _ := purego.SyscallN(library.session, uintptr(unsafe.Pointer(unsafe.SliceData(command))), uintptr(len(command)), uintptr(unsafe.Pointer(unsafe.SliceData(key))), uintptr(len(key)), uintptr(unsafe.Pointer(unsafe.SliceData(ciphertext))), uintptr(len(ciphertext)), uintptr(unsafe.Pointer(unsafe.SliceData(metadata))), uintptr(len(metadata)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(command)
	runtime.KeepAlive(key)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(metadata)
	runtime.KeepAlive(output)
	return int(length), nil
}

func Submit(request *Request, body []byte, result *Reply) error {
	if err := loadHot(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(library.request, uintptr(unsafe.Pointer(request)), uintptr(unsafe.Pointer(unsafe.SliceData(body))), uintptr(len(body)), uintptr(unsafe.Pointer(result)))
	runtime.KeepAlive(request)
	runtime.KeepAlive(body)
	runtime.KeepAlive(result)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func Operation(kind, id, argument uint64, data []byte, result *Reply) error {
	if err := loadHot(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(library.operation, uintptr(kind), uintptr(id), uintptr(argument), uintptr(unsafe.Pointer(unsafe.SliceData(data))), uintptr(len(data)), uintptr(unsafe.Pointer(result)))
	runtime.KeepAlive(data)
	runtime.KeepAlive(result)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

func WaitEvent(event *Event, fields []OutputField, hops []Hop, arena, data []byte) error {
	if err := loadHot(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(library.waitEvent, uintptr(unsafe.Pointer(event)), uintptr(unsafe.Pointer(unsafe.SliceData(fields))), uintptr(len(fields)), uintptr(unsafe.Pointer(unsafe.SliceData(hops))), uintptr(len(hops)), uintptr(unsafe.Pointer(unsafe.SliceData(arena))), uintptr(len(arena)), uintptr(unsafe.Pointer(unsafe.SliceData(data))), uintptr(len(data)))
	runtime.KeepAlive(event)
	runtime.KeepAlive(fields)
	runtime.KeepAlive(hops)
	runtime.KeepAlive(arena)
	runtime.KeepAlive(data)
	if valid != 1 {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}
