//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package phantom

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

var library struct {
	once                          sync.Once
	dispatch, profile, session    uintptr
	request, operation, waitEvent uintptr
	handle                        uintptr
	hotOnce                       sync.Once
	hotErr                        error
	err                           error
}

func loadNative() error {
	library.once.Do(func() {
		path := os.Getenv("PHANTOM_GO_LIBRARY")
		if path == "" {
			executable, err := os.Executable()
			if err != nil {
				library.err = &Error{Kind: "native_library_unavailable", cause: err}
				return
			}
			path = filepath.Join(filepath.Dir(executable), nativeFilename)
		}
		if !filepath.IsAbs(path) {
			library.err = &Error{Kind: "native_library_path"}
			return
		}
		handle, err := openNative(path)
		if err != nil {
			library.err = &Error{Kind: "native_library_unavailable", cause: err}
			return
		}
		library.handle = handle
		for _, binding := range []struct {
			name   string
			target *uintptr
		}{
			{"phantom_go_dispatch", &library.dispatch},
			{"phantom_go_profile", &library.profile},
			{"phantom_go_session", &library.session},
		} {
			address, err := nativeSymbol(handle, binding.name)
			if err != nil {
				library.err = &Error{Kind: "native_abi", cause: err}
				return
			}
			*binding.target = address
		}
		// The native runtime owns tasks for the process lifetime. Unloading the
		// library could leave those tasks executing unmapped code.
	})
	return library.err
}

func nativeDispatch(command, body, output []byte) (int, error) {
	if err := loadNative(); err != nil {
		return 0, err
	}
	length, _, _ := purego.SyscallN(library.dispatch, uintptr(unsafe.Pointer(unsafe.SliceData(command))), uintptr(len(command)), uintptr(unsafe.Pointer(unsafe.SliceData(body))), uintptr(len(body)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(command)
	runtime.KeepAlive(body)
	runtime.KeepAlive(output)
	return int(length), nil
}

func nativeProfile(command, document, metadata, output []byte) (int, error) {
	if err := loadNative(); err != nil {
		return 0, err
	}
	length, _, _ := purego.SyscallN(library.profile, uintptr(unsafe.Pointer(unsafe.SliceData(command))), uintptr(len(command)), uintptr(unsafe.Pointer(unsafe.SliceData(document))), uintptr(len(document)), uintptr(unsafe.Pointer(unsafe.SliceData(metadata))), uintptr(len(metadata)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(command)
	runtime.KeepAlive(document)
	runtime.KeepAlive(metadata)
	runtime.KeepAlive(output)
	return int(length), nil
}

func nativeSession(command, key, ciphertext, metadata, output []byte) (int, error) {
	if err := loadNative(); err != nil {
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

func loadHot() error {
	if err := loadNative(); err != nil {
		return err
	}
	library.hotOnce.Do(func() {
		for _, binding := range []struct {
			name   string
			target *uintptr
		}{
			{"phantom_go_request", &library.request},
			{"phantom_go_operation", &library.operation},
			{"phantom_go_wait_event", &library.waitEvent},
		} {
			address, err := nativeSymbol(library.handle, binding.name)
			if err != nil {
				library.hotErr = &Error{Kind: "native_abi", cause: err}
				return
			}
			*binding.target = address
		}
	})
	return library.hotErr
}

func nativeSubmit(request *nativeRequest, body []byte, result *nativeReply) error {
	if err := loadHot(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(library.request, uintptr(unsafe.Pointer(request)), uintptr(unsafe.Pointer(unsafe.SliceData(body))), uintptr(len(body)), uintptr(unsafe.Pointer(result)))
	runtime.KeepAlive(request)
	runtime.KeepAlive(body)
	runtime.KeepAlive(result)
	if valid != 1 {
		return &Error{Kind: "native_abi"}
	}
	return nil
}

func nativeOperation(kind, id, argument uint64, data []byte, result *nativeReply) error {
	if err := loadHot(); err != nil {
		return err
	}
	valid, _, _ := purego.SyscallN(library.operation, uintptr(kind), uintptr(id), uintptr(argument), uintptr(unsafe.Pointer(unsafe.SliceData(data))), uintptr(len(data)), uintptr(unsafe.Pointer(result)))
	runtime.KeepAlive(data)
	runtime.KeepAlive(result)
	if valid != 1 {
		return &Error{Kind: "native_abi"}
	}
	return nil
}

func nativeWaitEvent(event *nativeEvent, fields []nativeOutputField, hops []nativeHop, arena, data []byte) error {
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
		return &Error{Kind: "native_abi"}
	}
	return nil
}
