//go:build windows && amd64

package phantom

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var library struct {
	once           sync.Once
	dispatch, wait *syscall.LazyProc
	err            error
}

func loadNative() error {
	library.once.Do(func() {
		path := os.Getenv("PHANTOM_GO_LIBRARY")
		if path == "" {
			executable, err := os.Executable()
			if err != nil {
				library.err = &Error{Kind: "native_library_unavailable"}
				return
			}
			path = filepath.Join(filepath.Dir(executable), "phantom_go.dll")
		}
		if !filepath.IsAbs(path) {
			library.err = &Error{Kind: "native_library_path"}
			return
		}
		dll := syscall.NewLazyDLL(path)
		if dll.Load() != nil {
			library.err = &Error{Kind: "native_library_unavailable"}
			return
		}
		library.dispatch = dll.NewProc("phantom_go_dispatch")
		library.wait = dll.NewProc("phantom_go_wait")
		if library.dispatch.Find() != nil || library.wait.Find() != nil {
			library.err = &Error{Kind: "native_abi"}
		}
		// Keep the module loaded for the process lifetime: shared Tokio tasks must
		// never execute code from an unloaded DLL.
	})
	return library.err
}
func nativeDispatch(command, body, output []byte) (int, error) {
	if err := loadNative(); err != nil {
		return 0, err
	}
	// Conversion stays inside Call; all slices live through this synchronous copy.
	// Native tasks receive only owned copies, never these addresses.
	length, _, _ := library.dispatch.Call(uintptr(unsafe.Pointer(unsafe.SliceData(command))), uintptr(len(command)), uintptr(unsafe.Pointer(unsafe.SliceData(body))), uintptr(len(body)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(command)
	runtime.KeepAlive(body)
	runtime.KeepAlive(output)
	return int(length), nil
}
func nativeWait(metadata, data []byte) (int, error) {
	if err := loadNative(); err != nil {
		return 0, err
	}
	// Only this pump call blocks. Its output pointers remain on this call stack
	// and are used for bounded copies after the condition variable wakes.
	length, _, _ := library.wait.Call(uintptr(unsafe.Pointer(unsafe.SliceData(metadata))), uintptr(len(metadata)), uintptr(unsafe.Pointer(unsafe.SliceData(data))), uintptr(len(data)))
	runtime.KeepAlive(metadata)
	runtime.KeepAlive(data)
	return int(length), nil
}
