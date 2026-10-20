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
	once                             sync.Once
	dispatch, wait, profile, session *syscall.LazyProc
	err                              error
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
		library.profile = dll.NewProc("phantom_go_profile")
		library.session = dll.NewProc("phantom_go_session")
		if library.dispatch.Find() != nil || library.wait.Find() != nil || library.profile.Find() != nil || library.session.Find() != nil {
			library.err = &Error{Kind: "native_abi"}
		}
		// Keep the module loaded for the process lifetime: shared Tokio tasks must
		// never execute code from an unloaded DLL.
	})
	return library.err
}

func nativeSession(command, key, ciphertext, metadata, output []byte) (int, error) {
	if err := loadNative(); err != nil {
		return 0, err
	}
	// Borrowed pointers remain live through this synchronous CPU call; native
	// state contains only owned core values and the zeroized copy of the key.
	length, _, _ := library.session.Call(uintptr(unsafe.Pointer(unsafe.SliceData(command))), uintptr(len(command)), uintptr(unsafe.Pointer(unsafe.SliceData(key))), uintptr(len(key)), uintptr(unsafe.Pointer(unsafe.SliceData(ciphertext))), uintptr(len(ciphertext)), uintptr(unsafe.Pointer(unsafe.SliceData(metadata))), uintptr(len(metadata)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(command)
	runtime.KeepAlive(key)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(metadata)
	runtime.KeepAlive(output)
	return int(length), nil
}

func nativeProfile(command, document, metadata, output []byte) (int, error) {
	if err := loadNative(); err != nil {
		return 0, err
	}
	// All four buffers are borrowed only by this synchronous call. Native profile
	// owners retain Rust settings, never these Go addresses.
	length, _, _ := library.profile.Call(uintptr(unsafe.Pointer(unsafe.SliceData(command))), uintptr(len(command)), uintptr(unsafe.Pointer(unsafe.SliceData(document))), uintptr(len(document)), uintptr(unsafe.Pointer(unsafe.SliceData(metadata))), uintptr(len(metadata)), uintptr(unsafe.Pointer(unsafe.SliceData(output))), uintptr(len(output)))
	runtime.KeepAlive(command)
	runtime.KeepAlive(document)
	runtime.KeepAlive(metadata)
	runtime.KeepAlive(output)
	return int(length), nil
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
