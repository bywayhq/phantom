//go:build windows && amd64

package native

import "syscall"

func openNative(path string) (uintptr, error) {
	handle, err := syscall.LoadLibrary(path)
	return uintptr(handle), err
}

func nativeSymbol(handle uintptr, name string) (uintptr, error) {
	return syscall.GetProcAddress(syscall.Handle(handle), name)
}

const nativeFilename = "phantom_go.dll"
