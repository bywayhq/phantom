//go:build (linux || darwin) && (amd64 || arm64)

package native

import "github.com/ebitengine/purego"

func openNative(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
}

func nativeSymbol(handle uintptr, name string) (uintptr, error) {
	return purego.Dlsym(handle, name)
}
