//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"os"
	"path/filepath"
	"sync"
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

func Load() error {
	library.once.Do(func() {
		path := os.Getenv("PHANTOM_GO_LIBRARY")
		if path == "" {
			executable, err := os.Executable()
			if err != nil {
				library.err = &Failure{Kind: "native_library_unavailable", Cause: err}
				return
			}
			path = filepath.Join(filepath.Dir(executable), nativeFilename)
		}
		if !filepath.IsAbs(path) {
			library.err = &Failure{Kind: "native_library_path"}
			return
		}
		handle, err := openNative(path)
		if err != nil {
			library.err = &Failure{Kind: "native_library_unavailable", Cause: err}
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
				library.err = &Failure{Kind: "native_abi", Cause: err}
				return
			}
			*binding.target = address
		}
		// The native runtime owns tasks for the process lifetime. Unloading the
		// library could leave those tasks executing unmapped code.
	})
	return library.err
}

func loadHot() error {
	if err := Load(); err != nil {
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
				library.hotErr = &Failure{Kind: "native_abi", Cause: err}
				return
			}
			*binding.target = address
		}
	})
	return library.hotErr
}
