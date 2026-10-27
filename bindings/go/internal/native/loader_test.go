//go:build (windows && amd64) || ((linux || darwin) && (amd64 || arm64))

package native

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeLoaderPreservesCauseWithoutPrintingPath(t *testing.T) {
	const marker = "PHANTOM_TEST_ISOLATED_LOADER"
	if os.Getenv(marker) == "1" {
		err := Load()
		var failure *Failure
		if !errors.As(err, &failure) || failure.Kind != "native_library_unavailable" || errors.Unwrap(failure) == nil {
			t.Fatalf("loader failure lost its underlying cause: %T", err)
		}
		if strings.Contains(err.Error(), os.Getenv("PHANTOM_GO_LIBRARY")) || err.Error() != "phantom: native_library_unavailable" {
			t.Fatal("formatted loader failure exposed its path")
		}
		return
	}
	missing := filepath.Join(t.TempDir(), "do-not-print-loader-path", nativeFilename)
	child := exec.Command(os.Args[0], "-test.run=^TestNativeLoaderPreservesCauseWithoutPrintingPath$")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "PHANTOM_GO_LIBRARY=") && !strings.HasPrefix(value, marker+"=") {
			child.Env = append(child.Env, value)
		}
	}
	child.Env = append(child.Env, "PHANTOM_GO_LIBRARY="+missing, marker+"=1")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("isolated loader check: %v\n%s", err, output)
	}
}
