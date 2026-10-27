package phantom

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

func TestNativeBoundaryPreservesPublicCategoriesAndOriginalCauses(t *testing.T) {
	original := &fs.PathError{Op: "open", Path: "private-library-path", Err: fs.ErrNotExist}
	err := nativeBoundaryError(&native.Failure{
		Kind: "native_library_unavailable", Cause: original,
	})
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != "native_library_unavailable" || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("loader failure lost its category or cause: %T", err)
	}
	if errors.Unwrap(failure) != original || strings.Contains(err.Error(), "private-library-path") {
		t.Fatal("loader failure changed its source or exposed its path")
	}

	err = nativeBoundaryError(&native.Failure{
		Kind: "sse_body", Cause: &native.Failure{Kind: "timeout", Protocol: "h2", TimeoutPhase: "read_idle"},
	})
	if !errors.As(err, &failure) || failure.Kind != "sse_body" {
		t.Fatalf("SSE failure category changed: %v", err)
	}
	var cause *Error
	if !errors.As(errors.Unwrap(err), &cause) || !cause.Timeout() || cause.Protocol != "h2" || cause.TimeoutPhase != "read_idle" {
		t.Fatalf("SSE transport cause changed: %v", errors.Unwrap(err))
	}
}
