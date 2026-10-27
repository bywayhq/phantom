package phantom

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestNativeIdentityRunsOnceAcrossConcurrentFirstUses(t *testing.T) {
	var check identityCheck
	var calls atomic.Uint64
	call := func(command, body, output []byte) (int, error) {
		calls.Add(1)
		if string(command) != `{"kind":"identity"}` || body != nil {
			t.Error("identity query must not send a request or payload")
		}
		value, _ := json.Marshal(map[string]any{"value": map[string]any{"abi": nativeABIVersion, "version": nativePackageVersion}})
		return copy(output, value), nil
	}
	var group sync.WaitGroup
	for range 64 {
		group.Go(func() {
			if err := check.check(call); err != nil {
				t.Errorf("matching identity rejected: %v", err)
			}
		})
	}
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("identity calls = %d, want 1", calls.Load())
	}
}

func TestNativeIdentityRejectsWrongOrMalformedPairsWithoutLeakingValues(t *testing.T) {
	for _, test := range []struct {
		name, response, kind string
	}{
		{"version", `{"value":{"abi":2,"version":"secret-other-version"}}`, "native_version_mismatch"},
		{"abi", `{"value":{"abi":1,"version":"0.2.0"}}`, "native_abi_mismatch"},
		{"old-library", `{"error":{"kind":"invalid_command"}}`, "native_abi_mismatch"},
		{"missing-value", `{}`, "native_abi"},
		{"bad-json", `secret-bad-json`, "native_abi"},
		{"wrong-version-type", `{"value":{"abi":1,"version":17}}`, "native_abi"},
		{"wrong-abi-type", `{"value":{"abi":"secret","version":"0.2.0"}}`, "native_abi"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var check identityCheck
			calls := 0
			call := func(_, _, output []byte) (int, error) {
				calls++
				return copy(output, test.response), nil
			}
			err := check.check(call)
			var native *Error
			if !errors.As(err, &native) || native.Kind != test.kind || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unexpected identity failure: %#v", err)
			}
			if check.check(call) != err || calls != 1 {
				t.Fatal("incompatible library must stay rejected without another FFI call")
			}
		})
	}
}

func TestNativeIdentityPreservesLoaderAndUnsupportedErrors(t *testing.T) {
	for _, kind := range []string{"unsupported_platform", "native_library_unavailable", "native_library_path", "native_abi"} {
		var check identityCheck
		original := &Error{Kind: kind}
		err := check.check(func(_, _, _ []byte) (int, error) { return 0, original })
		if err != original {
			t.Fatalf("loader failure changed: got %v, want original %v", err, original)
		}
	}
}

func TestNativeIdentityRejectsInvalidReturnedLengths(t *testing.T) {
	for _, length := range []int{-1, 0, maxMetadata + 1} {
		var check identityCheck
		err := check.check(func(_, _, _ []byte) (int, error) { return length, nil })
		var native *Error
		if !errors.As(err, &native) || native.Kind != "native_abi" {
			t.Fatalf("invalid native length %d accepted: %v", length, err)
		}
	}
}
