package phantom

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPureRequestCallbackLateErrorsRetainPrimaryAndOriginalCause(t *testing.T) {
	cause := errors.New("private-callback-canary")
	prior := errors.New("native-source")
	timeout := &Error{Kind: "timeout", Protocol: "h2", TimeoutPhase: "total", cause: prior}
	for _, failureKind := range []string{"header_hook", "redirect"} {
		t.Run(failureKind, func(t *testing.T) {
			owner := &requestHooks{failure: cause, failureKind: failureKind}
			for _, primary := range []error{context.Canceled, context.DeadlineExceeded, timeout} {
				got := owner.wrap(primary)
				if !errors.Is(got, primary) || !errors.Is(got, cause) {
					t.Fatalf("primary and callback causes were not retained: %v", got)
				}
				var failure *Error
				if !errors.As(got, &failure) || (primary == timeout && (failure.Kind != "timeout" || failure.Protocol != "h2" || failure.TimeoutPhase != "total" || !errors.Is(got, prior))) {
					t.Fatalf("primary metadata changed: %v", got)
				}
				if primary == context.Canceled && failure.Kind != "cancelled" {
					t.Fatalf("cancellation classification changed: %v", got)
				}
				if primary == context.DeadlineExceeded && !failure.Timeout() {
					t.Fatalf("deadline classification changed: %v", got)
				}
				if strings.Contains(got.Error(), "canary") {
					t.Fatal("formatted error exposed callback cause")
				}
			}
			if owner.wrap(nil) != nil {
				t.Fatal("callback failure manufactured a request failure")
			}
			empty := &requestHooks{}
			if empty.wrap(timeout) != timeout || empty.wrap(context.Canceled) != context.Canceled {
				t.Fatal("no-failure path changed error identity")
			}
		})
	}
}
