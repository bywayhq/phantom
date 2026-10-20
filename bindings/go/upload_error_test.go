package phantom

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestObservedReaderErrorSurvivesCancellationWithoutLeakingItsText(t *testing.T) {
	source := errors.New("private source failure")
	for _, control := range []struct {
		err  error
		kind string
	}{
		{context.Canceled, "cancelled"},
		{context.DeadlineExceeded, "timeout"},
	} {
		upload := &uploadLifetime{}
		upload.remember(source)
		err := upload.wrap(control.err)
		if !errors.Is(err, source) || !errors.Is(err, control.err) {
			t.Fatalf("lost error causes: %v", err)
		}
		var failure *Error
		if !errors.As(err, &failure) || failure.Kind != control.kind || failure.Timeout() != (control.kind == "timeout") {
			t.Fatalf("error category: %v", err)
		}
		if failure.TimeoutPhase != "" {
			t.Fatal("caller cancellation invented a native timeout phase")
		}
		if strings.Contains(err.Error(), "private") {
			t.Fatal("reader text escaped redaction")
		}
	}
	untouched := &uploadLifetime{}
	if untouched.wrap(context.Canceled) != context.Canceled {
		t.Fatal("cancellation without a source error changed")
	}
	observed := &uploadLifetime{}
	observed.remember(source)
	native := &Error{Kind: "timeout", Protocol: "h2", TimeoutPhase: "total"}
	err := observed.wrap(native)
	var failure *Error
	if !errors.As(err, &failure) || failure.Protocol != "h2" || failure.TimeoutPhase != "total" || !errors.Is(err, source) {
		t.Fatalf("native metadata or source cause lost: %v", err)
	}
}
