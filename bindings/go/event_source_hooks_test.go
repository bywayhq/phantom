package phantom

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPureSourceHookFailureRetainsMatchingCauseAndFirstCleanup(t *testing.T) {
	first := errors.New("first secret")
	latest := errors.New("latest secret")
	owner := &eventSourceHooks{}
	owner.remember(10, first)
	owner.remember(11, latest)
	primary := &Error{Kind: "sse_request", TimeoutPhase: "total"}
	if got := owner.attach(primary, 10); got != primary {
		t.Fatal("a stale invocation attached to another failure")
	}
	got := owner.attach(primary, 11)
	if !errors.Is(got, primary) || !errors.Is(got, latest) || errors.Is(got, first) {
		t.Fatalf("matching failure identity: %v", got)
	}
	if strings.Contains(got.Error(), "secret") {
		t.Fatal("callback contents entered the public error")
	}
	if owner.cleanup == nil || owner.cleanup.cause != first {
		t.Fatal("later invocation erased an unreported cleanup failure")
	}
}

func TestPureSourceHookCleanupIsObservedOnceAndCancellationKeepsIt(t *testing.T) {
	cause := errors.New("private callback failure")
	client := &Client{}
	owner := &eventSourceHooks{client: client, done: make(chan struct{})}
	client.sourceHooks = map[*eventSourceHooks]struct{}{owner: {}}
	owner.remember(1, cause)
	close(owner.done)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(owner.wait(ctx), context.Canceled) || owner.cleanup == nil {
		t.Fatal("cancelled close consumed the late failure")
	}
	if err := client.waitSourceHooks(context.Background()); !errors.Is(err, cause) || kind(err) != "header_hook" {
		t.Fatalf("client cleanup: %v", err)
	}
	if len(client.sourceHooks) != 0 || owner.wait(context.Background()) != nil {
		t.Fatal("settled cleanup remained registered or was reported twice")
	}
}

func TestPureSourceHookDeliveredFailureIsNotRepeatedByClose(t *testing.T) {
	cause := errors.New("callback failed")
	owner := &eventSourceHooks{}
	owner.remember(7, cause)
	if err := owner.attach(&Error{Kind: "sse_request"}, 7); !errors.Is(err, cause) {
		t.Fatal("callback cause was lost")
	}
	if owner.cleanup != nil {
		t.Fatal("delivered failure remained a cleanup failure")
	}
}
