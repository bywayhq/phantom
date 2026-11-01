package phantom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPureRedirectPolicySnapshotsAndOmitsCallbacksFromWire(t *testing.T) {
	input := RedirectPolicy{MaximumHops: 2, CredentialHeaders: []string{"x-secret"}, Callback: func(context.Context, RedirectAttempt) (RedirectDecision, error) { return RedirectStop, nil }}
	wire, err := redirectPolicyWire(input)
	if err != nil {
		t.Fatal(err)
	}
	input.CredentialHeaders[0] = "changed"
	if wire.CredentialHeaders[0] != "x-secret" {
		t.Fatal("credential names alias caller state")
	}
	data, err := json.Marshal(wire)
	if err != nil || strings.Contains(string(data), "Callback") || strings.Contains(string(data), "callback") {
		t.Fatalf("callback entered wire config: %s, %v", data, err)
	}
	if decision, err := wire.Callback(context.Background(), RedirectAttempt{}); err != nil || decision != RedirectStop {
		t.Fatal("callback was not retained")
	}
	if _, err := redirectPolicyWire(RedirectPolicy{Callback: input.Callback}); kind(err) != "invalid_redirect_policy" {
		t.Fatalf("unbounded callback accepted: %v", err)
	}
	if owner, err := newRequestHooks(context.Background(), nil, nil, nil); owner != nil || err != nil {
		t.Fatal("no-callback path gained an owner")
	}
}

func TestPureRedirectCallbackErrorIdentityAndRedaction(t *testing.T) {
	owner, err := newRequestHooks(context.Background(), nil, nil, func(context.Context, RedirectAttempt) (RedirectDecision, error) { return RedirectFollow, nil })
	if err != nil || owner == nil {
		t.Fatalf("redirect-only owner: %v", err)
	}
	defer owner.cancel()
	cause := &callbackFailure{marker: 42}
	owner.failure, owner.failureKind = cause, "redirect"
	wrapped := owner.wrap(&Error{Kind: "redirect"})
	var original *callbackFailure
	if !errors.Is(wrapped, cause) || !errors.As(wrapped, &original) || original != cause {
		t.Fatal("redirect failure lost original cause")
	}
	timeout := &Error{Kind: "timeout"}
	if got := owner.wrap(timeout); !errors.Is(got, timeout) || !errors.Is(got, cause) || kind(got) != "timeout" {
		t.Fatal("callback failure replaced timeout")
	}
	attempt := RedirectAttempt{FromURL: "https://origin/private?canary", ToURL: "https://other/canary", Status: 303, Hop: 1}
	if strings.Contains(fmt.Sprintf("%v %#v", attempt, attempt), "canary") {
		t.Fatal("proposal formatting exposed URLs")
	}
}

type callbackFailure struct{ marker int }

func (*callbackFailure) Error() string { return "caller callback failure" }
