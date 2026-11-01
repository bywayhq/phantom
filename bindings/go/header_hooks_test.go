package phantom

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPureHeaderHooksPreserveOrderedCopiesAndClosedContexts(t *testing.T) {
	h := &HeaderHookContext{method: "GET", url: "https://example.test/?secret=canary", active: true, headers: []Header{
		{Name: "X-First", Value: []byte("one")},
		{Name: "X-Token", Value: []byte("canary")},
		{Name: "x-token", Value: []byte("duplicate")},
		{Name: "X-Last", Value: []byte("last")},
	}}
	if err := h.Set(Header{Name: "X-TOKEN", Value: []byte("replacement"), Sensitive: true}); err != nil {
		t.Fatal(err)
	}
	if err := h.Append(Header{Name: "X-Last", Value: []byte("duplicate")}); err != nil {
		t.Fatal(err)
	}
	headers := h.Headers()
	names := make([]string, len(headers))
	for i, header := range headers {
		names[i] = header.Name
	}
	if !reflect.DeepEqual(names, []string{"X-First", "X-TOKEN", "X-Last", "X-Last"}) || !headers[1].Sensitive {
		t.Fatalf("ordered edit: %v", names)
	}
	headers[0].Value[0] = 'x'
	if string(h.Headers()[0].Value) != "one" {
		t.Fatal("header snapshot aliases hook state")
	}
	if err := h.Remove("x-token"); err != nil {
		t.Fatal(err)
	}
	if h.Method() != "GET" || h.URL() != "https://example.test/?secret=canary" {
		t.Fatal("initial metadata changed")
	}
	if strings.Contains(fmt.Sprintf("%v %#v %#v", h, h, *h), "canary") {
		t.Fatal("hook formatting exposed a secret")
	}
	h.active = false
	if kind(h.Append(Header{Name: "X-Late"})) != "header_hook_closed" {
		t.Fatal("completed hook still mutable")
	}
}

func TestPureHeaderHooksSnapshotListsAndPreserveOriginalErrors(t *testing.T) {
	invoked := []int{}
	first := []HeaderHook{func(context.Context, *HeaderHookContext) error { invoked = append(invoked, 1); return nil }}
	second := []HeaderHook{func(context.Context, *HeaderHookContext) error { invoked = append(invoked, 2); return nil }}
	hooks, err := newHeaderHooks(context.Background(), first, second)
	if err != nil {
		t.Fatal(err)
	}
	defer hooks.cancel()
	first[0], second[0] = nil, nil
	for _, hook := range hooks.hooks {
		if err := hook(hooks.ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(invoked, []int{1, 2}) {
		t.Fatalf("callback order: %v", invoked)
	}
	cause := errors.New("caller failure")
	hooks.failure = cause
	wrapped := hooks.wrap(&Error{Kind: "header_hook"})
	if !errors.Is(wrapped, cause) || kind(wrapped) != "header_hook" {
		t.Fatal("original callback error missing")
	}
	timeout := &Error{Kind: "timeout"}
	if hooks.wrap(timeout) != timeout {
		t.Fatal("callback error replaced the timeout")
	}
	if _, err := newHeaderHooks(context.Background(), []HeaderHook{nil}, nil); kind(err) != "invalid_header_hooks" {
		t.Fatal("nil hook accepted")
	}
}

func TestPureHeaderHooksBoundEditsWithoutChangingState(t *testing.T) {
	h := &HeaderHookContext{active: true}
	if kind(h.Append(Header{Name: "X", Value: make([]byte, 65536)})) != "input_limit" || len(h.edits) != 0 {
		t.Fatal("oversized edit changed the context")
	}
	for range 256 {
		if err := h.Append(Header{Name: "X"}); err != nil {
			t.Fatal(err)
		}
	}
	if kind(h.Remove("X")) != "input_limit" || len(h.headers) != 256 {
		t.Fatal("edit limit changed the context")
	}
}
