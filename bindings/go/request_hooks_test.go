package phantom

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

func TestPureLogicalHooksSkipEmptyAndSnapshotOrder(t *testing.T) {
	empty, err := newRequestHooks(context.Background(), nil, nil, nil, RequestHooks{}, RequestHooks{})
	if err != nil || empty != nil {
		t.Fatal("empty bundles allocated a callback owner")
	}
	var order []string
	client := RequestHooks{OnRequest: func(context.Context, RequestHookContext) error { order = append(order, "client"); return nil }}
	request := RequestHooks{OnRequest: func(context.Context, RequestHookContext) error { order = append(order, "request"); return nil }}
	owner, err := newRequestHooks(context.Background(), nil, nil, nil, client, request)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.cancel()
	client.OnRequest = nil
	request.OnRequest = nil
	if err := owner.observeLogical(&logicalCall{phase: 1, request: RequestHookContext{"GET", "http://example.test/"}}); err != nil {
		t.Fatal(err)
	}
	if owner.phases != 1 || !reflect.DeepEqual(order, []string{"client", "request"}) {
		t.Fatalf("order=%v phases=%d", order, owner.phases)
	}
}

func TestPureLogicalHooksPreserveTwoCausesAndMetadata(t *testing.T) {
	first, second := errors.New("first secret"), errors.New("second secret")
	owner, err := newRequestHooks(context.Background(), nil, nil, nil, RequestHooks{OnError: func(_ context.Context, c RequestErrorHookContext) error {
		if !errors.Is(c.Error(), first) || kind(c.Error()) != "request_hook" {
			t.Fatal("error observer lost primary cause")
		}
		return second
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.cancel()
	owner.rememberFailure(first, "request_hook")
	if err := owner.observeLogical(&logicalCall{phase: 4, err: &Error{Kind: "request_hook"}}); err != second {
		t.Fatal("error observer failure changed")
	}
	owner.rememberFailure(second, "request_hook")
	primary := &Error{Kind: "timeout", Protocol: "h2", TimeoutPhase: "total"}
	wrapped := owner.wrap(primary)
	var metadata *Error
	if !errors.Is(wrapped, primary) || !errors.Is(wrapped, first) || !errors.Is(wrapped, second) || !errors.As(wrapped, &metadata) || metadata.Kind != "timeout" || metadata.Protocol != "h2" || metadata.TimeoutPhase != "total" {
		t.Fatal("error metadata or causes changed")
	}
	if strings.Contains(wrapped.Error(), "secret") {
		t.Fatal("formatting exposed callback error")
	}
	plain := &requestHooks{}
	if plain.wrap(primary) != primary {
		t.Fatal("no-failure identity changed")
	}
}

func TestPureLogicalMetadataIsOwnedAndRedacted(t *testing.T) {
	request := RequestHookContext{"GET", "https://example.test/?secret=canary"}
	response := ResponseHookContext{request: request, status: 503, effectiveURL: request.URL(), headers: []Header{{Name: "x-secret", Value: []byte("canary"), Sensitive: true}}, codings: []string{"gzip"}}
	response.Headers()[0].Value[0] = 'X'
	response.DecodedContentCodings()[0] = "br"
	if string(response.Headers()[0].Value) != "canary" || response.DecodedContentCodings()[0] != "gzip" {
		t.Fatal("metadata getter aliases storage")
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v %#v", request, request, response, response), "canary") {
		t.Fatal("formatting leaked metadata")
	}
}

func TestPureLogicalMetadataRejectsInvalidSpansAndFailures(t *testing.T) {
	arena := []byte("GEThttp://example.test/")
	value := native.LogicalInvocation{Phase: 1, Method: native.Slice{Length: 3}, URI: native.Slice{Offset: 3, Length: uint64(len(arena) - 3)}, ArenaLength: uint64(len(arena))}
	got, err := decodeLogicalCall(1, 2, value, nil, arena)
	if err != nil || got.logical.request.Method() != "GET" {
		t.Fatal(err)
	}
	value.URI.Length++
	if _, err := decodeLogicalCall(1, 2, value, nil, arena); kind(err) != "native_abi" {
		t.Fatal("out-of-arena span accepted")
	}
	value.URI.Length--
	value.Phase = 4
	if _, err := decodeLogicalCall(1, 2, value, nil, arena); kind(err) != "native_abi" {
		t.Fatal("error phase accepted success-shaped failure")
	}
	value.Phase = 3
	if _, err := decodeLogicalCall(1, 2, value, nil, arena); kind(err) != "native_abi" {
		t.Fatal("invalid phase accepted")
	}
}

func TestPureSourceLogicalCauseAssociationRejectsStaleGET(t *testing.T) {
	first, second := errors.New("first"), errors.New("second")
	owner := &eventSourceHooks{}
	old := &requestHooks{failure: first}
	owner.rememberInvocation(10, old)
	if owner.causeFor(11) != nil || owner.causeFor(10) != first {
		t.Fatal("stale GET failure was reassigned")
	}
	errorPhase := &requestHooks{failure: first, secondary: second, priorOperation: 10}
	owner.rememberInvocation(12, errorPhase)
	attached := owner.attach(&Error{Kind: "resolve"}, 12)
	if !errors.Is(attached, first) || !errors.Is(attached, second) || kind(attached) != "resolve" {
		t.Fatal("dual source causes lost")
	}
	if owner.cleanup != nil {
		t.Fatal("reported source failure retained for close")
	}
}
