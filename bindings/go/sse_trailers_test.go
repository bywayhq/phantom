package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEventTrailersBecomeCompleteAtValidatedEOF(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Add("Trailer", "X-End")
		_, _ = io.WriteString(w, "data: value\n\n")
		w.Header().Add("X-End", "one")
		w.Header().Add("X-End", "two")
	}))
	defer peer.Close()
	response, err := newClient(t).Events(context.Background(), Request{Method: "GET", URL: peer.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	if state, err := response.Events.Trailers(); err != nil || state.State != TrailersPending {
		t.Fatalf("unread trailers: %+v, %v", state, err)
	}
	if event, err := response.Events.Next(); err != nil || event.Data != "value" {
		t.Fatalf("event: %+v, %v", event, err)
	}
	if state, err := response.Events.Trailers(); err != nil || state.State != TrailersPending {
		t.Fatalf("before EOF: %+v, %v", state, err)
	}
	if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if err := response.Events.Close(); err != nil {
		t.Fatal(err)
	}
	state, err := response.Events.Trailers()
	if err != nil || state.State != TrailersComplete || len(state.Headers) != 2 || !strings.EqualFold(state.Headers[0].Name, "X-End") || string(state.Headers[0].Value) != "one" || string(state.Headers[1].Value) != "two" {
		t.Fatalf("complete trailers: %+v, %v", state, err)
	}
	state.Headers[0].Value[0] = 'x'
	again, err := response.Events.Trailers()
	if err != nil || string(again.Headers[0].Value) != "one" {
		t.Fatalf("trailer snapshot changed: %+v, %v", again, err)
	}
}

func TestEventBodyFailurePreservesTypedCauseAndReleasesStream(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "id: retained\ndata: value\n\n")
	}))
	defer peer.Close()
	response, err := newClient(t).Events(context.Background(), Request{Method: "GET", URL: peer.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	if event, err := response.Events.Next(); err != nil || event.ID != "retained" {
		t.Fatalf("first event: %+v, %v", event, err)
	}
	_, err = response.Events.Next()
	if kind(err) != "sse_body" || kind(errors.Unwrap(err)) != "http1" {
		t.Fatalf("body failure and cause: %v / %v", err, errors.Unwrap(err))
	}
	if response.Events.LastEventID() != "retained" {
		t.Fatalf("error discarded ID: %q", response.Events.LastEventID())
	}
	if state, err := response.Events.Trailers(); err != nil || state.State != TrailersUnavailable {
		t.Fatalf("failed trailers: %+v, %v", state, err)
	}
	if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal failure repeated: %v", err)
	}
}
