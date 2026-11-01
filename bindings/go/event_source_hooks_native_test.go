package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventSourceHooksRefreshEachGETAndProtectManagedID(t *testing.T) {
	var hits atomic.Int32
	observed := make(chan http.Header, 3)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Header.Clone()
		if hits.Add(1) == 3 {
			w.WriteHeader(204)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "id: retained\nretry: 0\ndata: event\n\n")
	}))
	defer peer.Close()
	type hookContextKey struct{}
	openingContext := context.WithValue(context.Background(), hookContextKey{}, "retained")
	var order []int
	client := hookClient(t, Config{HeaderHooks: []HeaderHook{func(ctx context.Context, h *HeaderHookContext) error {
		if ctx.Value(hookContextKey{}) != "retained" {
			return errors.New("opening context values lost")
		}
		order = append(order, 1)
		return h.Append(Header{Name: "X-Order", Value: []byte("client")})
	}}})
	zero := time.Duration(0)
	source, err := client.EventSource(openingContext, peer.URL, EventSourceOptions{Protocol: "h1", InitialRetry: &zero,
		Headers: []SSEHeader{SSEField(Header{Name: "Accept", Value: []byte("text/event-stream")}), LastEventID("Last-Event-ID")},
		HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
			order = append(order, 2)
			return h.Append(Header{Name: "X-Order", Value: []byte("source")})
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for range 2 {
		if event, err := source.Next(context.Background()); err != nil || event.ID != "retained" {
			t.Fatalf("event: %+v %v", event, err)
		}
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal: %v", err)
	}
	if err := source.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []int{1, 2, 1, 2, 1, 2}) {
		t.Fatalf("order: %v", order)
	}
	for index := range 3 {
		h := <-observed
		if !reflect.DeepEqual(h.Values("X-Order"), []string{"client", "source"}) {
			t.Fatalf("request %d: %v", index, h)
		}
		want := ""
		if index > 0 {
			want = "retained"
		}
		if h.Get("Last-Event-ID") != want {
			t.Fatalf("managed ID %d: %v", index, h)
		}
	}
}

func TestEventSourceHookErrorIsTerminalAndSkipClientHooks(t *testing.T) {
	var hits atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "retry: 0\ndata: initial\n\n")
	}))
	defer peer.Close()
	client := hookClient(t, Config{HeaderHooks: []HeaderHook{func(context.Context, *HeaderHookContext) error { return errors.New("must be skipped") }}})
	cause := errors.New("source-specific failure")
	var calls atomic.Int32
	source, err := client.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1", SkipClientHeaderHooks: true,
		HeaderHooks: []HeaderHook{func(context.Context, *HeaderHookContext) error {
			if calls.Add(1) > 1 {
				return cause
			}
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, cause) {
		t.Fatalf("original callback cause: %v", err)
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("repeated error: %v", err)
	}
	if hits.Load() != 1 || calls.Load() != 2 {
		t.Fatalf("sent=%d callbacks=%d", hits.Load(), calls.Load())
	}
	if err := source.CloseContext(context.Background()); err != nil {
		t.Fatalf("already observed failure: %v", err)
	}
}

func TestEventSourceHookCannotMutateManagedLastEventID(t *testing.T) {
	var hits atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	defer peer.Close()
	client := hookClient(t, Config{})
	source, err := client.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1",
		HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
			return h.Set(Header{Name: "Last-Event-ID", Value: []byte("forged")})
		}},
	})
	if source != nil {
		defer source.Close()
	}
	if err == nil || hits.Load() != 0 {
		t.Fatalf("protected ID: err=%v requests=%d", err, hits.Load())
	}
}
