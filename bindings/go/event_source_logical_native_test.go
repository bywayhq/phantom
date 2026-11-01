package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventSourceLogicalHooksRunPerGETWithHeadersAndManagedID(t *testing.T) {
	var sends atomic.Int32
	observed := make(chan http.Header, 3)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Header.Clone()
		if sends.Add(1) == 3 {
			w.WriteHeader(204)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "id: retained\nretry: 0\ndata: event\n\n")
	}))
	defer peer.Close()
	var order []string
	client := hookClient(t, Config{RequestHooks: RequestHooks{
		OnRequest:  func(context.Context, RequestHookContext) error { order = append(order, "client-request"); return nil },
		OnResponse: func(context.Context, ResponseHookContext) error { order = append(order, "client-response"); return nil },
	}, HeaderHooks: []HeaderHook{func(context.Context, *HeaderHookContext) error { return errors.New("must be skipped") }}})
	zero := time.Duration(0)
	source, err := client.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1", InitialRetry: &zero, SkipClientHeaderHooks: true,
		Headers: []SSEHeader{SSEField(Header{Name: "Accept", Value: []byte("text/event-stream")}), LastEventID("Last-Event-ID")},
		HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
			order = append(order, "header")
			return h.Set(Header{Name: "X-Hook", Value: []byte("ready")})
		}},
		RequestHooks: RequestHooks{OnRequest: func(context.Context, RequestHookContext) error { order = append(order, "source-request"); return nil }, OnResponse: func(_ context.Context, r ResponseHookContext) error {
			order = append(order, "source-response")
			if r.Status() != 200 && r.Status() != 204 {
				t.Error("response metadata changed")
			}
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for range 2 {
		event, err := source.Next(context.Background())
		if err != nil || event.ID != "retained" {
			t.Fatalf("event=%+v err=%v", event, err)
		}
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal=%v", err)
	}
	if err := source.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var want []string
	for range 3 {
		want = append(want, "client-request", "source-request", "header", "client-response", "source-response")
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order=%v", order)
	}
	for i := range 3 {
		headers := <-observed
		id := ""
		if i > 0 {
			id = "retained"
		}
		if headers.Get("Last-Event-ID") != id || headers.Get("X-Hook") != "ready" {
			t.Fatalf("request %d: %v", i, headers)
		}
	}
}

func TestEventSourceLogicalErrorPreservesBothCausesAndTerminates(t *testing.T) {
	var sends atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sends.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "retry: 0\ndata: event\n\n")
	}))
	defer peer.Close()
	first, second := &callbackFailure{marker: 81}, &callbackFailure{marker: 82}
	client := hookClient(t, Config{})
	var requests atomic.Int32
	source, err := client.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1", RequestHooks: RequestHooks{
		OnRequest: func(context.Context, RequestHookContext) error {
			if requests.Add(1) == 2 {
				return first
			}
			return nil
		},
		OnError: func(_ context.Context, e RequestErrorHookContext) error {
			if !errors.Is(e.Error(), first) {
				t.Error("source error observer lost original cause")
			}
			return second
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("source causes=%v", err)
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("repeated terminal=%v", err)
	}
	if err := source.CloseContext(context.Background()); err != nil {
		t.Fatalf("observed error repeated at close: %v", err)
	}
	if sends.Load() != 1 || requests.Load() != 2 {
		t.Fatalf("sends=%d requests=%d", sends.Load(), requests.Load())
	}
}

func TestEventSourceCancelledReadRetainsLogicalCallbackUntilSourceClose(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "retry: 0\ndata: event\n\n")
	}))
	defer peer.Close()
	client := hookClient(t, Config{})
	entered, cleaning, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var responses atomic.Int32
	cause := &callbackFailure{marker: 83}
	source, err := client.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1", RequestHooks: RequestHooks{OnResponse: func(ctx context.Context, _ ResponseHookContext) error {
		if responses.Add(1) == 1 {
			return nil
		}
		close(entered)
		<-ctx.Done()
		close(cleaning)
		<-release
		return cause
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	readCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := source.Next(readCtx); result <- err }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("reconnect response hook not entered")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("read cancellation=%v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("read did not hand back")
	}
	select {
	case <-cleaning:
		t.Fatal("cancelled read cancelled retained GET")
	default:
	}
	closeCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = source.CloseContext(closeCtx)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("source close released active callback=%v", err)
	}
	select {
	case <-cleaning:
	case <-time.After(10 * time.Second):
		t.Fatal("source close did not cancel callback")
	}
	releaseOnce.Do(func() { close(release) })
	if err := source.CloseContext(context.Background()); !errors.Is(err, cause) {
		t.Fatalf("unreported callback failure=%v", err)
	}
	if err := source.CloseContext(context.Background()); err != nil {
		t.Fatalf("repeated cleanup error=%v", err)
	}
}

func TestEventSourceLateErrorCallbackReportsOnlyUnobservedCauseAtClose(t *testing.T) {
	var sends atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			w.WriteHeader(204)
			return
		}
		sends.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "retry: 0\ndata: event\n\n")
	}))
	defer peer.Close()
	client := hookClient(t, Config{})
	warm, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/warm"})
	if err != nil {
		t.Fatal(err)
	}
	if err := warm.Body.Close(); err != nil {
		t.Fatal(err)
	}
	first, second := &callbackFailure{marker: 84}, &callbackFailure{marker: 85}
	entered, cleaning, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var requests atomic.Int32
	source, err := client.EventSource(context.Background(), peer.URL+"/events", EventSourceOptions{
		Protocol: "h1", Timeouts: Timeouts{Total: LimitTimeout(200 * time.Millisecond)},
		RequestHooks: RequestHooks{
			OnRequest: func(context.Context, RequestHookContext) error {
				if requests.Add(1) == 2 {
					return first
				}
				return nil
			},
			OnError: func(ctx context.Context, e RequestErrorHookContext) error {
				if !errors.Is(e.Error(), first) {
					t.Error("error callback lost original cause")
				}
				close(entered)
				<-ctx.Done()
				close(cleaning)
				<-release
				return second
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := source.Next(context.Background()); result <- err }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("error callback not entered")
	}
	select {
	case <-cleaning:
	case <-time.After(10 * time.Second):
		t.Fatal("total deadline did not cancel error callback")
	}
	select {
	case err := <-result:
		if !errors.Is(err, first) || errors.Is(err, second) {
			t.Fatalf("terminal result before cleanup=%v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("terminal result waited for error callback cleanup")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = source.CloseContext(closeCtx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close released active error callback=%v", err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := source.CloseContext(context.Background()); !errors.Is(err, second) || errors.Is(err, first) {
		t.Fatalf("late error callback cause=%v", err)
	}
	if err := source.CloseContext(context.Background()); err != nil {
		t.Fatalf("late error repeated=%v", err)
	}
	if sends.Load() != 1 || requests.Load() != 2 {
		t.Fatalf("sends=%d requests=%d", sends.Load(), requests.Load())
	}
}
