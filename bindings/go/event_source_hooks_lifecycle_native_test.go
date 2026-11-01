package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventSourceCancelledReadRetainsPendingHookAndHTTP2Sibling(t *testing.T) {
	var calls atomic.Int32
	entered, release := make(chan context.Context, 1), make(chan struct{})
	addresses := make(chan string, 3)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addresses <- r.RemoteAddr
		if r.URL.Path == "/sibling" {
			_, _ = io.WriteString(w, "healthy")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "retry: 0\ndata: event\n\n")
	}))
	peer.EnableHTTP2 = true
	peer.StartTLS()
	defer peer.Close()
	client := hookClient(t, Config{Protocol: "h2", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}})
	source, err := client.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h2",
		HeaderHooks: []HeaderHook{func(ctx context.Context, _ *HeaderHookContext) error {
			if calls.Add(1) == 2 {
				entered <- ctx
				<-release
			}
			return ctx.Err()
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	read := make(chan error, 1)
	go func() { _, err := source.Next(ctx); read <- err }()
	var hookContext context.Context
	select {
	case hookContext = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect hook did not start")
	}
	cancel()
	select {
	case err := <-read:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled read retained its lease")
	}
	if hookContext.Err() != nil {
		t.Fatal("read cancellation cancelled the retained GET callback")
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/sibling"})
	if err != nil {
		t.Fatal(err)
	}
	if body, err := response.Body.ReadAll(32); err != nil || string(body) != "healthy" {
		t.Fatalf("sibling: %q %v", body, err)
	}
	if initial, sibling := <-addresses, <-addresses; initial != sibling {
		t.Fatalf("HTTP/2 sibling did not reuse the source connection: %s != %s", initial, sibling)
	}
	close(release)
	if event, err := source.Next(context.Background()); err != nil || event.Data != "event" {
		t.Fatalf("retained GET: %+v %v", event, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("callback repeated after read cancellation: %d", calls.Load())
	}
	if err := source.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEventSourceGETTimeoutReconnectsAfterActualHookCleanup(t *testing.T) {
	var requests, starts, finishes atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "retry: 0\ndata: event\n\n")
	}))
	defer peer.Close()
	client := hookClient(t, Config{})
	cause := errors.New("cleanup after GET deadline")
	source, err := client.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1",
		Timeouts: Timeouts{Total: LimitTimeout(500 * time.Millisecond)},
		HeaderHooks: []HeaderHook{
			func(ctx context.Context, _ *HeaderHookContext) error {
				if starts.Add(1) == 2 {
					<-ctx.Done()
					return cause
				}
				return nil
			},
			func(context.Context, *HeaderHookContext) error { finishes.Add(1); return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range 2 {
		if event, err := source.Next(ctx); err != nil || event.Data != "event" {
			t.Fatalf("event after timeout: %+v %v", event, err)
		}
	}
	if starts.Load() != 3 || finishes.Load() != 2 || requests.Load() != 2 {
		t.Fatalf("starts=%d finishes=%d sent=%d", starts.Load(), finishes.Load(), requests.Load())
	}
	if err := source.CloseContext(ctx); !errors.Is(err, cause) {
		t.Fatalf("unreported timeout cleanup: %v", err)
	}
}

func TestEventSourceCloseWaitsForActualHookReturnAndRetainsLateFailure(t *testing.T) {
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var calls atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "retry: 0\ndata: first\n\n")
	}))
	defer peer.Close()
	client := hookClient(t, Config{})
	cause := errors.New("late source failure")
	source, err := client.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1",
		HeaderHooks: []HeaderHook{func(ctx context.Context, _ *HeaderHookContext) error {
			if calls.Add(1) == 1 {
				return nil
			}
			close(entered)
			<-ctx.Done()
			close(cancelled)
			<-release
			return cause
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() { _, err := source.Next(context.Background()); read <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("hook did not start")
	}
	closeContext, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := source.CloseContext(closeContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("early close: %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("hook cancellation was not signalled")
	}
	shutdown, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if err := client.Shutdown(shutdown); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown bypassed host custody: %v", err)
	}
	close(release)
	if err := source.CloseContext(context.Background()); !errors.Is(err, cause) {
		t.Fatalf("late callback cause: %v", err)
	}
	select {
	case <-read:
	case <-time.After(5 * time.Second):
		t.Fatal("native read lease retained")
	}
	if err := client.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
