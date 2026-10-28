package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventSourceReconnectUsesCommittedIDAndStopsOn204(t *testing.T) {
	var hits atomic.Int32
	headers := make(chan http.Header, 3)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		switch hits.Add(1) {
		case 1:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "id: abc\nretry: 0\ndata: first\n\n")
		case 2:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "id:\ndata: second\n\n")
		default:
			w.WriteHeader(204)
		}
	}))
	defer peer.Close()
	source, err := newClient(t).EventSource(context.Background(), peer.URL+"/events", EventSourceOptions{Protocol: "h1", Headers: []SSEHeader{SSEField(Header{Name: "Accept", Value: []byte("text/event-stream")}), LastEventID("Last-Event-ID"), SSEField(Header{Name: "X-Order", Value: []byte("last")})}})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if source.Status != 200 || source.Protocol != "h1" || source.EffectiveURL != peer.URL+"/events" {
		t.Fatalf("initial metadata: %+v", source)
	}
	for _, expected := range []SSEEvent{{Data: "first", Type: "message", ID: "abc"}, {Data: "second", Type: "message"}} {
		event, err := source.Next(context.Background())
		if err != nil || event != expected || source.LastEventID() != expected.ID {
			t.Fatalf("event: %+v %v, want %+v", event, err, expected)
		}
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("204: %v", err)
	}
	if !source.Closed() || source.Reconnects() != 2 || source.RetryMilliseconds() != 0 {
		t.Fatalf("state: closed=%v reconnects=%d retry=%d", source.Closed(), source.Reconnects(), source.RetryMilliseconds())
	}
	for i, want := range []string{"", "abc", ""} {
		received := <-headers
		if received.Get("Last-Event-ID") != want || received.Get("X-Order") != "last" {
			t.Fatalf("request %d: %v", i, received)
		}
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("repeated EOF: %v", err)
	}
}

func TestEventSourceInitial204AndTerminalValidation(t *testing.T) {
	for _, test := range []struct {
		name, contentType, body, want string
		status                        int
		limits                        *SSELimits
	}{
		{name: "204", status: 204},
		{name: "type", status: 200, contentType: "text/plain", want: "sse_invalid_content_type"},
		{name: "status", status: 403, contentType: "text/event-stream", want: "sse_unexpected_status"},
		{name: "line", status: 200, contentType: "text/event-stream", body: "data: long\n\n", limits: &SSELimits{4, 128}, want: "sse_line_too_long"},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer peer.Close()
			source, err := newClient(t).EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1", Limits: test.limits})
			if test.name == "type" || test.name == "status" {
				if kind(err) != test.want {
					t.Fatalf("opening: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			_, err = source.Next(context.Background())
			if test.want == "" {
				if !errors.Is(err, io.EOF) || !source.Closed() {
					t.Fatalf("204: %v", err)
				}
			} else if kind(err) != test.want {
				t.Fatalf("terminal: %v", err)
			}
			if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
				t.Fatalf("repeat: %v", err)
			}
		})
	}
}

func TestEventSourceLargeEventAndReconnectLimit(t *testing.T) {
	line := strings.Repeat("x", 60*1024)
	payload := strings.Repeat("data: "+line+"\n", 6) + "\n"
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, payload)
	}))
	defer peer.Close()
	maximum := uint64(0)
	source, err := newClient(t).EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1", MaxReconnects: &maximum})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	event, err := source.Next(context.Background())
	if err != nil || event.Data != strings.Join([]string{line, line, line, line, line, line}, "\n") {
		t.Fatalf("large event: %d, %v", len(event.Data), err)
	}
	if _, err := source.Next(context.Background()); kind(err) != "sse_reconnect_limit" {
		t.Fatalf("reconnect limit: %v", err)
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("repeat: %v", err)
	}
}

func TestEventSourceCancellationRestoresReaderAndKeepsHTTP2Sibling(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	addresses := make(chan string, 2)
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addresses <- r.RemoteAddr
		if r.URL.Path == "/sibling" {
			_, _ = io.WriteString(w, "healthy")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: initial\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "data: resumed\n\n")
		case <-r.Context().Done():
		}
	}))
	peer.EnableHTTP2 = true
	peer.StartTLS()
	defer peer.Close()
	client, err := New(Config{Profile: profile, Protocol: "h2", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	source, err := client.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h2"})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if event, err := source.Next(context.Background()); err != nil || event.Data != "initial" {
		t.Fatalf("initial: %+v %v", event, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := source.Next(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel: %v", err)
	}
	// This immediately following read must acquire the returned native lease.
	again, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if _, err := source.Next(again); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("immediate resume: %v", err)
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/sibling"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if body, err := response.Body.ReadAll(7); err != nil || string(body) != "healthy" {
		t.Fatalf("sibling: %q %v", body, err)
	}
	if first, second := <-addresses, <-addresses; first != second {
		t.Fatalf("pool lost: %s != %s", first, second)
	}
}
func TestEventSourceShutdownWaitsAcrossBackoffAndCanBeRetried(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
	}))
	defer peer.Close()
	client := newClient(t)
	delay := time.Second
	source, err := client.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1", InitialRetry: &delay})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = source.Next(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("backoff cancel: %v", err)
	}
	deadline, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = client.Shutdown(deadline)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown sealed a retained source: %v", err)
	}
	if source.Closed() {
		t.Fatal("shutdown timeout closed source")
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	retry, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := client.Shutdown(retry); err != nil {
		t.Fatalf("shutdown retry: %v", err)
	}
}

func TestEventSourceInitialRequestFailurePreservesTypedCause(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := peer.URL
	peer.Close()
	maximum := uint64(0)
	source, err := newClient(t).EventSource(context.Background(), url, EventSourceOptions{Protocol: "h1", MaxReconnects: &maximum})
	if source != nil {
		_ = source.Close()
		t.Fatal("failed setup returned a source")
	}
	var outer *Error
	if !errors.As(err, &outer) || outer.Kind != "sse_request" {
		t.Fatalf("outer failure: %v", err)
	}
	var cause *Error
	if !errors.As(errors.Unwrap(err), &cause) || cause.Kind == "" || cause.Kind == outer.Kind {
		t.Fatalf("missing typed request cause: %v", errors.Unwrap(err))
	}
}
