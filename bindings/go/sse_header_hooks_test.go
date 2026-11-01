package phantom

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

func TestEventsHeaderHooksRunOnceAcrossRetriesAndRedirects(t *testing.T) {
	var finalHits atomic.Int64
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHits.Add(1)
		if !reflect.DeepEqual(r.Header.Values("X-Order"), []string{"client", "request"}) || r.Header.Get("X-Secret") != "" {
			t.Errorf("redirect headers: %v", r.Header)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "id: first\ndata: ready\n\n")
	}))
	defer final.Close()
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !reflect.DeepEqual(r.Header.Values("X-Order"), []string{"client", "request"}) || r.Header.Get("X-Secret") != "canary" {
			t.Errorf("origin headers: %v", r.Header)
		}
		if originHits.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Location", final.URL)
		w.WriteHeader(302)
	}))
	defer origin.Close()
	var order []string
	client := hookClient(t, Config{
		HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
			order = append(order, "client")
			if err := h.Append(Header{Name: "X-Order", Value: []byte("client")}); err != nil {
				return err
			}
			return h.Append(Header{Name: "X-Secret", Value: []byte("canary"), Sensitive: true})
		}},
		RedirectPolicy: RedirectPolicy{MaximumHops: 1, CredentialHeaders: []string{"x-secret"}},
		RetryPolicy:    RetryPolicy{Status: &StatusRetry{Statuses: []int{503}, Maximum: 1}},
	})
	budget, err := NewAttemptBudget(3)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	response, err := client.Events(context.Background(), Request{Method: "GET", URL: origin.URL, Budget: budget,
		HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
			order = append(order, "request")
			return h.Append(Header{Name: "X-Order", Value: []byte("request")})
		}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	if event, err := response.Events.Next(); err != nil || event != (SSEEvent{Data: "ready", Type: "message", ID: "first"}) {
		t.Fatalf("decoded event: %+v, %v", event, err)
	}
	if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("event EOF: %v", err)
	}
	remaining, err := budget.Remaining()
	if err != nil || remaining != 0 || originHits.Load() != 2 || finalHits.Load() != 1 || !reflect.DeepEqual(order, []string{"client", "request"}) {
		t.Fatalf("remaining=%d origin=%d final=%d order=%v error=%v", remaining, originHits.Load(), finalHits.Load(), order, err)
	}
}

func TestEventsHeaderHookFailureAndCancellationDoNotSend(t *testing.T) {
	for _, mode := range []string{"error", "cancel", "total"} {
		t.Run(mode, func(t *testing.T) {
			var hits atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(204) }))
			defer server.Close()
			config := Config{}
			if mode == "total" {
				config.Timeout = 200 * time.Millisecond
			}
			client := hookClient(t, config)
			budget, err := NewAttemptBudget(1)
			if err != nil {
				t.Fatal(err)
			}
			defer budget.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := &hookTestError{}
			calls := 0
			_, err = client.Events(ctx, Request{Method: "GET", URL: server.URL, Budget: budget,
				HeaderHooks: []HeaderHook{func(ctx context.Context, _ *HeaderHookContext) error {
					calls++
					if mode == "error" {
						return cause
					}
					if mode == "cancel" {
						cancel()
					}
					<-ctx.Done()
					return ctx.Err()
				}}}, nil)
			switch mode {
			case "error":
				var retained *hookTestError
				if kind(err) != "header_hook" || !errors.Is(err, cause) || !errors.As(err, &retained) || retained != cause {
					t.Fatalf("callback cause: %v", err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
			case "total":
				if kind(err) != "timeout" {
					t.Fatalf("total deadline: %v", err)
				}
			}
			remaining, budgetErr := budget.Remaining()
			if budgetErr != nil || remaining != 1 || hits.Load() != 0 || calls != 1 {
				t.Fatalf("remaining=%d hits=%d error=%v", remaining, hits.Load(), budgetErr)
			}
		})
	}
}

func TestEventsHeaderHooksPreserveDecoderLimits(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || r.Method != "POST" || string(body) != "input" {
			t.Errorf("request body=%q method=%s error=%v", body, r.Method, err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: too long\n\n")
	}))
	defer peer.Close()
	var calls int
	client := hookClient(t, Config{HeaderHooks: []HeaderHook{func(context.Context, *HeaderHookContext) error { calls++; return nil }}})
	response, err := client.Events(context.Background(), Request{Method: "POST", URL: peer.URL, Body: []byte("input")}, &SSELimits{4, 128})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	if _, err := response.Events.Next(); kind(err) != "sse_line_too_long" || calls != 1 {
		t.Fatalf("decoder limit=%v calls=%d", err, calls)
	}
}

func TestEventsHeaderHooksKeepHTTP2SiblingAliveWhenEventStreamIsCancelled(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "ok")
	}))
	var connections atomic.Int64
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer close(release)
	client := hookClient(t, Config{Protocol: "h2", AdditionalRootsDER: [][]byte{server.Certificate().Raw}})
	held, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/held"})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Body.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	response, err := client.Events(ctx, Request{Method: "GET", URL: server.URL + "/events", HeaderHooks: []HeaderHook{
		func(context.Context, *HeaderHookContext) error { calls++; return nil },
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	if event, err := response.Events.Next(); err != nil || event.Data != "first" {
		t.Fatalf("first event: %+v, %v", event, err)
	}
	result := make(chan error, 1)
	go func() { _, err := response.Events.Next(); result <- err }()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("event cancellation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("event read cancellation did not settle")
	}
	release <- struct{}{}
	body, err := held.Body.ReadAll(2)
	if err != nil || string(body) != "ok" || connections.Load() != 1 || calls != 1 {
		t.Fatalf("sibling=%q connections=%d hook calls=%d error=%v", body, connections.Load(), calls, err)
	}
}

func TestEventsHeaderHookShutdownWaitsForActualHostReturn(t *testing.T) {
	client := newClient(t)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var handback sync.Once
	defer handback.Do(func() { close(release) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.Events(ctx, Request{Method: "GET", URL: "http://origin.invalid/", HeaderHooks: []HeaderHook{
			func(ctx context.Context, _ *HeaderHookContext) error {
				close(entered)
				<-ctx.Done()
				close(cancelled)
				<-release
				return ctx.Err()
			},
		}}, nil)
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("SSE hook did not start")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("SSE hook was not cancelled")
	}
	shutdown, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err := client.Shutdown(shutdown)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown released host custody: %v", err)
	}
	handback.Do(func() { close(release) })
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("SSE opening cancellation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SSE host handback did not finish")
	}
	shutdown, stop = context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := client.Shutdown(shutdown); err != nil {
		t.Fatalf("shutdown after host handback: %v", err)
	}
}

func TestEventsHeaderHookNativeBoundsRejectBeforeAdmission(t *testing.T) {
	for _, test := range []struct {
		line, event, hooks uint64
		failure            string
	}{
		{1024*1024 + 1, 128, 1, "invalid_sse_limits"},
		{128, 8*1024*1024 + 1, 1, "invalid_sse_limits"},
		{128, 128, 0, "invalid_header_hooks"},
		{128, 128, 257, "invalid_header_hooks"},
	} {
		var reply native.Reply
		if err := native.SSEHeaderHookRequest(&native.Request{}, nil, test.line, test.event, test.hooks, &reply); err != nil {
			t.Fatal(err)
		}
		if reply.Operation != 0 || kind(nativeRecordError(reply.Error)) != test.failure {
			t.Fatalf("line=%d event=%d hooks=%d operation=%d error=%v", test.line, test.event, test.hooks, reply.Operation, nativeRecordError(reply.Error))
		}
	}
}
