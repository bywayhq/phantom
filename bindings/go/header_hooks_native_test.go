package phantom

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func hookClient(t *testing.T, config Config) *Client {
	t.Helper()
	config.Profile = profile
	if config.Protocol == "" {
		config.Protocol = "h1"
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func TestHeaderHooksRunOnceAcrossRetriesAndCrossOriginRedirects(t *testing.T) {
	order := []int{}
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !reflect.DeepEqual(r.Header.Values("X-Order"), []string{"one", "two"}) || r.Header.Get("Authorization") != "" {
			t.Errorf("redirect headers: %v", r.Header)
		}
		w.WriteHeader(204)
	}))
	defer final.Close()
	var hits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !reflect.DeepEqual(r.Header.Values("X-Order"), []string{"one", "two"}) || r.Header.Get("Authorization") != "secret" {
			t.Errorf("origin headers: %v", r.Header)
		}
		if hits.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Location", final.URL)
		w.WriteHeader(302)
	}))
	defer origin.Close()
	defaults := []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
		order = append(order, 1)
		if h.Method() != "GET" || h.URL() != origin.URL+"/start" {
			return errors.New("initial metadata changed")
		}
		if err := h.Append(Header{Name: "X-Order", Value: []byte("one")}); err != nil {
			return err
		}
		return h.Append(Header{Name: "Authorization", Value: []byte("secret"), Sensitive: true})
	}}
	client := hookClient(t, Config{HeaderHooks: defaults, RedirectPolicy: RedirectPolicy{MaximumHops: 1}, RetryPolicy: RetryPolicy{Status: &StatusRetry{Statuses: []int{503}, Maximum: 1}}})
	defaults[0] = nil
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: origin.URL + "/start", HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
		order = append(order, 2)
		if len(h.Headers()) != 2 {
			return errors.New("client hook changes missing")
		}
		return h.Append(Header{Name: "X-Order", Value: []byte("two")})
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.Status != 204 || hits.Load() != 2 || !reflect.DeepEqual(order, []int{1, 2}) {
		t.Fatalf("head=%d hits=%d order=%v", response.Status, hits.Load(), order)
	}
}

func TestHeaderHookCancellationAndTotalTimeoutDoNotSpendAttempts(t *testing.T) {
	for _, total := range []bool{false, true} {
		name := "context"
		if total {
			name = "total"
		}
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(204) }))
			defer server.Close()
			entered := make(chan struct{})
			config := Config{}
			if total {
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
			result := make(chan error, 1)
			go func() {
				_, err := client.Do(ctx, Request{Method: "GET", URL: server.URL, Budget: budget, HeaderHooks: []HeaderHook{func(ctx context.Context, _ *HeaderHookContext) error {
					close(entered)
					<-ctx.Done()
					return ctx.Err()
				}}})
				result <- err
			}()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("hook did not start")
			}
			if !total {
				cancel()
			}
			select {
			case err := <-result:
				if total {
					if kind(err) != "timeout" {
						t.Fatalf("total timeout: %v", err)
					}
				} else if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("callback cancellation did not settle")
			}
			remaining, err := budget.Remaining()
			if err != nil || remaining != 1 || hits.Load() != 0 {
				t.Fatalf("remaining=%d hits=%d error=%v", remaining, hits.Load(), err)
			}
		})
	}
}

func TestClientHeaderHooksPermitConcurrentRequestsWithoutSendingEarly(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(204)
	}))
	defer server.Close()
	entered, release := make(chan struct{}, 2), make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := hookClient(t, Config{HeaderHooks: []HeaderHook{func(ctx context.Context, h *HeaderHookContext) error {
		entered <- struct{}{}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return h.Append(Header{Name: "X-Ready", Value: []byte("yes")})
		}
	}}})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			response, err := client.Do(ctx, Request{Method: "GET", URL: server.URL})
			if err == nil {
				err = response.Body.Close()
			}
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("a pending callback blocked the second request")
		}
	}
	if hits.Load() != 0 {
		t.Fatal("request sent before its callback returned")
	}
	close(release)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent callbacks did not finish")
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("completed requests: %d", hits.Load())
	}
}

func TestHeaderHookErrorsRetainCausesAndPreparedBodyValidation(t *testing.T) {
	client := newClient(t)
	cause := &hookTestError{}
	_, err := client.Do(context.Background(), Request{Method: "GET", URL: "http://origin.invalid/", HeaderHooks: []HeaderHook{func(context.Context, *HeaderHookContext) error { return cause }}})
	var retained *hookTestError
	if kind(err) != "header_hook" || !errors.Is(err, cause) || !errors.As(err, &retained) || retained != cause {
		t.Fatalf("callback error: %v", err)
	}
	if strings.Contains(err.Error(), "canary") {
		t.Fatal("callback error formatting exposed its cause")
	}
	prepared, err := PrepareForm([]FormField{{Name: "key", Value: "value"}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	_, err = client.Do(context.Background(), Request{Method: "POST", URL: "http://origin.invalid/", PreparedBody: prepared, Headers: []Header{{Name: "Content-Type", Value: []byte(prepared.ContentType())}}, HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
		if !strings.Contains(string(h.Headers()[0].Value), "application/x-www-form-urlencoded") {
			return errors.New("prepared headers unavailable")
		}
		return h.Remove("content-type")
	}}})
	if kind(err) != "invalid_header" {
		t.Fatalf("prepared metadata validation: %v", err)
	}
	_, err = client.Do(context.Background(), Request{Method: "GET", URL: "http://origin.invalid/", HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
		return h.Append(Header{Name: "bad name", Value: []byte("x")})
	}}})
	if kind(err) != "header_hook" {
		t.Fatalf("field validation: %v", err)
	}
}

type hookTestError struct{}

func (*hookTestError) Error() string { return "private-canary" }

func TestHeaderHookShutdownRetainsHostCustodyUntilCallbackReturns(t *testing.T) {
	client := newClient(t)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.Do(ctx, Request{Method: "GET", URL: "http://origin.invalid/", HeaderHooks: []HeaderHook{func(ctx context.Context, _ *HeaderHookContext) error {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			<-release
			return ctx.Err()
		}}})
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("hook did not start")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("hook was not cancelled")
	}
	shutdown, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err := client.Shutdown(shutdown)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown released host custody: %v", err)
	}
	// A cancelled shutdown remains retryable after actual host handback.
	release <- struct{}{}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("send cancellation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("host handback did not finish")
	}
}

func TestHeaderHookCancellationPreservesAnExistingHTTP2Response(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if r.URL.Path == "/held" {
			w.(http.Flusher).Flush()
			<-release
		}
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
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/held"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = client.Do(ctx, Request{Method: "GET", URL: server.URL + "/never", HeaderHooks: []HeaderHook{func(ctx context.Context, _ *HeaderHookContext) error { cancel(); <-ctx.Done(); return ctx.Err() }}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("hook cancellation: %v", err)
	}
	release <- struct{}{}
	body, err := response.Body.ReadAll(2)
	if err != nil || string(body) != "ok" {
		t.Fatalf("unrelated HTTP/2 body: %q, %v", body, err)
	}
	next, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/next"})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Body.Close()
	if next.Status != 200 {
		t.Fatalf("reused HTTP/2 request: %d", next.Status)
	}
	if connections.Load() != 1 {
		t.Fatalf("HTTP/2 connection was replaced: %d", connections.Load())
	}
}
