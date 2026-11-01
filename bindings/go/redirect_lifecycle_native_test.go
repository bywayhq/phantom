package phantom

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRedirectCallbackDeadlineAndCancellationKeepSharedAllowance(t *testing.T) {
	var sends atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sends.Add(1)
		w.Header().Set("Location", "/never")
		w.WriteHeader(302)
	}))
	defer peer.Close()
	client := hookClient(t, Config{})
	for _, cancelCaller := range []bool{false, true} {
		t.Run(map[bool]string{false: "total", true: "caller"}[cancelCaller], func(t *testing.T) {
			warm, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL})
			if err != nil {
				t.Fatal(err)
			}
			if err := warm.Body.Close(); err != nil {
				t.Fatal(err)
			}
			before := sends.Load()
			entered := false
			cause := &callbackFailure{marker: 43}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			budget, err := NewAttemptBudget(2)
			if err != nil {
				t.Fatal(err)
			}
			defer budget.Close()
			request := Request{Method: "GET", URL: peer.URL, Budget: budget, RedirectPolicy: &RedirectPolicy{MaximumHops: 2, Callback: func(ctx context.Context, _ RedirectAttempt) (RedirectDecision, error) {
				entered = true
				if cancelCaller {
					cancel()
				}
				<-ctx.Done()
				return 0, cause
			}}}
			if !cancelCaller {
				request.Timeout = 200 * time.Millisecond
			}
			_, err = client.Do(ctx, request)
			if !entered {
				t.Fatalf("redirect callback was not entered: %v", err)
			}
			if !errors.Is(err, cause) {
				t.Fatal("late redirect error was lost")
			}
			var failure *Error
			if !cancelCaller && (!errors.As(err, &failure) || failure.TimeoutPhase != "total") {
				t.Fatalf("total timeout metadata changed: %v", err)
			}
			if cancelCaller {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("caller cancellation: %v", err)
				}
			} else if kind(err) != "timeout" {
				t.Fatalf("total deadline: %v", err)
			}
			remaining, readErr := budget.Remaining()
			if readErr != nil || remaining != 1 || sends.Load() != before+1 {
				t.Fatalf("another attempt sent: remaining=%d sends=%d error=%v", remaining, sends.Load()-before, readErr)
			}
		})
	}
}

func TestRedirectCallbackShutdownWaitsForActualGoReturn(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Location", "/never"); w.WriteHeader(302) }))
	defer peer.Close()
	client := hookClient(t, Config{})
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var handback sync.Once
	defer handback.Do(func() { close(release) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.Do(ctx, Request{Method: "GET", URL: peer.URL, RedirectPolicy: &RedirectPolicy{MaximumHops: 1, Callback: func(ctx context.Context, _ RedirectAttempt) (RedirectDecision, error) {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			<-release
			return RedirectFollow, nil
		}}})
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("redirect callback did not start")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("redirect callback was not cancelled")
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
			t.Fatalf("send cancellation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("host callback handback did not finish")
	}
	shutdown, stop = context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := client.Shutdown(shutdown); err != nil {
		t.Fatal(err)
	}
}

func TestRedirectCallbackCancellationPreservesAnActiveHTTP2Sibling(t *testing.T) {
	release := make(chan struct{})
	var released sync.Once
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/never")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
		if r.URL.Path == "/held" {
			w.(http.Flusher).Flush()
			<-release
		}
		_, _ = io.WriteString(w, "ok")
	}))
	var connections atomic.Int64
	peer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	peer.EnableHTTP2 = true
	peer.StartTLS()
	defer peer.Close()
	defer released.Do(func() { close(release) })
	client := hookClient(t, Config{Protocol: "h2", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}})
	sibling, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/held"})
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Body.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = client.Do(ctx, Request{Method: "GET", URL: peer.URL + "/start", RedirectPolicy: &RedirectPolicy{MaximumHops: 1, Callback: func(ctx context.Context, _ RedirectAttempt) (RedirectDecision, error) {
		cancel()
		<-ctx.Done()
		return RedirectFollow, nil
	}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("redirect cancellation: %v", err)
	}
	released.Do(func() { close(release) })
	body, err := sibling.Body.ReadAll(2)
	if err != nil || string(body) != "ok" {
		t.Fatalf("unrelated H2 body: %q %v", body, err)
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/after"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.Status != 200 || connections.Load() != 1 {
		t.Fatalf("H2 replaced: status=%d connections=%d", response.Status, connections.Load())
	}
}
