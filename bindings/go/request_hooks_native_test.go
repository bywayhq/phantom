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
)

func TestLogicalHooksOrderOnceAcrossRedirectAndDoNotConsumeBody(t *testing.T) {
	var sends atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/final")
			w.WriteHeader(302)
			return
		}
		if r.Header.Get("X-Hook") != "ready" {
			t.Error("header hook not applied")
		}
		w.Header().Set("X-Response", "retained")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "body")
	}))
	defer peer.Close()
	var order []string
	client := hookClient(t, Config{RedirectPolicy: RedirectPolicy{MaximumHops: 1}, RequestHooks: RequestHooks{
		OnRequest: func(_ context.Context, r RequestHookContext) error {
			order = append(order, "client-request")
			if r.Method() != "GET" || r.URL() != peer.URL+"/start" {
				t.Error("original request changed")
			}
			return nil
		},
		OnResponse: func(_ context.Context, r ResponseHookContext) error {
			order = append(order, "client-response")
			if r.Status() != 503 || r.EffectiveURL() != peer.URL+"/final" || r.RedirectsFollowed() != 1 {
				t.Error("final response metadata changed")
			}
			return nil
		},
		OnError: func(context.Context, RequestErrorHookContext) error {
			t.Error("HTTP status selected error phase")
			return nil
		},
	}, HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
		order = append(order, "header")
		return h.Set(Header{Name: "X-Hook", Value: []byte("ready")})
	}}})
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/start", RequestHooks: RequestHooks{
		OnRequest: func(context.Context, RequestHookContext) error { order = append(order, "request-request"); return nil },
		OnResponse: func(context.Context, ResponseHookContext) error {
			order = append(order, "request-response")
			return nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := response.Body.ReadAll(4)
	if err != nil || string(body) != "body" || sends.Load() != 2 {
		t.Fatalf("body=%q sends=%d err=%v", body, sends.Load(), err)
	}
	if !reflect.DeepEqual(order, []string{"client-request", "request-request", "header", "client-response", "request-response"}) {
		t.Fatalf("order=%v", order)
	}
}

func TestLogicalRequestAndErrorFailuresPreserveBothCausesWithoutSend(t *testing.T) {
	var sends atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { sends.Add(1); w.WriteHeader(204) }))
	defer peer.Close()
	first, second := &callbackFailure{marker: 71}, &callbackFailure{marker: 72}
	var errorsSeen atomic.Int32
	client := hookClient(t, Config{RequestHooks: RequestHooks{
		OnRequest: func(context.Context, RequestHookContext) error { return first },
		OnError: func(_ context.Context, e RequestErrorHookContext) error {
			errorsSeen.Add(1)
			if !errors.Is(e.Error(), first) || kind(e.Error()) != "request_hook" {
				t.Error("error observer lost request cause")
			}
			return second
		},
	}})
	budget, err := NewAttemptBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	_, err = client.Do(context.Background(), Request{Method: "GET", URL: peer.URL, Budget: budget})
	if kind(err) != "request_hook" || !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("causes: %v", err)
	}
	remaining, readErr := budget.Remaining()
	if readErr != nil || remaining != 1 || sends.Load() != 0 || errorsSeen.Load() != 1 {
		t.Fatalf("remaining=%d sends=%d errors=%d err=%v", remaining, sends.Load(), errorsSeen.Load(), readErr)
	}
}

func TestLogicalResponseFailureDoesNotSelectErrorPhaseAndPreservesPool(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "body") }))
	defer peer.Close()
	client := hookClient(t, Config{})
	cause := &callbackFailure{marker: 73}
	_, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL, RequestHooks: RequestHooks{
		OnResponse: func(context.Context, ResponseHookContext) error { return cause },
		OnError: func(context.Context, RequestErrorHookContext) error {
			t.Error("response failure invoked error callback")
			return nil
		},
	}})
	if !errors.Is(err, cause) || kind(err) != "request_hook" {
		t.Fatalf("response failure: %v", err)
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if body, err := response.Body.ReadAll(4); err != nil || string(body) != "body" {
		t.Fatalf("later request: %q %v", body, err)
	}
}

func TestRedirectAndLogicalErrorFailuresPreserveBothCauses(t *testing.T) {
	var sends atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sends.Add(1)
		w.Header().Set("Location", "/next")
		w.WriteHeader(302)
	}))
	defer peer.Close()
	first, second := &callbackFailure{marker: 75}, &callbackFailure{marker: 76}
	client := hookClient(t, Config{})
	budget, err := NewAttemptBudget(2)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	var observed atomic.Int32
	_, err = client.Do(context.Background(), Request{Method: "GET", URL: peer.URL, Budget: budget,
		RedirectPolicy: &RedirectPolicy{MaximumHops: 1, Callback: func(context.Context, RedirectAttempt) (RedirectDecision, error) {
			return 0, first
		}},
		RequestHooks: RequestHooks{OnError: func(_ context.Context, e RequestErrorHookContext) error {
			observed.Add(1)
			if kind(e.Error()) != "redirect" || !errors.Is(e.Error(), first) {
				t.Error("error callback lost redirect failure")
			}
			return second
		}},
	})
	if kind(err) != "redirect" || !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("redirect/error causes=%v", err)
	}
	remaining, readErr := budget.Remaining()
	if readErr != nil || remaining != 1 || sends.Load() != 1 || observed.Load() != 1 {
		t.Fatalf("remaining=%d sends=%d errors=%d err=%v", remaining, sends.Load(), observed.Load(), readErr)
	}
}

func TestLogicalHooksCancellationAndDeadlineKeepCustodyAndAllowance(t *testing.T) {
	for _, total := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller", true: "total"}[total], func(t *testing.T) {
			var sends atomic.Int32
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { sends.Add(1); w.WriteHeader(204) }))
			defer peer.Close()
			client := hookClient(t, Config{})
			budget, err := NewAttemptBudget(1)
			if err != nil {
				t.Fatal(err)
			}
			defer budget.Close()
			entered, cleaning, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := &callbackFailure{marker: 74}
			request := Request{Method: "GET", URL: peer.URL, Budget: budget, RequestHooks: RequestHooks{
				OnRequest: func(ctx context.Context, _ RequestHookContext) error {
					close(entered)
					<-ctx.Done()
					close(cleaning)
					<-release
					return cause
				},
				OnError: func(context.Context, RequestErrorHookContext) error {
					t.Error("cancelled callback selected error phase")
					return nil
				},
			}}
			if total {
				request.Timeout = 200 * time.Millisecond
			}
			result := make(chan error, 1)
			go func() { _, err := client.Do(ctx, request); result <- err }()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("callback not entered")
			}
			if !total {
				cancel()
			}
			select {
			case <-cleaning:
			case <-time.After(10 * time.Second):
				t.Fatal("callback cancellation not delivered")
			}
			shutdown, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
			err = client.Shutdown(shutdown)
			stop()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("shutdown released callback early: %v", err)
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case err = <-result:
			case <-time.After(10 * time.Second):
				t.Fatal("callback did not hand back")
			}
			if !errors.Is(err, cause) {
				t.Fatalf("late error missing: %v", err)
			}
			if total {
				var primary *Error
				if !errors.As(err, &primary) || primary.Kind != "timeout" || primary.TimeoutPhase != "total" {
					t.Fatalf("deadline metadata: %v", err)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatalf("caller cancellation: %v", err)
			}
			remaining, readErr := budget.Remaining()
			if readErr != nil || remaining != 1 || sends.Load() != 0 {
				t.Fatalf("remaining=%d sends=%d err=%v", remaining, sends.Load(), readErr)
			}
			if err := client.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLogicalHooksDefaultsSurviveForkAndRestore(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer peer.Close()
	var calls atomic.Int32
	client := hookClient(t, Config{RequestHooks: RequestHooks{OnRequest: func(context.Context, RequestHookContext) error { calls.Add(1); return nil }}})
	fork, err := client.Fork(SessionSharing{})
	if err != nil {
		t.Fatal(err)
	}
	defer fork.Close()
	key := [32]byte{9}
	snapshot, err := client.ExportSession(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := client.RestoreSession(context.Background(), snapshot, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	for _, owner := range []*Client{fork, restored} {
		response, err := owner.Do(context.Background(), Request{Method: "GET", URL: peer.URL})
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
	}
	if calls.Load() != 2 {
		t.Fatalf("inherited callbacks=%d", calls.Load())
	}
}

func TestLogicalResponseCancellationPreservesHTTP2SiblingTailAndReuse(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/held" {
			_, _ = io.WriteString(w, "a")
			w.(http.Flusher).Flush()
			<-release
			_, _ = io.WriteString(w, "tail")
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	var connections atomic.Int32
	peer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	peer.EnableHTTP2 = true
	peer.StartTLS()
	defer peer.Close()
	client := hookClient(t, Config{Protocol: "h2", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}})
	sibling, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/held"})
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Body.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cause := &callbackFailure{marker: 75}
	_, err = client.Do(ctx, Request{Method: "GET", URL: peer.URL + "/cancel", RequestHooks: RequestHooks{OnResponse: func(ctx context.Context, r ResponseHookContext) error {
		if r.Protocol() != "h2" {
			t.Error("not HTTP2")
		}
		cancel()
		<-ctx.Done()
		return cause
	}}})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) {
		t.Fatalf("response cancellation=%v", err)
	}
	releaseOnce.Do(func() { close(release) })
	if body, err := sibling.Body.ReadAll(5); err != nil || string(body) != "atail" {
		t.Fatalf("sibling tail=%q %v", body, err)
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/after"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if body, err := response.Body.ReadAll(2); err != nil || string(body) != "ok" || connections.Load() != 1 {
		t.Fatalf("reuse=%d body=%q %v", connections.Load(), body, err)
	}
}

func TestLogicalHooksObserveRawSSEWithoutConsumingEvents(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "upload" {
			t.Error("request body changed")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: retained\n\n")
	}))
	defer peer.Close()
	var phases []string
	client := hookClient(t, Config{RequestHooks: RequestHooks{OnRequest: func(context.Context, RequestHookContext) error { phases = append(phases, "request"); return nil }, OnResponse: func(context.Context, ResponseHookContext) error { phases = append(phases, "response"); return nil }}})
	response, err := client.Events(context.Background(), Request{Method: "POST", URL: peer.URL, Body: []byte("upload"), HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
		return h.Set(Header{Name: "X-Ready", Value: []byte("yes")})
	}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	event, err := response.Events.Next()
	if err != nil || event.Data != "retained" {
		t.Fatalf("event=%+v err=%v", event, err)
	}
	if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF=%v", err)
	}
	if !reflect.DeepEqual(phases, []string{"request", "response"}) {
		t.Fatalf("phases=%v", phases)
	}
}
