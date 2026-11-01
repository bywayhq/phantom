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

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

func TestRedirectCallbacksFollowAfterHeadersAndKeepMethodAndCredentialRules(t *testing.T) {
	order := []string{}
	var finalHits atomic.Int64
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHits.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) != 0 || r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Key") != "" {
			t.Errorf("redirect method/credentials: method=%s body=%q error=%v", r.Method, body, err)
		}
		w.WriteHeader(204)
	}))
	defer final.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "payload" || r.Method != "POST" || r.Header.Get("Authorization") != "secret" || r.Header.Get("X-Key") != "secret" {
			t.Errorf("initial request: method=%s body=%q error=%v", r.Method, body, err)
		}
		w.Header().Set("Location", final.URL+"/end")
		w.WriteHeader(303)
	}))
	defer origin.Close()
	client := hookClient(t, Config{HeaderHooks: []HeaderHook{func(context.Context, *HeaderHookContext) error { order = append(order, "client-header"); return nil }}})
	budget, err := NewAttemptBudget(2)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: origin.URL + "/start", Body: []byte("payload"), Budget: budget, Headers: []Header{{Name: "Authorization", Value: []byte("secret")}, {Name: "X-Key", Value: []byte("secret")}}, HeaderHooks: []HeaderHook{func(context.Context, *HeaderHookContext) error { order = append(order, "request-header"); return nil }}, RedirectPolicy: &RedirectPolicy{MaximumHops: 1, CredentialHeaders: []string{"x-key"}, Callback: func(ctx context.Context, a RedirectAttempt) (RedirectDecision, error) {
		if ctx.Err() != nil || a.FromURL != origin.URL+"/start" || a.ToURL != final.URL+"/end" || a.Status != 303 || a.Method != "POST" || a.NextMethod != "GET" || a.Hop != 1 {
			return 0, errors.New("redirect proposal metadata changed")
		}
		order = append(order, "redirect")
		return RedirectFollow, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.Status != 204 || finalHits.Load() != 1 || !reflect.DeepEqual(order, []string{"client-header", "request-header", "redirect"}) {
		t.Fatalf("response=%d order=%v final=%d", response.Status, order, finalHits.Load())
	}
	remaining, err := budget.Remaining()
	if err != nil || remaining != 0 {
		t.Fatalf("budget=%d error=%v", remaining, err)
	}
}

func TestEventsRedirectCallbacksKeepSingleResponseDecoderAndHeaderOrder(t *testing.T) {
	var headerCalls, redirectCalls atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || r.Method != "POST" || string(body) != "payload" || r.Header.Get("X-Hook") != "ready" {
			t.Errorf("SSE redirected upload: method=%s body=%q error=%v", r.Method, body, err)
		}
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/end")
			w.WriteHeader(307)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: done\n\n")
	}))
	defer peer.Close()
	client := hookClient(t, Config{})
	response, err := client.Events(context.Background(), Request{Method: "POST", URL: peer.URL + "/start", Body: []byte("payload"), HeaderHooks: []HeaderHook{func(_ context.Context, h *HeaderHookContext) error {
		headerCalls.Add(1)
		return h.Append(Header{Name: "X-Hook", Value: []byte("ready")})
	}}, RedirectPolicy: &RedirectPolicy{MaximumHops: 1, Callback: func(context.Context, RedirectAttempt) (RedirectDecision, error) {
		redirectCalls.Add(1)
		return RedirectFollow, nil
	}}}, &SSELimits{MaxLineBytes: 64, MaxEventBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	event, err := response.Events.Next()
	if err != nil || event.Data != "done" {
		t.Fatalf("SSE event: %v %v", event, err)
	}
	if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("single-response SSE did not finish: %v", err)
	}
	if headerCalls.Load() != 1 || redirectCalls.Load() != 1 {
		t.Fatalf("headers=%d redirect=%d", headerCalls.Load(), redirectCalls.Load())
	}
}

func TestRedirectCallbacksKeepHopLimitsAndSharedBudgets(t *testing.T) {
	var hits atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "/again")
		w.WriteHeader(302)
	}))
	defer peer.Close()
	client := hookClient(t, Config{})
	var calls atomic.Int64
	callback := func(context.Context, RedirectAttempt) (RedirectDecision, error) {
		calls.Add(1)
		return RedirectFollow, nil
	}
	_, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL, RedirectPolicy: &RedirectPolicy{MaximumHops: 1, Callback: callback}})
	if kind(err) != "redirect" || calls.Load() != 1 || hits.Load() != 2 {
		t.Fatalf("hop boundary: calls=%d hits=%d error=%v", calls.Load(), hits.Load(), err)
	}
	budget, err := NewAttemptBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	_, err = client.Do(context.Background(), Request{Method: "GET", URL: peer.URL, Budget: budget, RedirectPolicy: &RedirectPolicy{MaximumHops: 3, Callback: callback}})
	if kind(err) != "attempt_budget_exhausted" || calls.Load() != 2 || hits.Load() != 3 {
		t.Fatalf("shared allowance: calls=%d hits=%d error=%v", calls.Load(), hits.Load(), err)
	}
}

func TestRedirectCallbackNativeBoundsRejectBeforeAdmission(t *testing.T) {
	for _, test := range []struct {
		count   uint64
		limits  *native.CallbackSSELimits
		failure string
	}{
		{257, nil, "invalid_header_hooks"},
		{0, &native.CallbackSSELimits{Line: 1024*1024 + 1, Event: 128}, "invalid_sse_limits"},
		{0, &native.CallbackSSELimits{Line: 128, Event: 8*1024*1024 + 1}, "invalid_sse_limits"},
	} {
		var reply native.Reply
		if err := native.RedirectHookRequest(&native.Request{}, nil, test.count, test.limits, &reply); err != nil {
			t.Fatal(err)
		}
		if err := nativeRecordError(reply.Error); kind(err) != test.failure || reply.Operation != 0 {
			t.Fatalf("admitted invalid callback descriptor: operation=%d error=%v", reply.Operation, err)
		}
	}
}

func TestRedirectCallbackStopRejectFailureAndInvalidDecisionDoNotSendAgain(t *testing.T) {
	var sends atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		w.Header().Set("Location", "/never")
		w.WriteHeader(302)
		_, _ = io.WriteString(w, "unread")
	}))
	defer peer.Close()
	client := hookClient(t, Config{})
	cause := &callbackFailure{marker: 42}
	for _, test := range []struct {
		name     string
		decision RedirectDecision
		failure  error
	}{
		{"stop", RedirectStop, nil}, {"reject", RedirectReject, nil}, {"original", 0, cause}, {"invalid", 0, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := sends.Load()
			budget, err := NewAttemptBudget(2)
			if err != nil {
				t.Fatal(err)
			}
			defer budget.Close()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/start", Budget: budget, RedirectPolicy: &RedirectPolicy{MaximumHops: 2, Callback: func(context.Context, RedirectAttempt) (RedirectDecision, error) { return test.decision, test.failure }}})
			if test.decision == RedirectStop {
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := response.Body.ReadAll(6)
				if err != nil || response.Status != 302 || string(body) != "unread" {
					t.Fatalf("unread redirect: %q %v", body, err)
				}
			} else {
				if kind(err) != "redirect" || response != nil {
					t.Fatalf("expected redirect failure: %v", err)
				}
				if test.failure != nil {
					var original *callbackFailure
					if !errors.Is(err, cause) || !errors.As(err, &original) || original != cause {
						t.Fatal("original callback error lost")
					}
				}
			}
			remaining, err := budget.Remaining()
			if err != nil || remaining != 1 || sends.Load() != before+1 {
				t.Fatalf("extra attempt: remaining=%d sends=%d error=%v", remaining, sends.Load()-before, err)
			}
		})
	}
}

func TestRedirectCallbackDefaultsSurviveForkRestoreAndCanBeOverridden(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Location", "/end"); w.WriteHeader(302) }))
	defer peer.Close()
	var calls atomic.Int64
	client := hookClient(t, Config{RedirectPolicy: RedirectPolicy{MaximumHops: 1, Callback: func(context.Context, RedirectAttempt) (RedirectDecision, error) {
		calls.Add(1)
		return RedirectStop, nil
	}}})
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
	for _, owner := range []*Client{client, fork, restored} {
		response, err := owner.Do(context.Background(), Request{Method: "GET", URL: peer.URL})
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		response, err = owner.Do(context.Background(), Request{Method: "GET", URL: peer.URL, RedirectPolicy: &RedirectPolicy{}})
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if _, err := owner.EventSource(context.Background(), peer.URL, EventSourceOptions{Protocol: "h1"}); kind(err) != "event_source_redirect_callback_unsupported" {
			t.Fatalf("EventSource silently dropped callback: %v", err)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("inherited callbacks=%d", calls.Load())
	}
}
