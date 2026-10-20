package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStatusRetryWaitsRespectRetryAfterAndTotalDeadline(t *testing.T) {
	for _, test := range []struct {
		name, retryAfter string
		limit            *time.Duration
		delay            time.Duration
		total            time.Duration
		status           int
		hits             int64
	}{
		{"configured wait", "", nil, 40 * time.Millisecond, 5 * time.Second, 200, 2},
		{"malformed falls back", "not-a-date", durationPointer(0), 40 * time.Millisecond, 5 * time.Second, 200, 2},
		{"above cap returns response", "1", durationPointer(0), 0, 5 * time.Second, 503, 1},
		{"zero honored", "0", durationPointer(0), 0, 5 * time.Second, 200, 2},
		{"past date honored", "Sat, 01 Jan 2000 00:00:00 GMT", durationPointer(0), 0, 5 * time.Second, 200, 2},
		{"cannot fit deadline returns response", "", nil, time.Minute, 5 * time.Second, 503, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var hits atomic.Int64
			var mu sync.Mutex
			var first, second time.Time
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				mu.Lock()
				if hits.Add(1) == 1 {
					first = time.Now()
					if test.retryAfter != "" {
						w.Header().Set("Retry-After", test.retryAfter)
					}
					w.WriteHeader(503)
				} else {
					second = time.Now()
				}
				mu.Unlock()
				_, _ = io.WriteString(w, "ok")
			}))
			defer server.Close()
			policy := RetryPolicy{Status: &StatusRetry{Statuses: []int{503}, Maximum: 1, Delay: test.delay, RetryAfterLimit: test.limit}}
			client, err := New(Config{Profile: profile, Protocol: "h1", RetryPolicy: policy, Timeout: test.total})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.Status != test.status || hits.Load() != test.hits {
				t.Fatalf("status=%d hits=%d", response.Status, hits.Load())
			}
			if _, err := response.Body.ReadAll(2); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if test.hits == 2 && second.Sub(first) < test.delay {
				t.Fatal("core retry skipped configured wait")
			}
		})
	}
}

func TestStatusRetryCancellationAndSharedBudgetPreventAnotherSend(t *testing.T) {
	for _, test := range []struct {
		name           string
		cancel, budget bool
	}{
		{"cancel during wait", true, false},
		{"shared budget exhausted", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var hits atomic.Int64
			first := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hit := hits.Add(1)
				w.Header().Set("Set-Cookie", "retry-seen=yes; Path=/")
				w.WriteHeader(503)
				_, _ = io.WriteString(w, "ok")
				w.(http.Flusher).Flush()
				if hit == 1 {
					close(first)
				}
			}))
			defer server.Close()
			delay := time.Duration(0)
			if test.cancel {
				delay = time.Minute
			}
			client, err := New(Config{Profile: profile, Protocol: "h1", RetryPolicy: RetryPolicy{Status: &StatusRetry{Statuses: []int{503}, Maximum: 1, Delay: delay}}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var budget *AttemptBudget
			if test.budget {
				budget, err = NewAttemptBudget(1)
				if err != nil {
					t.Fatal(err)
				}
				defer budget.Close()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				response, err := client.Do(ctx, Request{Method: "GET", URL: server.URL, Budget: budget})
				if response != nil {
					_ = response.Body.Close()
				}
				done <- err
			}()
			select {
			case <-first:
			case <-time.After(5 * time.Second):
				t.Fatal("first attempt did not reach peer")
			}
			if test.cancel {
				// Intermediate response state is applied before the retry wait.
				// Observe it rather than cancelling while setup is still pending.
				deadline := time.Now().Add(5 * time.Second)
				for {
					cookies, err := client.CookiesForURL(server.URL)
					if err != nil {
						t.Fatal(err)
					}
					if cookies == "retry-seen=yes" {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("intermediate response was not processed")
					}
					time.Sleep(time.Millisecond)
				}
				cancel()
			}
			select {
			case err := <-done:
				if test.cancel && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel=%v", err)
				}
				if test.budget && kind(err) != "attempt_budget_exhausted" {
					t.Fatalf("budget=%v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("retry operation did not settle")
			}
			// A released owner must settle native work before another send can occur.
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if hits.Load() != 1 {
				t.Fatalf("retry escaped stop condition: hits=%d", hits.Load())
			}
		})
	}
}

func TestStatusRetryCappedBackoffAndAggregateRetryCap(t *testing.T) {
	for _, test := range []struct {
		name    string
		maximum *uint64
		jitter  bool
		hits    int
	}{
		{"capped doubling", nil, false, 4},
		{"aggregate cap", uint64Pointer(1), false, 2},
		{"full jitter", nil, true, 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			var timestamps []time.Time
			var mu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				mu.Lock()
				timestamps = append(timestamps, time.Now())
				mu.Unlock()
				w.WriteHeader(503)
				_, _ = io.WriteString(w, "ok")
			}))
			defer server.Close()
			client, err := New(Config{
				Profile: profile, Protocol: "h1", Timeout: 5 * time.Second,
				RetryPolicy: RetryPolicy{
					Status:         &StatusRetry{Statuses: []int{503}, Maximum: 3, Delay: 20 * time.Millisecond, MaximumDelay: durationPointer(40 * time.Millisecond), FullJitter: test.jitter},
					MaximumRetries: test.maximum,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.Status != 503 {
				t.Fatalf("status=%d", response.Status)
			}
			if _, err := response.Body.ReadAll(2); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(timestamps) != test.hits {
				t.Fatalf("attempts=%d", len(timestamps))
			}
			if !test.jitter {
				for index := 1; index < len(timestamps); index++ {
					minimum := 40 * time.Millisecond
					if index == 1 {
						minimum = 20 * time.Millisecond
					}
					if timestamps[index].Sub(timestamps[index-1]) < minimum {
						t.Fatalf("retry %d skipped backoff", index)
					}
				}
			}
		})
	}
}
