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

func TestRequestContextRejectsBeforeInputValidationOrAdmission(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	client := newClient(t)
	budget, err := NewAttemptBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer stop()
	for _, test := range []struct {
		name string
		ctx  context.Context
		want error
		kind string
	}{
		{name: "nil", kind: "invalid_context"},
		{name: "cancelled", ctx: cancelled, want: context.Canceled},
		{name: "expired", ctx: expired, want: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := client.Do(test.ctx, Request{
				Method: "GET", URL: server.URL, Budget: budget,
				Headers: make([]Header, 257),
			})
			if response != nil {
				_ = response.Body.Close()
				t.Fatal("rejected context returned a response")
			}
			if test.want != nil {
				if !errors.Is(err, test.want) {
					t.Fatalf("context error: %v; want %v", err, test.want)
				}
			} else if kind(err) != test.kind {
				t.Fatalf("context error: %v; want %s", err, test.kind)
			}
		})
	}
	if remaining, err := budget.Remaining(); err != nil || remaining != 1 {
		t.Fatalf("rejected contexts spent budget: %d, %v", remaining, err)
	}
	if hits.Load() != 0 {
		t.Fatalf("rejected contexts sent %d requests", hits.Load())
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL, Budget: budget})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := response.Body.ReadAll(2); err != nil || string(data) != "ok" {
		t.Fatalf("healthy body: %q, %v", data, err)
	}
	if remaining, err := budget.Remaining(); err != nil || remaining != 0 || hits.Load() != 1 {
		t.Fatalf("healthy admission: remaining=%d hits=%d error=%v", remaining, hits.Load(), err)
	}
}

type admissionContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (ctx *admissionContext) Err() error {
	err := ctx.Context.Err()
	// Publish only after taking the pre-lock sample, so the test can cancel
	// without making that first sample itself reject the operation.
	ctx.once.Do(func() { close(ctx.checked) })
	return err
}

func TestCancellationWhileWaitingForAdmissionSkipsDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := &admissionContext{Context: ctx, checked: make(chan struct{})}
	pump.mu.Lock()
	unlock := sync.OnceFunc(pump.mu.Unlock)
	defer unlock()
	done := make(chan error, 1)
	go func() {
		// Dispatch rejects this command during JSON encoding. That distinct
		// input_limit outcome proves the old path reached dispatch after cancel.
		done <- perform(observed, make(chan struct{}), nil, func(completion) error {
			return errors.New("unexpected completion")
		})
	}()
	select {
	case <-observed.checked:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not check its context before admission")
	}
	cancel()
	unlock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled admission reached dispatch: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled admission did not settle")
	}
}
