package phantom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const profile = "chrome/154.0.8037.97/windows-11-26200/r1"

func newClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(Config{Profile: profile, Protocol: "h1", Timeout: 5 * time.Second})
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
func kind(err error) string {
	var native *Error
	if errors.As(err, &native) {
		return native.Kind
	}
	return ""
}

func TestRequestsCookiesUploadsHeadersAndSharedBudget(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if values := r.Header.Values("X-Duplicate"); len(values) != 0 && strings.Join(values, ",") != "one,two" {
			t.Errorf("duplicate request values: %v", values)
		}
		w.Header().Add("Set-Cookie", "seen=yes; Path=/")
		w.Header().Add("X-Duplicate", "one")
		w.Header().Add("X-Duplicate", "two")
		if r.Method == "PUT" {
			_, _ = io.Copy(w, r.Body)
		} else {
			_, _ = io.WriteString(w, "hello")
		}
	}))
	defer server.Close()
	first, second := newClient(t), newClient(t)
	budget, err := NewAttemptBudget(3)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	for index, client := range []*Client{first, second, first} {
		response, err := client.Do(context.Background(), Request{Method: "PUT", URL: server.URL, Headers: []Header{{"X-Duplicate", []byte("one")}, {"X-Duplicate", []byte("two")}}, Body: []byte("hello"), Budget: budget})
		if err != nil {
			t.Fatal(err)
		}
		if response.Status != 200 || response.Protocol != "h1" {
			t.Fatalf("response head: %+v", response)
		}
		var duplicates []string
		for _, header := range response.Headers {
			if strings.EqualFold(header.Name, "X-Duplicate") {
				duplicates = append(duplicates, string(header.Value))
			}
		}
		if strings.Join(duplicates, ",") != "one,two" {
			t.Fatalf("response duplicates: %v", duplicates)
		}
		data, err := response.Body.ReadAll(5)
		if err != nil || string(data) != "hello" {
			t.Fatalf("body%d: %q %v", index, data, err)
		}
	}
	if _, err := second.Do(context.Background(), Request{Method: "GET", URL: server.URL, Budget: budget}); kind(err) != "attempt_budget_exhausted" {
		t.Fatalf("exhaustion: %v", err)
	}
	if hits.Load() != 3 {
		t.Fatalf("sent %d attempts", hits.Load())
	}
	if remaining, err := budget.Remaining(); err != nil || remaining != 0 {
		t.Fatalf("budget %d: %v", remaining, err)
	}
	if value, err := first.CookiesForURL(server.URL); err != nil || value != "seen=yes" {
		t.Fatalf("cookies %q: %v", value, err)
	}
	if err := first.ClearCookies(); err != nil {
		t.Fatal(err)
	}
	if value, err := first.CookiesForURL(server.URL); err != nil || value != "" {
		t.Fatalf("cleared cookies %q: %v", value, err)
	}
	if err := first.SetCookie(server.URL, "manual=one; Path=/"); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentBudgetNeverOverspends(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	client := newClient(t)
	budget, err := NewAttemptBudget(3)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	var workers sync.WaitGroup
	var completed atomic.Int64
	for range 12 {
		workers.Go(func() {
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL, Budget: budget})
			if err != nil {
				if kind(err) != "attempt_budget_exhausted" {
					t.Error(err)
				}
				return
			}
			data, err := response.Body.ReadAll(2)
			if err != nil || string(data) != "ok" {
				t.Errorf("body %q: %v", data, err)
				return
			}
			completed.Add(1)
		})
	}
	workers.Wait()
	if hits.Load() != 3 || completed.Load() != 3 {
		t.Fatalf("hits=%d completed=%d", hits.Load(), completed.Load())
	}
}

func TestBodyBoundCancellationAndConcurrentClose(t *testing.T) {
	entered := make(chan struct{}, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			_, _ = w.Write(bytes.Repeat([]byte("x"), 100000))
			return
		}
		w.Header().Set("Content-Length", "1000000")
		_, _ = io.WriteString(w, "a")
		w.(http.Flusher).Flush()
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	client := newClient(t)
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/large"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = response.Body.ReadAll(5); kind(err) != "response_body_limit" {
		t.Fatalf("limit: %v", err)
	}
	for _, cancelContext := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		response, err := client.Do(ctx, Request{Method: "GET", URL: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		<-entered
		data := make([]byte, 1)
		if n, err := response.Body.Read(data); n != 1 || err != nil {
			t.Fatalf("first read %d: %v", n, err)
		}
		done := make(chan error, 1)
		go func() { _, err := response.Body.Read(data); done <- err }()
		time.Sleep(10 * time.Millisecond)
		if cancelContext {
			cancel()
		} else {
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("closed read succeeded")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("close did not interrupt read")
		}
		cancel()
		_ = response.Body.Close()
	}
}

func TestCancellationRacingHeadDeliveryDoesNotExhaustBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hello") }))
	defer server.Close()
	client := newClient(t)
	for index := range 100 {
		ctx, cancel := context.WithCancel(context.Background())
		if index%2 == 0 {
			time.AfterFunc(time.Microsecond, cancel)
		}
		response, err := client.Do(ctx, Request{Method: "GET", URL: server.URL})
		cancel()
		if err == nil {
			_ = response.Body.Close()
		} else if !errors.Is(err, context.Canceled) {
			t.Fatalf("request%d: %v", index, err)
		}
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := response.Body.ReadAll(5); err != nil {
		t.Fatal(err)
	}
}

func TestFullAdmissionDoesNotStarveControlOrShutdown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	client := newClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var workers sync.WaitGroup
	for range 64 {
		workers.Go(func() {
			response, err := client.Do(ctx, Request{Method: "GET", URL: server.URL})
			if response != nil {
				_ = response.Body.Close()
			}
			if err != nil && !errors.Is(err, context.Canceled) && kind(err) != "client_closed" {
				t.Error(err)
			}
		})
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		pump.mu.Lock()
		count := len(pump.pending)
		pump.mu.Unlock()
		if count == 64 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d pending requests", count)
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL}); kind(err) != "capacity" {
		t.Fatalf("admission: %v", err)
	}
	if err := client.SetCookie(server.URL, "control=yes; Path=/"); err != nil {
		t.Fatalf("control blocked: %v", err)
	}
	shutdown, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := client.Shutdown(shutdown)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown starved: %v", err)
	}
	cancel()
	workers.Wait()
	// Cancellation releases native reservations asynchronously.
	for deadline := time.Now().Add(3 * time.Second); ; {
		err = client.Close()
		if kind(err) != "shutdown_in_progress" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestAggregateUploadCustodyAndStaleHandles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	client := newClient(t)
	payload := make([]byte, maxUpload)
	var bodies []*Body
	defer func() {
		for _, body := range bodies {
			_ = body.Close()
		}
	}()
	for range 2 {
		response, err := client.Do(context.Background(), Request{Method: "PUT", URL: server.URL, Body: payload})
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, response.Body)
	}
	if _, err := client.Do(context.Background(), Request{Method: "PUT", URL: server.URL, Body: []byte("x")}); kind(err) != "capacity" {
		t.Fatalf("aggregate custody: %v", err)
	}
	_ = bodies[0].Close()
	response, err := client.Do(context.Background(), Request{Method: "PUT", URL: server.URL, Body: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := response.Body.ReadAll(2); err != nil {
		t.Fatal(err)
	}
	budget, err := NewAttemptBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	id := budget.id.Load()
	_ = budget.Close()
	_, err = dispatch(map[string]any{"kind": "budget_remaining", "budget": id}, nil)
	if kind(err) != "invalid_handle" {
		t.Fatalf("stale budget: %v", err)
	}
	_, err = New(Config{Profile: profile, Protocol: "h1", Proxy: "http://user:secret@127.0.0.1:bad"})
	if err == nil || strings.Contains(fmt.Sprint(err), "secret") {
		t.Fatalf("redaction: %v", err)
	}
}

func TestForwardProxyAndMetadataLimits(t *testing.T) {
	var hits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.RequestURI != "http://origin.invalid/resource" || r.Host != "origin.invalid" {
			t.Errorf("proxy target %q %q", r.RequestURI, r.Host)
		}
		_, _ = io.WriteString(w, "proxy")
	}))
	defer proxy.Close()
	client, err := New(Config{Profile: profile, Protocol: "h1", Proxy: proxy.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: "http://origin.invalid/resource"})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := response.Body.ReadAll(5); err != nil || string(data) != "proxy" {
		t.Fatalf("proxy body %q: %v", data, err)
	}
	if hits.Load() != 1 {
		t.Fatal("proxy not used")
	}
	for index := range 80 {
		if err := client.SetCookie("http://origin.invalid/", fmt.Sprintf("c%d=%s; Path=/", index, strings.Repeat("x", 3500))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.CookiesForURL("http://origin.invalid/"); kind(err) != "metadata_limit" {
		t.Fatalf("oversized cookie metadata: %v", err)
	}
	if err := client.ClearCookies(); err != nil {
		t.Fatal(err)
	}
	if value, err := client.CookiesForURL("http://origin.invalid/"); err != nil || value != "" {
		t.Fatalf("post-error control %q: %v", value, err)
	}
}

func TestProxySetupCancellationAndNativeDeadline(t *testing.T) {
	entered := make(chan struct{}, 1)
	disconnected := make(chan struct{}, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			t.Errorf("method=%s", r.Method)
		}
		entered <- struct{}{}
		<-r.Context().Done()
		disconnected <- struct{}{}
	}))
	defer proxy.Close()
	client, err := New(Config{Profile: profile, Protocol: "h1", Proxy: proxy.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.Do(ctx, Request{Method: "GET", URL: "https://origin.invalid/"}); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("CONNECT not observed")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("setup cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("setup cancellation hung")
	}
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("CONNECT peer not released")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "a")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	direct := newClient(t)
	response, err := direct.Do(context.Background(), Request{Method: "GET", URL: server.URL, Timeout: 80 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	_, err = response.Body.ReadAll(100)
	var native *Error
	if !errors.As(err, &native) || native.Kind != "timeout" || native.TimeoutPhase != "total" {
		t.Fatalf("body deadline: %v", err)
	}
}
