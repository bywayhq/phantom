package phantom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolOptionsOmissionValidationAndOwnedValues(t *testing.T) {
	if value, err := poolWire(nil); err != nil || value != nil {
		t.Fatalf("omitted pool=%+v: %v", value, err)
	}
	empty, err := poolWire(&PoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := json.Marshal(empty); err != nil || string(data) != "{}" {
		t.Fatalf("empty overrides=%s: %v", data, err)
	}
	maximum, wait := uint64(9), time.Nanosecond
	input := &PoolOptions{MaxHTTP2ConnectionsPerOrigin: &maximum, NegotiatedSetupWaitLimit: &wait}
	wire, err := poolWire(input)
	if err != nil {
		t.Fatal(err)
	}
	maximum, wait = 0, -1
	if *wire.MaxHTTP2ConnectionsPerOrigin != 9 || *wire.NegotiatedSetupWaitLimitNS != 1 {
		t.Fatalf("wire retained caller pointers: %+v", wire)
	}
	zero := time.Duration(0)
	if value, err := poolWire(&PoolOptions{NegotiatedSetupWaitLimit: &zero}); err != nil || value.NegotiatedSetupWaitLimitNS == nil || *value.NegotiatedSetupWaitLimitNS != 0 {
		t.Fatalf("explicit zero wait=%+v: %v", value, err)
	}
	negative := -time.Nanosecond
	if client, err := New(Config{Pool: &PoolOptions{NegotiatedSetupWaitLimit: &negative}}); client != nil || kind(err) != "invalid_pool_options" {
		t.Fatalf("negative duration: client=%v error=%v", client, err)
	}
	zeroCount := uint64(0)
	for _, options := range []*PoolOptions{
		{MaxRetainedHTTP1Connections: &zeroCount}, {MaxRetainedHTTP2Connections: &zeroCount},
		{MaxRetainedHTTP3Connections: &zeroCount}, {MaxConcurrentHTTP1RequestsPerOrigin: &zeroCount},
		{MaxPendingHTTP1RequestsPerOrigin: &zeroCount}, {MaxConcurrentHTTP2RequestsPerOrigin: &zeroCount},
		{MaxPendingHTTP2RequestsPerOrigin: &zeroCount}, {MaxHTTP2ConnectionsPerOrigin: &zeroCount},
		{MaxConcurrentHTTP3RequestsPerOrigin: &zeroCount}, {MaxPendingHTTP3RequestsPerOrigin: &zeroCount},
		{MaxHTTP3ConnectionsPerOrigin: &zeroCount},
	} {
		if client, err := New(Config{Pool: options}); client != nil || kind(err) != "invalid_pool_options" {
			t.Fatalf("zero count: client=%v error=%v", client, err)
		}
	}
	// No invented limit is applied to H2 connections or retention counts.
	largest := uint64(^uint(0))
	if _, err := poolWire(&PoolOptions{MaxHTTP2ConnectionsPerOrigin: &largest}); err != nil {
		t.Fatal(err)
	}
	if largest != math.MaxUint64 {
		tooLarge := largest + 1
		if _, err := poolWire(&PoolOptions{MaxRetainedHTTP1Connections: &tooLarge}); kind(err) != "invalid_pool_options" {
			t.Fatalf("usize overflow: %v", err)
		}
	}
}

func poolClient(t *testing.T, options *PoolOptions) *Client {
	t.Helper()
	client, err := New(Config{Profile: profile, Protocol: "h1", Pool: options, Timeout: 5 * time.Second})
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

func TestPoolRetentionEvictsIdleOriginWithoutDisablingReuse(t *testing.T) {
	var mu sync.Mutex
	var addresses []string
	origin := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			addresses = append(addresses, r.RemoteAddr)
			mu.Unlock()
			_, _ = io.WriteString(w, "ok")
		}))
	}
	first, second := origin(), origin()
	defer first.Close()
	defer second.Close()
	retained := uint64(1)
	client := poolClient(t, &PoolOptions{MaxRetainedHTTP1Connections: &retained})
	for _, url := range []string{first.URL, first.URL, second.URL, first.URL} {
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: url})
		if err != nil {
			t.Fatal(err)
		}
		if body, err := response.Body.ReadAll(2); err != nil || string(body) != "ok" {
			t.Fatalf("body=%q: %v", body, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(addresses) != 4 || addresses[0] != addresses[1] || addresses[0] == addresses[3] {
		t.Fatalf("retention/reuse connection identities: %v", addresses)
	}
}

func TestPoolActiveBoundBackpressuresAndCancelsOnlyWaitingRequest(t *testing.T) {
	var hits atomic.Int64
	var mu sync.Mutex
	sockets := make(map[string]struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mu.Lock()
		sockets[r.RemoteAddr] = struct{}{}
		mu.Unlock()
		if r.URL.Path == "/held" {
			w.Header().Set("Content-Length", "2")
			_, _ = io.WriteString(w, "a")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	active, pending := uint64(2), uint64(1)
	client := poolClient(t, &PoolOptions{MaxConcurrentHTTP1RequestsPerOrigin: &active,
		MaxPendingHTTP1RequestsPerOrigin: &pending})
	var held []*Response
	defer func() {
		for _, response := range held {
			_ = response.Body.Close()
		}
	}()
	for range 2 {
		// Hold ownership independently of the queued request's cancellation
		// deadline, while still bounding setup and response-head acquisition.
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/held",
			Timeouts: Timeouts{Total: Timeout{Mode: TimeoutDisabled}, PoolAdmission: LimitTimeout(5 * time.Second),
				Connect: LimitTimeout(5 * time.Second), ResponseHead: LimitTimeout(5 * time.Second)}})
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, response)
	}
	if _, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/must-not-send",
		Timeouts: Timeouts{PoolAdmission: LimitTimeout(0)}}); kind(err) != "timeout" {
		t.Fatalf("full active bound: %v", err)
	} else {
		var typed *Error
		if !errors.As(err, &typed) || typed.TimeoutPhase != "pool_admission" {
			t.Fatalf("admission phase: %v", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner := newDiagnostics(t, 32)
	done := make(chan error, 1)
	go func() {
		response, err := client.Do(ctx, Request{Method: "GET", URL: server.URL + "/queued", Diagnostics: owner})
		if response != nil {
			_ = response.Body.Close()
		}
		done <- err
	}()
	// Observe the core admission phase rather than infer a queued request from
	// a sleep. Both active bodies remain unfinished throughout cancellation.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	observed := false
	for !observed {
		value, err := owner.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if value != nil {
			for _, event := range value.Events {
				observed = observed || (event.Phase == TimingPoolAdmission && event.Outcome == TimingPending)
			}
		}
		if !observed {
			select {
			case err := <-done:
				t.Fatalf("waiting request settled before cancellation: %v", err)
			case <-ctx.Done():
				t.Fatal("core admission not observed")
			case <-ticker.C:
			}
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("waiting request reached peer: hits=%d", hits.Load())
	}
	mu.Lock()
	if len(sockets) != 2 {
		t.Errorf("active connections=%d", len(sockets))
	}
	mu.Unlock()
	for _, response := range held {
		var first [1]byte
		if _, err := io.ReadFull(response.Body, first[:]); err != nil || first[0] != 'a' {
			t.Fatalf("queued cancellation affected an active body: %q %v", first, err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	healthy, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/healthy"})
	if err != nil {
		t.Fatal(err)
	}
	if body, err := healthy.Body.ReadAll(2); err != nil || string(body) != "ok" || hits.Load() != 3 {
		t.Fatalf("healthy=%q hits=%d: %v", body, hits.Load(), err)
	}
}
