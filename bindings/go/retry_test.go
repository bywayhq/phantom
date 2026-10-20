package phantom

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

func durationPointer(value time.Duration) *time.Duration { return &value }

func TestRetryStatusSetOwnsOnlyDistinctSupportedCodes(t *testing.T) {
	order := []int{503, 429, 408, 504, 502, 500, 425}
	statuses := make([]int, 65536)
	for index := range statuses {
		statuses[index] = order[index%len(order)]
	}
	wire, err := retryPolicyWire(RetryPolicy{Status: &StatusRetry{Statuses: statuses, Maximum: 1}})
	if err != nil || wire.Status == nil || !reflect.DeepEqual(wire.Status.Statuses, order) {
		t.Fatalf("set snapshot=%v, error=%v", wire.Status, err)
	}
	statuses[0] = 421
	if !reflect.DeepEqual(wire.Status.Statuses, order) {
		t.Fatal("wire set retains caller storage")
	}
	for _, invalid := range [][]int{nil, {}, {421}, {503, 200}} {
		_, err := retryPolicyWire(RetryPolicy{Status: &StatusRetry{Statuses: invalid, Maximum: 1}})
		if kind(err) != "invalid_retry_policy" {
			t.Fatalf("invalid status error=%v", err)
		}
	}
}

func TestRetryWireSnapshotsExactValuesAndRejectsInvalidDurations(t *testing.T) {
	cap := 31 * time.Nanosecond
	after := 61 * time.Nanosecond
	maximum := uint64(math.MaxUint64)
	unprocessed := uint64(4)
	policy := RetryPolicy{
		Connection:             &ConnectionRetry{Maximum: 2, Delay: 7, MaximumDelay: &cap, FullJitter: true},
		Status:                 &StatusRetry{Statuses: []int{429, 503}, Maximum: 3, Delay: 11, MaximumDelay: &cap, FullJitter: true, RetryAfterLimit: &after},
		ReusedConnectionReplay: true, UnprocessedReplays: &unprocessed, MaximumRetries: &maximum, HTTP2Fallback: true,
	}
	wire, err := retryPolicyWire(policy)
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(before, []byte(`"maximum_retries":18446744073709551615`)) || wire.Connection.DelayNS != 7 || wire.Status.DelayNS != 11 {
		t.Fatal("counts or nanoseconds changed")
	}
	cap, after, maximum, unprocessed = 0, 0, 0, 0
	policy.Connection.Maximum = 0
	policy.Status.Statuses[0] = 421
	policy.Status.Delay = -1
	actual, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(actual, before) {
		t.Fatal("wire retains mutable caller policy")
	}
	zero, err := retryPolicyWire(RetryPolicy{MaximumRetries: uint64Pointer(0)})
	if err != nil || zero.MaximumRetries == nil || *zero.MaximumRetries != 0 {
		t.Fatal("zero aggregate cap lost")
	}
	for _, invalid := range []RetryPolicy{
		{Connection: &ConnectionRetry{}},
		{Connection: &ConnectionRetry{Maximum: 1, Delay: -1}},
		{Connection: &ConnectionRetry{Maximum: 1, MaximumDelay: durationPointer(-1)}},
		{Connection: &ConnectionRetry{Maximum: 1, Delay: 2, MaximumDelay: durationPointer(1)}},
		{Status: &StatusRetry{Maximum: 1, Delay: -1}},
		{Status: &StatusRetry{Maximum: 1, MaximumDelay: durationPointer(-1)}},
		{Status: &StatusRetry{Maximum: 1, Delay: 2, MaximumDelay: durationPointer(1)}},
		{Status: &StatusRetry{Maximum: 1, RetryAfterLimit: durationPointer(-1)}},
		{Status: &StatusRetry{Maximum: 1, Statuses: []int{-1}}},
		{Status: &StatusRetry{Maximum: 1, Statuses: []int{65536}}},
		{UnprocessedReplays: uint64Pointer(0)},
	} {
		if _, err := retryPolicyWire(invalid); kind(err) != "invalid_retry_policy" {
			t.Fatalf("invalid policy error=%v", err)
		}
	}
}

func TestStatusRetryUsesCoreReplayRulesAndRequestReplacement(t *testing.T) {
	policy := RetryPolicy{Status: &StatusRetry{Statuses: []int{503}, Maximum: 1}}
	for _, test := range []struct {
		name, method string
		client       RetryPolicy
		request      *RetryPolicy
		wantStatus   int
		wantBodies   []string
	}{
		{"default", "GET", RetryPolicy{}, nil, 503, []string{"upload"}},
		{"inherits", "GET", policy, nil, 200, []string{"upload", "upload"}},
		{"request enables", "PUT", RetryPolicy{}, &policy, 200, []string{"upload", "upload"}},
		{"request disables", "GET", policy, &RetryPolicy{}, 503, []string{"upload"}},
		{"unsafe method", "POST", policy, nil, 503, []string{"upload"}},
		{"aggregate zero", "GET", RetryPolicy{Status: policy.Status, MaximumRetries: uint64Pointer(0)}, nil, 503, []string{"upload"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var mu sync.Mutex
			var bodies []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				bodies = append(bodies, string(data))
				hit := len(bodies)
				mu.Unlock()
				if r.Method != test.method {
					t.Errorf("method=%s", r.Method)
				}
				if hit == 1 {
					w.WriteHeader(503)
				}
				_, _ = io.WriteString(w, "ok")
			}))
			defer server.Close()
			client, err := New(Config{Profile: profile, Protocol: "h1", RetryPolicy: test.client, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			response, err := client.Do(context.Background(), Request{Method: test.method, URL: server.URL, Body: []byte("upload"), RetryPolicy: test.request})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.Status != test.wantStatus {
				t.Fatalf("status=%d", response.Status)
			}
			data, err := response.Body.ReadAll(2)
			if err != nil || string(data) != "ok" {
				t.Fatalf("body=%q error=%v", data, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if !reflect.DeepEqual(bodies, test.wantBodies) {
				t.Fatalf("bodies=%v want=%v", bodies, test.wantBodies)
			}
		})
	}
}

func TestInvalidStatusRetryFailsBeforeSending(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { mu.Lock(); hits++; mu.Unlock() }))
	defer server.Close()
	client, err := New(Config{Profile: profile, Protocol: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, statuses := range [][]int{nil, {421}, {503, 200}} {
		policy := RetryPolicy{Status: &StatusRetry{Statuses: statuses, Maximum: 1}}
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL, RetryPolicy: &policy})
		if response != nil || kind(err) != "invalid_retry_policy" {
			t.Fatalf("response=%v error=%v", response, err)
		}
		invalid, err := New(Config{Profile: profile, Protocol: "h1", RetryPolicy: policy})
		if invalid != nil || kind(err) != "invalid_retry_policy" {
			t.Fatalf("client=%v error=%v", invalid, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("invalid policy sent %d requests", hits)
	}
}
