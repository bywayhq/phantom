package phantom

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newDiagnostics(t *testing.T, maximum uint64) *RequestDiagnostics {
	t.Helper()
	owner, err := NewRequestDiagnostics(maximum)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	return owner
}

func timeline(t *testing.T, owner *RequestDiagnostics) *RequestTimeline {
	t.Helper()
	value, err := owner.Snapshot()
	if err != nil || value == nil {
		t.Fatalf("timeline=%+v, error=%v", value, err)
	}
	return value
}

func bodyTiming(t *testing.T, value *RequestTimeline) RequestTiming {
	t.Helper()
	for _, event := range value.Events {
		if event.Phase == "response_body" {
			return event
		}
	}
	t.Fatalf("response body was not observed: %+v", value)
	return RequestTiming{}
}

func TestDiagnosticsDurationPreservesFullRangeAndRejectsInvalidABI(t *testing.T) {
	var duration DiagnosticDuration
	if err := json.Unmarshal([]byte(`{"seconds":18446744073709551615,"nanoseconds":999999999}`), &duration); err != nil || duration.Seconds != math.MaxUint64 || duration.Nanoseconds != 999999999 {
		t.Fatalf("duration=%+v, error=%v", duration, err)
	}
	for _, input := range []string{`null`, `{}`, `{"seconds":0}`, `{"seconds":-1,"nanoseconds":0}`, `{"seconds":0,"nanoseconds":1000000000}`} {
		if err := json.Unmarshal([]byte(input), &duration); err == nil {
			t.Fatalf("accepted invalid duration %s", input)
		}
	}
	for _, input := range []string{`{}`, `{"outcome":"complete","events":[],"dropped_events":0,"admitted_attempts":0}`, `{"outcome":"pending","events":[],"admitted_attempts":0}`} {
		if _, err := decodeRequestTimeline([]byte(input)); kind(err) != "native_abi" {
			t.Fatalf("accepted invalid timeline %s: %v", input, err)
		}
	}
	if value, err := decodeRequestTimeline([]byte("null")); err != nil || value != nil {
		t.Fatalf("unattached=%+v, error=%v", value, err)
	}
}

func TestDiagnosticsSeparateResponseHeadFromBodyCompletionAndAbandonment(t *testing.T) {
	for _, abandon := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "abandon"}[abandon], func(t *testing.T) {
			release := make(chan struct{})
			var releaseOnce sync.Once
			finish := func() { releaseOnce.Do(func() { close(release) }) }
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "2")
				_, _ = io.WriteString(w, "a")
				w.(http.Flusher).Flush()
				select {
				case <-release:
					_, _ = io.WriteString(w, "b")
				case <-r.Context().Done():
				}
			}))
			defer func() {
				finish()
				server.Close()
			}()
			client := newClient(t)
			owner := newDiagnostics(t, 128)
			if value, err := owner.Snapshot(); err != nil || value != nil {
				t.Fatalf("unattached=%+v, error=%v", value, err)
			}
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL, Diagnostics: owner})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			before := timeline(t, owner)
			if before.Outcome != "response_head" || before.SendElapsed == nil || bodyTiming(t, before).Outcome != "pending" || bodyTiming(t, before).Finished != nil {
				t.Fatalf("head/body distinction lost: %+v", before)
			}
			var first [1]byte
			if _, err := io.ReadFull(response.Body, first[:]); err != nil || first[0] != 'a' {
				t.Fatalf("first byte=%q, error=%v", first, err)
			}
			want := TimingAbandoned
			if abandon {
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				finish()
				remaining, err := response.Body.ReadAll(1)
				if err != nil || string(remaining) != "b" {
					t.Fatalf("remaining=%q, error=%v", remaining, err)
				}
				want = TimingCompleted
			}
			after := timeline(t, owner)
			if after.Outcome != "response_head" || *after.SendElapsed != *before.SendElapsed || bodyTiming(t, after).Outcome != want || bodyTiming(t, after).Finished == nil {
				t.Fatalf("body result=%+v, expected %s", after, want)
			}
			if bodyTiming(t, before).Outcome != "pending" {
				t.Fatal("earlier snapshot changed after completion")
			}
			finish()
		})
	}
}

func TestDiagnosticsSingleUseIsAtomicAndCapacityDropsAreExplicit(t *testing.T) {
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := newClient(t)
	owner := newDiagnostics(t, 1)
	var pending sync.WaitGroup
	var successes atomic.Int64
	for range 8 {
		pending.Add(1)
		go func() {
			defer pending.Done()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL, Diagnostics: owner})
			if err != nil {
				if kind(err) != "diagnostics_already_attached" {
					t.Errorf("duplicate attachment: %v", err)
				}
				return
			}
			if err := response.Body.Close(); err != nil {
				t.Error(err)
			}
			successes.Add(1)
		}()
	}
	pending.Wait()
	if successes.Load() != 1 || received.Load() != 1 {
		t.Fatalf("successes=%d, received=%d", successes.Load(), received.Load())
	}
	value := timeline(t, owner)
	if value.Outcome != "response_head" || len(value.Events) != 1 || value.DroppedEvents == 0 || value.AdmittedAttempts != 1 {
		t.Fatalf("bounded timeline=%+v", value)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Snapshot(); kind(err) != "invalid_handle" {
		t.Fatalf("released owner snapshot: %v", err)
	}
	if _, err := NewRequestDiagnostics(0); kind(err) != "invalid_diagnostics_capacity" {
		t.Fatalf("zero capacity: %v", err)
	}
}

func TestDiagnosticsRetainCancelledAndFailedSends(t *testing.T) {
	for _, cancelSend := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "cancel"}[cancelSend], func(t *testing.T) {
			received := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(received)
				if cancelSend {
					<-r.Context().Done()
					return
				}
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = connection.Close()
				}
			}))
			defer server.Close()
			client := newClient(t)
			owner := newDiagnostics(t, 128)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				response, err := client.Do(ctx, Request{Method: "POST", URL: server.URL, Body: []byte("x"), Diagnostics: owner})
				if response != nil {
					_ = response.Body.Close()
				}
				done <- err
			}()
			select {
			case <-received:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not reach peer")
			}
			want := TimelineFailed
			if cancelSend {
				cancel()
				want = TimelineCancelled
			}
			if err := <-done; err == nil {
				t.Fatal("send unexpectedly succeeded")
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				value := timeline(t, owner)
				if value.Outcome == want {
					if value.SendElapsed == nil {
						t.Fatal("polled send has no elapsed observation")
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("outcome=%s, expected %s", value.Outcome, want)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestDiagnosticsExposeVerifiedTLSFactsAndOwnedCertificateBytes(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := New(Config{Profile: profile, Protocol: "h1", AdditionalRootsDER: [][]byte{server.Certificate().Raw}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	owner := newDiagnostics(t, 128)
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL, Diagnostics: owner})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	for _, event := range timeline(t, owner).Events {
		if event.Connection == nil {
			continue
		}
		connection := event.Connection
		info := connection.OriginTLS.Info
		if connection.EndpointScope != "tcp_socket" || connection.PeerAddress == nil || connection.OriginTLS.State != "established" || info == nil || !info.PeerVerified || info.VersionID == nil || info.CipherSuiteID == nil || len(info.PeerCertificatesDER) == 0 || !bytes.Equal(info.PeerCertificatesDER[0], server.Certificate().Raw) || connection.ProxyTLS.State != "not_used" {
			t.Fatalf("TLS facts=%+v, connection=%+v", info, connection)
		}
		info.PeerCertificatesDER[0][0] ^= 1
		for _, later := range timeline(t, owner).Events {
			if later.Connection != nil && bytes.Equal(later.Connection.OriginTLS.Info.PeerCertificatesDER[0], server.Certificate().Raw) {
				return
			}
		}
		t.Fatal("snapshot mutated shared certificate bytes")
	}
	t.Fatal("connection use was not observed")
}
