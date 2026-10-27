package phantom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type admissionEvent struct {
	index   int
	entered bool
	err     error
}

type admissionPeer struct {
	server    *httptest.Server
	events    chan admissionEvent
	cancelled chan struct{}
	sends     atomic.Int64
}

func newAdmissionPeer(count int) *admissionPeer {
	peer := &admissionPeer{events: make(chan admissionEvent, 2*count+1), cancelled: make(chan struct{}, count+1)}
	peer.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer.sends.Add(1)
		if r.URL.Path == "/pending" {
			index, err := strconv.Atoi(r.URL.Query().Get("index"))
			if err != nil {
				http.Error(w, "invalid request index", http.StatusBadRequest)
				return
			}
			peer.events <- admissionEvent{index: index, entered: true}
			<-r.Context().Done()
			peer.cancelled <- struct{}{}
			return
		}
		w.Header().Set("Content-Length", "1")
		_, _ = io.WriteString(w, "x")
	}))
	return peer
}

func admissionClient(tb testing.TB, maximum int) *Client {
	tb.Helper()
	active := uint64(maximum + 1)
	client, err := New(Config{Profile: profile, Protocol: "h1", Timeout: 30 * time.Second, Pool: &PoolOptions{MaxConcurrentHTTP1RequestsPerOrigin: &active}})
	if err != nil {
		tb.Fatal(err)
	}
	return client
}

func closeAdmissionBodies(tb testing.TB, bodies []*Body) {
	tb.Helper()
	for _, body := range bodies {
		if err := body.Close(); err != nil {
			tb.Error(err)
		}
	}
}

func TestResponseCapacityCannotDiscardAnAlreadySentResponse(t *testing.T) {
	peer := newAdmissionPeer(0)
	defer peer.server.Close()
	client := admissionClient(t, 128)
	defer client.Close()
	var bodies []*Body
	defer func() { closeAdmissionBodies(t, bodies) }()
	for range 64 {
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.server.URL})
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, response.Body)
	}
	before := peer.sends.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := client.Do(ctx, Request{Method: "POST", URL: peer.server.URL, Body: []byte("side effect")})
	if response != nil {
		defer response.Body.Close()
	}
	if kind(err) == "capacity" && peer.sends.Load() != before {
		t.Fatalf("capacity discarded a response after sending request: origin sends %d -> %d", before, peer.sends.Load())
	}
	if err != nil && kind(err) != "capacity" && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

type mixedAdmissionObservation struct {
	sends            int64
	rejected         int
	bodyCompletions  int
	bodyRejected     int
	cancellation     time.Duration
	peerCancellation time.Duration
}

func observeMixedAdmission(tb testing.TB, total int) mixedAdmissionObservation {
	tb.Helper()
	live := max(1, total/4)
	pending := total - live
	peer := newAdmissionPeer(pending)
	defer peer.server.Close()
	client := admissionClient(tb, total)
	defer func() {
		if err := client.Close(); err != nil {
			tb.Error(err)
		}
	}()
	var bodies []*Body
	defer func() { closeAdmissionBodies(tb, bodies) }()
	for range live {
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.server.URL})
		if err != nil {
			tb.Fatal(err)
		}
		bodies = append(bodies, response.Body)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var workers sync.WaitGroup
	for index := range pending {
		workers.Go(func() {
			response, err := client.Do(ctx, Request{Method: "GET", URL: peer.server.URL + "/pending?index=" + strconv.Itoa(index)})
			if response != nil {
				_ = response.Body.Close()
			}
			peer.events <- admissionEvent{index: index, err: err}
		})
	}
	// Every index is accounted for by an independent origin observation or a
	// caller-visible rejection. This probe targets the current fail-fast policy.
	seen := make([]bool, pending)
	observed, arrived := 0, 0
	result := mixedAdmissionObservation{}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for observed < pending {
		select {
		case event := <-peer.events:
			if event.index < 0 || event.index >= pending {
				tb.Fatal("peer returned an invalid index")
			}
			if !seen[event.index] {
				seen[event.index] = true
				observed++
				if event.entered {
					arrived++
				} else if kind(event.err) == "capacity" {
					result.rejected++
				} else {
					tb.Fatalf("pending request failed before observation: %v", event.err)
				}
			}
		case <-deadline.C:
			cancel()
			workers.Wait()
			tb.Fatal("pending requests did not reach admission within the bounded run")
		}
	}
	for _, body := range bodies {
		data, err := body.ReadAll(1)
		if kind(err) == "capacity" {
			result.bodyRejected++
		} else if err != nil || string(data) != "x" {
			cancel()
			workers.Wait()
			tb.Fatalf("live body: %q %v", data, err)
		} else {
			result.bodyCompletions++
		}
	}
	started := time.Now()
	cancel()
	workers.Wait()
	result.cancellation = time.Since(started)
	for range arrived {
		select {
		case <-peer.cancelled:
		case <-deadline.C:
			tb.Fatal("origin did not observe cancellation within the bounded run")
		}
	}
	result.peerCancellation = time.Since(started)
	result.sends = peer.sends.Load()
	return result
}

func TestLiveBodiesSurvivePendingHeadAdmission(t *testing.T) {
	result := observeMixedAdmission(t, 96)
	t.Logf("origin sends=%d early capacity=%d completed bodies=%d rejected bodies=%d cancellation=%s peer cancellation=%s", result.sends, result.rejected, result.bodyCompletions, result.bodyRejected, result.cancellation, result.peerCancellation)
	if result.bodyRejected != 0 {
		t.Fatalf("pending heads starved %d existing response bodies", result.bodyRejected)
	}
}

// BenchmarkMixedAdmission holds response heads to expose admission, then reads
// existing bodies and cancels. Counters include the in-process controlled peer.
func BenchmarkMixedAdmission(b *testing.B) {
	for _, total := range []int{1, 8, 32, 64, 96} {
		b.Run(fmt.Sprint(total), func(b *testing.B) {
			var sum mixedAdmissionObservation
			for b.Loop() {
				result := observeMixedAdmission(b, total)
				sum.sends += result.sends
				sum.rejected += result.rejected
				sum.bodyCompletions += result.bodyCompletions
				sum.bodyRejected += result.bodyRejected
				sum.cancellation += result.cancellation
				sum.peerCancellation += result.peerCancellation
			}
			runs := float64(b.N)
			b.ReportMetric(float64(sum.sends)/runs, "origin-sends/op")
			b.ReportMetric(float64(sum.rejected)/runs, "admission-errors/op")
			b.ReportMetric(float64(sum.bodyCompletions)/runs, "completed-bodies/op")
			b.ReportMetric(float64(sum.bodyRejected)/runs, "body-errors/op")
			b.ReportMetric(float64(sum.cancellation.Nanoseconds())/runs, "cancel-ns/op")
			b.ReportMetric(float64(sum.peerCancellation.Nanoseconds())/runs, "peer-cancel-ns/op")
		})
	}
}
