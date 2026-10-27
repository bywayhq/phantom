package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEventCancellationReleasesBlockedUploadAndPreservesHTTP2Sibling(t *testing.T) {
	for _, action := range []string{"cancel", "close"} {
		t.Run(action, func(t *testing.T) {
			addresses := make(chan string, 2)
			release := make(chan struct{})
			peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				addresses <- r.RemoteAddr
				if r.URL.Path == "/sibling" {
					_, _ = io.WriteString(w, "heal")
					w.(http.Flusher).Flush()
					select {
					case <-release:
						_, _ = io.WriteString(w, "thy")
					case <-r.Context().Done():
					}
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: started\n\n")
				w.(http.Flusher).Flush()
				_, _ = io.Copy(io.Discard, r.Body)
			}))
			peer.EnableHTTP2 = true
			peer.StartTLS()
			defer peer.Close()
			client, err := New(Config{Profile: profile, Protocol: "h2", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := newGatedUpload()
			response, err := client.Events(ctx, Request{Method: "POST", URL: peer.URL, Upload: source}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Events.Close()
			if event, err := response.Events.Next(); err != nil || event.Data != "started" {
				t.Fatalf("first event: %+v, %v", event, err)
			}
			sibling, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/sibling"})
			if err != nil {
				t.Fatal(err)
			}
			defer sibling.Body.Close()
			pending := make(chan error, 1)
			go func() { _, err := response.Events.Next(); pending <- err }()
			if action == "cancel" {
				cancel()
			} else if err := response.Events.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-pending:
				if action == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
				if action == "close" && kind(err) != "sse_closed" {
					t.Fatalf("close: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("event read did not settle")
			}
			waitUploadClosed(t, &source.closes)
			close(release)
			if data, err := sibling.Body.ReadAll(7); err != nil || string(data) != "healthy" {
				t.Fatalf("sibling: %q, %v", data, err)
			}
			if first, second := <-addresses, <-addresses; first != second {
				t.Fatalf("sibling moved connections: %s != %s", first, second)
			}
		})
	}
}

func TestShutdownTimeoutLeavesEventStreamReadable(t *testing.T) {
	release := make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "data: drained\n\n")
		case <-r.Context().Done():
		}
	}))
	defer peer.Close()
	client := newClient(t)
	response, err := client.Events(context.Background(), Request{Method: "GET", URL: peer.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := client.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown did not wait for stream: %v", err)
	}
	close(release)
	if event, err := response.Events.Next(); err != nil || event.Data != "drained" {
		t.Fatalf("retained stream: %+v, %v", event, err)
	}
	if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if err := client.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEventSetupCancellationReclaimsUnpublishedResponse(t *testing.T) {
	seen := make(chan struct{}, 1)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pending" {
			seen <- struct{}{}
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: recovered\n\n")
	}))
	defer peer.Close()
	client := newClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		response, err := client.Events(ctx, Request{Method: "GET", URL: peer.URL + "/pending"}, nil)
		if response != nil {
			_ = response.Events.Close()
		}
		done <- err
	}()
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("setup did not reach peer")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("setup cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setup did not cancel")
	}
	response, err := client.Events(context.Background(), Request{Method: "GET", URL: peer.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	if event, err := response.Events.Next(); err != nil || event.Data != "recovered" {
		t.Fatalf("after cancellation: %+v, %v", event, err)
	}
}
