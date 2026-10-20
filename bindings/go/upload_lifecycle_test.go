package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

func TestEarlyHTTP2UploadCloseCancelAndAbandonPreserveSibling(t *testing.T) {
	for _, action := range []string{"close", "cancel", "abandon"} {
		t.Run(action, func(t *testing.T) {
			addresses := make(chan string, 2)
			peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				addresses <- r.RemoteAddr
				if r.URL.Path == "/sibling" {
					_, _ = io.WriteString(w, "healthy")
					return
				}
				_, _ = io.WriteString(w, "head")
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
			source := newGatedUpload()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Keep the response out of the test's stack for the abandoned case.
			func() {
				response, err := client.Do(ctx, Request{Method: "POST", URL: peer.URL, Upload: source})
				if err != nil {
					t.Fatal(err)
				}
				if action == "close" {
					_ = response.Body.Close()
				}
				if action == "cancel" {
					cancel()
				}
			}()
			if action == "abandon" {
				deadline := time.Now().Add(3 * time.Second)
				for source.closes.Load() == 0 && time.Now().Before(deadline) {
					runtime.GC()
					time.Sleep(time.Millisecond)
				}
			}
			waitUploadClosed(t, &source.closes)
			sibling, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/sibling"})
			if err != nil {
				t.Fatal(err)
			}
			if data, err := sibling.Body.ReadAll(7); err != nil || string(data) != "healthy" {
				t.Fatalf("sibling %q: %v", data, err)
			}
			if first, second := <-addresses, <-addresses; first != second {
				t.Fatalf("sibling moved connections: %s != %s", first, second)
			}
		})
	}
}

func TestUnreadEarlyHTTP2UploadHonorsInheritedAndOverriddenTotal(t *testing.T) {
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		_, _ = io.WriteString(w, "head")
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	peer.EnableHTTP2 = true
	peer.StartTLS()
	defer peer.Close()
	client, err := New(Config{Profile: profile, Protocol: "h2", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeouts: Timeouts{Total: LimitTimeout(time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	fork, err := client.Fork(SessionSharing{})
	if err != nil {
		t.Fatal(err)
	}
	defer fork.Close()
	for _, c := range []*Client{client, fork} {
		warm, err := c.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/warm"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := warm.Body.ReadAll(2); err != nil {
			t.Fatal(err)
		}
		source := newGatedUpload()
		response, err := c.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Upload: source})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		// No body read drives the Rust response timer during this wait.
		waitUploadClosed(t, &source.closes)
		_, err = response.Body.Read(make([]byte, 64))
		var failure *Error
		if !errors.As(err, &failure) || failure.Kind != "timeout" || failure.TimeoutPhase != "total" {
			t.Fatalf("unread upload deadline: %v", err)
		}
		_ = response.Body.Close()
	}
	source := newGatedUpload()
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Upload: source, Timeouts: Timeouts{Total: Timeout{Mode: TimeoutDisabled}}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	time.Sleep(1100 * time.Millisecond)
	if source.closes.Load() != 0 {
		t.Fatal("disabled total inherited the client deadline")
	}
	_ = response.Body.Close()
	waitUploadClosed(t, &source.closes)
	zero := newGatedUpload()
	if response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Upload: zero, Timeouts: Timeouts{Total: LimitTimeout(0)}}); kind(err) != "timeout" {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatalf("zero total: %v", err)
	}
	waitUploadClosed(t, &zero.closes)
}
