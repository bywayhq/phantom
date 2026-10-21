package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type multipartCloseFailure struct {
	ownedUpload
	failure error
}

func (source *multipartCloseFailure) Close() error { source.closes.Add(1); return source.failure }

func TestMultipartValidationKeepsRedactedCloseFailure(t *testing.T) {
	sentinel := errors.New("private cleanup cause")
	source := &multipartCloseFailure{ownedUpload: ownedUpload{Reader: strings.NewReader("unused")}, failure: sentinel}
	_, err := (&Client{}).Do(nil, Request{Multipart: &StreamingMultipart{Parts: []MultipartPart{MultipartReader("file", source)}}})
	if kind(err) != "invalid_context" || !errors.Is(err, sentinel) || strings.Contains(err.Error(), "private") || source.closes.Load() != 1 || source.bytes.Load() != 0 {
		t.Fatalf("cleanup result: %v", err)
	}
}

func TestMultipartReaderCloseFailureStopsBeforeNextPart(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer peer.Close()
	client := newClient(t)
	sentinel := errors.New("private cleanup cause")
	source := &multipartCloseFailure{ownedUpload: ownedUpload{Reader: strings.NewReader("prefix")}, failure: sentinel}
	next := &ownedUpload{Reader: strings.NewReader("unused")}
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Headers: []Header{{Name: "Content-Type", Value: []byte("multipart/form-data; boundary=close")}}, Multipart: &StreamingMultipart{Boundary: "close", MaximumBytes: 1024, Parts: []MultipartPart{MultipartReader("file", source), MultipartReader("next", next)}}})
	if err == nil {
		_, err = response.Body.ReadAll(0)
	}
	if err == nil || !errors.Is(err, sentinel) || strings.Contains(err.Error(), "private") {
		t.Fatalf("cleanup result: %v", err)
	}
	waitUploadClosed(t, &source.closes)
	waitUploadClosed(t, &next.closes)
	if next.bytes.Load() != 0 {
		t.Fatal("failed Close permitted next reader")
	}
}

func TestEarlyFinalMultipartResponseRetainsUnstartedCleanupFailure(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(413)
		_, _ = io.WriteString(w, "no")
	}))
	defer peer.Close()
	client := newClient(t)
	for _, maximum := range []int{2, 1} {
		t.Run(map[bool]string{true: "successful EOF", false: "response cap"}[maximum == 2], func(t *testing.T) {
			sentinel := errors.New("private unstarted cleanup")
			source := &multipartCloseFailure{ownedUpload: ownedUpload{Reader: strings.NewReader("unread")}, failure: sentinel}
			response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Headers: []Header{{Name: "Content-Type", Value: []byte("multipart/form-data; boundary=early")}}, ExpectContinue: durationPointer(time.Second), Multipart: &StreamingMultipart{Boundary: "early", MaximumBytes: 1024, Parts: []MultipartPart{MultipartReader("file", source)}}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = response.Body.ReadAll(maximum)
			if err == nil || !errors.Is(err, sentinel) || strings.Contains(err.Error(), "private") {
				t.Fatalf("lost cleanup: %v", err)
			}
			if maximum == 1 && kind(err) != "response_body_limit" {
				t.Fatalf("replaced bound error: %v", err)
			}
			if source.bytes.Load() != 0 || source.closes.Load() != 1 {
				t.Fatal("early final read or lost source")
			}
			if err = response.Body.Close(); !errors.Is(err, sentinel) {
				t.Fatalf("close lost cleanup: %v", err)
			}
		})
	}
}

func TestEarlyHTTP2MultipartCloseCancelAndUnreadDeadlinePreserveSibling(t *testing.T) {
	for _, action := range []string{"close", "cancel", "deadline"} {
		t.Run(action, func(t *testing.T) {
			cancelled := make(chan error, 1)
			healthyLive := make(chan struct{})
			releaseHealthy := make(chan struct{})
			var release sync.Once
			releaseSibling := func() { release.Do(func() { close(releaseHealthy) }) }
			addresses := make(chan string, 3)
			peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				addresses <- r.RemoteAddr
				if r.URL.Path == "/warm" {
					_, _ = io.WriteString(w, "ok")
					return
				}
				if r.URL.Path == "/healthy" {
					_, _ = io.WriteString(w, "heal")
					w.(http.Flusher).Flush()
					close(healthyLive)
					select {
					case <-releaseHealthy:
						_, _ = io.WriteString(w, "thy")
					case <-r.Context().Done():
					}
					return
				}
				_, _ = io.WriteString(w, "head")
				w.(http.Flusher).Flush()
				_, _ = io.Copy(io.Discard, r.Body)
				cancelled <- r.Context().Err()
			}))
			peer.EnableHTTP2 = true
			peer.StartTLS()
			defer peer.Close()
			defer releaseSibling()
			client, err := New(Config{Profile: profile, Protocol: "h2", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			warm, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/warm"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = warm.Body.ReadAll(2); err != nil {
				t.Fatal(err)
			}
			first := newGatedUpload()
			later := &ownedUpload{Reader: strings.NewReader("unread")}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := Request{Method: "POST", URL: peer.URL + "/upload", Headers: []Header{{Name: "content-type", Value: []byte("multipart/form-data; boundary=held")}}, Multipart: &StreamingMultipart{Boundary: "held", MaximumBytes: 4096, Parts: []MultipartPart{MultipartReader("first", first), MultipartReader("later", later)}}}
			if action == "deadline" {
				request.Timeouts.Total = LimitTimeout(time.Second)
			}
			selected, err := client.Do(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer selected.Body.Close()
			select {
			case <-first.started:
			case <-time.After(3 * time.Second):
				t.Fatal("multipart reader not demanded")
			}
			healthy, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/healthy", Timeouts: Timeouts{Total: Timeout{Mode: TimeoutDisabled}}})
			if err != nil {
				t.Fatal(err)
			}
			defer healthy.Body.Close()
			select {
			case <-healthyLive:
			case <-time.After(3 * time.Second):
				t.Fatal("sibling not live")
			}
			switch action {
			case "close":
				if err := selected.Body.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			waitUploadClosed(t, &first.closes)
			waitUploadClosed(t, &later.closes)
			if later.bytes.Load() != 0 {
				t.Fatal("closed multipart polled unstarted reader")
			}
			if action == "deadline" {
				_, err = selected.Body.ReadAll(16)
				var failure *Error
				if !errors.As(err, &failure) || failure.Kind != "timeout" || failure.TimeoutPhase != "total" {
					t.Fatalf("unread deadline: %v", err)
				}
			}
			select {
			case err := <-cancelled:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("peer cancellation: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("peer did not observe cancellation")
			}
			releaseSibling()
			if data, err := healthy.Body.ReadAll(7); err != nil || string(data) != "healthy" {
				t.Fatalf("sibling %q: %v", data, err)
			}
			firstAddress := <-addresses
			for range 2 {
				if other := <-addresses; other != firstAddress {
					t.Fatal("multipart cancellation replaced shared connection")
				}
			}
		})
	}
}
