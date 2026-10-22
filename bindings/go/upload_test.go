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

type ownedUpload struct {
	io.Reader
	closes atomic.Int32
	bytes  atomic.Int64
}

func (u *ownedUpload) Close() error { u.closes.Add(1); return nil }
func (u *ownedUpload) Read(output []byte) (int, error) {
	n, err := u.Reader.Read(output)
	u.bytes.Add(int64(n))
	return n, err
}

func waitUploadClosed(t *testing.T, count *atomic.Int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for count.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if count.Load() != 1 {
		t.Fatalf("source closed %d times", count.Load())
	}
}

type tailUpload struct {
	data []byte
	err  error
}

func (u *tailUpload) Read(output []byte) (int, error) {
	n := copy(output, u.data)
	u.data = u.data[n:]
	if len(u.data) == 0 {
		return n, u.err
	}
	return n, nil
}

func TestStreamingUploadLengthsAndFinalBytes(t *testing.T) {
	var received sync.Map
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter := &uploadByteCounter{}
		received.Store(r.URL.Path, counter)
		n, err := io.Copy(io.Discard, io.TeeReader(r.Body, counter))
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, "%d/%d", n, r.ContentLength)
	}))
	defer peer.Close()
	client := newClient(t)
	for _, test := range []struct {
		name  string
		size  int
		exact bool
	}{
		{"unknown", 9 * 1024 * 1024, false}, {"exact", 9 * 1024 * 1024, true}, {"zero", 0, true}, {"empty-unknown", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &ownedUpload{Reader: io.LimitReader(repeatedUploadByte{}, int64(test.size))}
			request := Request{Method: "POST", URL: peer.URL + "/" + test.name, Upload: source}
			length := uint64(test.size)
			wireLength := int64(-1)
			if test.exact {
				request.UploadLength = &length
				wireLength = int64(length)
			}
			started := time.Now()
			response, err := client.Do(context.Background(), request)
			var peerBytes int64
			if value, ok := received.Load("/" + test.name); ok {
				peerBytes = value.(*uploadByteCounter).bytes.Load()
			}
			t.Logf("upload elapsed=%s source_bytes=%d peer_bytes=%d", time.Since(started), source.bytes.Load(), peerBytes)
			if err != nil {
				var failure *Error
				if errors.As(err, &failure) {
					t.Logf("native error kind=%s protocol=%s timeout_phase=%s", failure.Kind, failure.Protocol, failure.TimeoutPhase)
				}
				t.Fatal(err)
			}
			data, err := response.Body.ReadAll(64)
			if err != nil || string(data) != fmt.Sprintf("%d/%d", test.size, wireLength) {
				t.Fatalf("response %q: %v", data, err)
			}
			waitUploadClosed(t, &source.closes)
		})
	}
	final := &ownedUpload{Reader: &tailUpload{data: []byte("last bytes"), err: io.EOF}}
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Upload: final})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := response.Body.ReadAll(64); err != nil || string(data) != "10/-1" {
		t.Fatalf("n+EOF %q: %v", data, err)
	}
	waitUploadClosed(t, &final.closes)
}

type uploadByteCounter struct{ bytes atomic.Int64 }

func (counter *uploadByteCounter) Write(input []byte) (int, error) {
	counter.bytes.Add(int64(len(input)))
	return len(input), nil
}

type repeatedUploadByte struct{}

func (repeatedUploadByte) Read(output []byte) (int, error) {
	for i := range output {
		output[i] = 'x'
	}
	return len(output), nil
}

func TestStreamingUploadFailuresAndValidationCloseSource(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer peer.Close()
	client := newClient(t)
	sentinel := errors.New("private reader failure")
	for _, test := range []struct {
		name   string
		reader io.Reader
		length *uint64
		cause  error
	}{
		{"source", &tailUpload{data: []byte("prefix"), err: sentinel}, nil, sentinel},
		{"short", strings.NewReader("a"), uploadSize(2), nil},
		{"long", strings.NewReader("abc"), uploadSize(2), nil},
		{"no-progress", emptyUpload{}, nil, io.ErrNoProgress},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &ownedUpload{Reader: test.reader}
			response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Upload: source, UploadLength: test.length})
			if err == nil {
				_, err = response.Body.ReadAll(1)
			}
			if err == nil {
				t.Fatal("upload failure accepted")
			}
			if test.cause != nil && !errors.Is(err, test.cause) {
				t.Fatalf("lost source cause: %v", err)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("source error exposed in redacted error")
			}
			waitUploadClosed(t, &source.closes)
		})
	}
	for _, request := range []Request{
		{Method: "POST", URL: peer.URL, Body: []byte{}, Upload: &ownedUpload{Reader: strings.NewReader("a")}},
		{Method: "POST", URL: "\x00", Upload: &ownedUpload{Reader: strings.NewReader("a")}},
	} {
		if _, err := client.Do(context.Background(), request); err == nil {
			t.Fatal("invalid request accepted")
		}
		waitUploadClosed(t, &request.Upload.(*ownedUpload).closes)
	}
	if _, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, UploadLength: uploadSize(0)}); kind(err) != "invalid_upload" {
		t.Fatalf("length without source: %v", err)
	}
}

func uploadSize(n uint64) *uint64 { return &n }

type emptyUpload struct{}

func (emptyUpload) Read([]byte) (int, error) { return 0, nil }

type gatedUpload struct {
	source  io.Reader
	started chan struct{}
	release chan struct{}
	closed  chan struct{}
	start   sync.Once
	close   sync.Once
	closes  atomic.Int32
}

func newGatedUpload() *gatedUpload {
	return &gatedUpload{source: bytes.NewReader([]byte("payload")), started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
}
func (u *gatedUpload) Read(output []byte) (int, error) {
	u.start.Do(func() { close(u.started) })
	select {
	case <-u.release:
		return u.source.Read(output)
	case <-u.closed:
		return 0, io.ErrClosedPipe
	}
}
func (u *gatedUpload) Close() error {
	u.closes.Add(1)
	u.close.Do(func() { close(u.closed) })
	return nil
}

func TestStreamingUploadCancellationAndNativeDeadlineInterruptReader(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer peer.Close()
	client := newClient(t)
	for _, deadline := range []bool{false, true} {
		source := newGatedUpload()
		ctx, cancel := context.WithCancel(context.Background())
		request := Request{Method: "POST", URL: peer.URL, Upload: source}
		if deadline {
			request.Timeouts.Total = LimitTimeout(100 * time.Millisecond)
		}
		done := make(chan error, 1)
		go func() {
			response, err := client.Do(ctx, request)
			if response != nil {
				_ = response.Body.Close()
			}
			done <- err
		}()
		select {
		case <-source.started:
		case <-time.After(3 * time.Second):
			t.Fatal("reader not started")
		}
		if !deadline {
			cancel()
		}
		select {
		case err := <-done:
			if deadline && kind(err) != "timeout" {
				t.Fatalf("native deadline: %v", err)
			}
			if !deadline && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("upload did not terminate")
		}
		cancel()
		waitUploadClosed(t, &source.closes)
	}
}

func TestStreamingUploadSurvivesEarlyHTTP2HeadAndPreservesSibling(t *testing.T) {
	source := newGatedUpload()
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sibling" {
			_, _ = io.WriteString(w, "healthy")
			return
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "head")
		w.(http.Flusher).Flush()
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil || n != 7 {
			t.Errorf("upload %d: %v", n, err)
		}
		_, _ = io.WriteString(w, "done")
	}))
	peer.EnableHTTP2 = true
	peer.StartTLS()
	defer peer.Close()
	client, err := New(Config{Profile: profile, Protocol: "h2", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Upload: source})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if source.closes.Load() != 0 {
		t.Fatal("source closed when only response head completed")
	}
	sibling, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/sibling"})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := sibling.Body.ReadAll(7); err != nil || string(data) != "healthy" {
		t.Fatalf("sibling %q: %v", data, err)
	}
	close(source.release)
	if data, err := response.Body.ReadAll(8); err != nil || string(data) != "headdone" {
		t.Fatalf("early response %q: %v", data, err)
	}
	waitUploadClosed(t, &source.closes)
}

func TestCompleteEarlyHTTP2ResponseClosesBlockedUploadReader(t *testing.T) {
	source := newGatedUpload()
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-source.started:
		case <-time.After(3 * time.Second):
			t.Error("source read did not overlap the early response")
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(413)
	}))
	peer.EnableHTTP2 = true
	peer.StartTLS()
	defer peer.Close()
	client, err := New(Config{Profile: profile, Protocol: "h2", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Upload: source})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.Status != 413 {
		t.Fatalf("status %d", response.Status)
	}
	waitUploadClosed(t, &source.closes)
}
