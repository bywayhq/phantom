package phantom

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStreamingMultipartFramingAndReaderFailuresCloseUnstartedSources(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer peer.Close()
	client := newClient(t)
	sentinel := errors.New("private source cause")
	for _, test := range []struct {
		name     string
		reader   io.Reader
		maximum  uint64
		expected string
		cause    error
	}{
		{"cap", strings.NewReader(strings.Repeat("x", 2048)), 256, "multipart_too_large", nil},
		{"split collision", &frameReader{frames: [][]byte{[]byte("first--fi"), []byte("xture-tail")}}, 4096, "multipart_boundary_collision", nil},
		{"source", &tailUpload{data: []byte("prefix"), err: sentinel}, 4096, "", sentinel},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := &ownedUpload{Reader: test.reader}
			next := &ownedUpload{Reader: strings.NewReader("not read")}
			response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Headers: []Header{{Name: "Content-Type", Value: []byte("multipart/form-data; boundary=fixture")}}, Multipart: &StreamingMultipart{Boundary: "fixture", MaximumBytes: test.maximum, Parts: []MultipartPart{MultipartReader("first", first), MultipartReader("next", next)}}})
			if err == nil {
				_, err = response.Body.ReadAll(0)
			}
			if err == nil || (test.expected != "" && kind(err) != test.expected) {
				t.Fatalf("framing failure: %v", err)
			}
			if test.cause != nil && !errors.Is(err, test.cause) {
				t.Fatalf("lost reader cause: %v", err)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("source leaked")
			}
			waitUploadClosed(t, &first.closes)
			waitUploadClosed(t, &next.closes)
			if next.bytes.Load() != 0 {
				t.Fatal("unstarted source polled")
			}
		})
	}
}

type frameReader struct{ frames [][]byte }

func (r *frameReader) Read(output []byte) (int, error) {
	if len(r.frames) == 0 {
		return 0, io.EOF
	}
	n := copy(output, r.frames[0])
	r.frames[0] = r.frames[0][n:]
	if len(r.frames[0]) == 0 {
		r.frames = r.frames[1:]
	}
	return n, nil
}

func TestStreamingMultipartPreflightDoesNotSpendBudget(t *testing.T) {
	var calls atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.Copy(io.Discard, r.Body) }))
	defer peer.Close()
	client := newClient(t)
	budget, err := NewAttemptBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	for _, test := range []string{"body conflict", "upload conflict", "prepared conflict", "bad name", "bad boundary", "length", "type", "zero", "too many"} {
		t.Run(test, func(t *testing.T) {
			source := &ownedUpload{Reader: strings.NewReader("unread")}
			form := &StreamingMultipart{Boundary: "fixture", MaximumBytes: 4096, Parts: []MultipartPart{MultipartReader("file", source)}}
			request := Request{Method: "POST", URL: peer.URL, Multipart: form, Budget: budget, Headers: []Header{{Name: "Content-Type", Value: []byte("multipart/form-data; boundary=fixture")}}}
			switch test {
			case "body conflict":
				request.Body = []byte{}
			case "upload conflict":
				request.Upload = io.NopCloser(strings.NewReader(""))
			case "prepared conflict":
				request.PreparedBody = &PreparedBody{}
			case "bad name":
				form.Parts[0].name = "bad\x00name"
			case "bad boundary":
				form.Boundary = "bad\r\nboundary"
			case "length":
				request.Headers = append(request.Headers, Header{Name: "Content-Length", Value: []byte("0")})
			case "type":
				request.Headers[0].Value = []byte("multipart/form-data; boundary=other")
			case "zero":
				form.MaximumBytes = 0
			case "too many":
				form.Parts = append(form.Parts, make([]MultipartPart, 1024)...)
			}
			response, err := client.Do(context.Background(), request)
			if response != nil {
				_ = response.Body.Close()
			}
			if err == nil {
				t.Fatal("invalid multipart accepted")
			}
			if test == "too many" {
				if source.closes.Load() != 0 {
					t.Fatal("count rejection took reader custody")
				}
				_ = source.Close()
			} else {
				waitUploadClosed(t, &source.closes)
			}
			if source.bytes.Load() != 0 {
				t.Fatal("invalid request read source")
			}
			remaining, err := budget.Remaining()
			if err != nil || remaining != 1 || calls.Load() != 0 {
				t.Fatalf("preflight admitted: remaining=%d calls=%d err=%v", remaining, calls.Load(), err)
			}
		})
	}
}

func TestStreamingMultipartCannotReplayAfterRedirect(t *testing.T) {
	var calls atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "0")
		w.Header().Set("Location", "/next")
		w.WriteHeader(307)
	}))
	defer peer.Close()
	client := newClient(t)
	source := &ownedUpload{Reader: bytes.NewReader([]byte("file"))}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := client.Do(ctx, Request{Method: "POST", URL: peer.URL, Headers: []Header{{Name: "Content-Type", Value: []byte("multipart/form-data; boundary=once")}}, Multipart: &StreamingMultipart{Boundary: "once", MaximumBytes: 1024, Parts: []MultipartPart{MultipartReader("file", source)}}, RedirectPolicy: &RedirectPolicy{MaximumHops: 1}})
	if response != nil {
		_ = response.Body.Close()
	}
	if kind(err) != "request_body" || calls.Load() != 1 {
		t.Fatalf("multipart replay: %v, calls=%d", err, calls.Load())
	}
	waitUploadClosed(t, &source.closes)
}
