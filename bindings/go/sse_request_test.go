package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEventsPreserveRequestBodiesContextsAndSharedBudget(t *testing.T) {
	var hits atomic.Uint64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != "POST" || r.Header.Get("Sec-Fetch-Mode") != "cors" || r.Header.Get("Origin") != "http://"+r.Host || r.Referer() != "http://"+r.Host+"/page" {
			t.Errorf("request options: %s %v", r.Method, r.Header)
		}
		expectedType := "application/x-www-form-urlencoded"
		if r.URL.Path == "/multipart" {
			expectedType = "multipart/form-data; boundary=sse-body"
			if err := r.ParseMultipartForm(1024); err != nil {
				t.Error(err)
				return
			}
			if r.MultipartForm != nil {
				defer r.MultipartForm.RemoveAll()
			}
			if r.FormValue("message") != "payload" {
				t.Errorf("multipart value: %q", r.FormValue("message"))
			}
		} else {
			if r.URL.Path == "/prepared" {
				expectedType = "application/x-www-form-urlencoded;charset=UTF-8"
			}
			data, err := io.ReadAll(io.LimitReader(r.Body, 1024))
			if err != nil || string(data) != "message=payload" {
				t.Errorf("body: %q, %v", data, err)
			}
		}
		if r.Header.Get("Content-Type") != expectedType {
			t.Errorf("content type: %q", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: received\n\n")
	}))
	defer peer.Close()
	client := newClient(t)
	budget, err := NewAttemptBudget(4)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	prepared, err := PrepareForm([]FormField{{Name: "message", Value: "payload"}}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	source := &ownedUpload{Reader: strings.NewReader("message=payload")}
	multipart := &StreamingMultipart{Boundary: "sse-body", MaximumBytes: 1024, Parts: []MultipartPart{MultipartText("message", "payload")}}
	for _, test := range []struct {
		name    string
		request Request
	}{
		{"bytes", Request{Body: []byte("message=payload")}},
		{"stream", Request{Upload: source}},
		{"prepared", Request{PreparedBody: prepared}},
		{"multipart", Request{Multipart: multipart}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := test.request
			request.Method, request.URL, request.Context, request.Budget = "POST", peer.URL+"/"+test.name, "fetchUpload", budget
			contentType := "application/x-www-form-urlencoded"
			if request.PreparedBody != nil {
				contentType = request.PreparedBody.ContentType()
			}
			if request.Multipart != nil {
				contentType, err = request.Multipart.ContentType()
				if err != nil {
					t.Fatal(err)
				}
			}
			request.Headers = []Header{{Name: "Origin", Value: []byte(peer.URL)}, {Name: "Referer", Value: []byte(peer.URL + "/page")}, {Name: "Content-Type", Value: []byte(contentType)}}
			response, err := client.Events(context.Background(), request, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Events.Close()
			if event, err := response.Events.Next(); err != nil || event != (SSEEvent{Data: "received", Type: "message"}) {
				t.Fatalf("event: %+v, %v", event, err)
			}
			if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
		})
	}
	waitUploadClosed(t, &source.closes)
	if _, err := client.Events(context.Background(), Request{Method: "GET", URL: peer.URL, Budget: budget}, nil); kind(err) != "attempt_budget_exhausted" {
		t.Fatalf("budget exhaustion: %v", err)
	}
	if hits.Load() != 4 {
		t.Fatalf("origin received %d requests", hits.Load())
	}
}

func TestInvalidSSELimitsReleaseUploadsBeforeNativeAdmission(t *testing.T) {
	client := &Client{}
	client.id.Store(1)
	for _, limits := range []SSELimits{{-1, 1}, {1, -1}, {1024*1024 + 1, 1}, {1, 8*1024*1024 + 1}} {
		source := &ownedUpload{Reader: strings.NewReader("unread")}
		_, err := client.Events(context.Background(), Request{Method: "POST", URL: "http://127.0.0.1/", Upload: source}, &limits)
		if kind(err) != "invalid_sse_limits" || source.closes.Load() != 1 || source.bytes.Load() != 0 {
			t.Fatalf("invalid limits: %v, closes=%d, bytes=%d", err, source.closes.Load(), source.bytes.Load())
		}
	}
}
