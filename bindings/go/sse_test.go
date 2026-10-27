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

func TestEventsDecodeSplitUTF8AndPreserveCommittedStateAtEOF(t *testing.T) {
	wire := []byte("\xef\xbb\xbf: comment\r\nid: first\r\nretry: 18446744073709551615\r\nevent: price\r\ndata: café\r\ndata: two\r\n\r\nid:\n\ndata: \xff\n\nid: before-eof\n\ndata: unfinished")
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Fetch-Mode") != "cors" || r.Header.Get("Referer") != "http://"+r.Host+"/page" {
			t.Errorf("request context: %v", r.Header)
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Add("X-Order", "one")
		w.Header().Add("X-Order", "two")
		for _, value := range wire {
			if _, err := w.Write([]byte{value}); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	defer peer.Close()
	client := newClient(t)
	response, err := client.Events(context.Background(), Request{Method: "GET", URL: peer.URL + "/events", Context: "fetch", Headers: []Header{{Name: "Referer", Value: []byte(peer.URL + "/page")}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	if response.Status != 200 || response.Protocol != "h1" || response.EffectiveURL != peer.URL+"/events" {
		t.Fatalf("response metadata: %+v", response)
	}
	var ordered []string
	for _, header := range response.Headers {
		if strings.EqualFold(header.Name, "X-Order") {
			ordered = append(ordered, string(header.Value))
		}
	}
	if strings.Join(ordered, ",") != "one,two" {
		t.Fatalf("ordered response headers: %v", ordered)
	}
	for _, expected := range []SSEEvent{{Data: "café\ntwo", Type: "price", ID: "first"}, {Data: "�", Type: "message"}} {
		event, err := response.Events.Next()
		if err != nil || event != expected || response.Events.LastEventID() != expected.ID {
			t.Fatalf("event: got %+v, %v; want %+v", event, err, expected)
		}
	}
	if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("unterminated event: %v", err)
	}
	if response.Events.LastEventID() != "before-eof" {
		t.Fatalf("committed EOF ID: %q", response.Events.LastEventID())
	}
	if delay, present := response.Events.RetryMilliseconds(); !present || delay != ^uint64(0) {
		t.Fatalf("retry field: %d, %v", delay, present)
	}
	if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("repeated EOF: %v", err)
	}
}

func TestEventsTransferAboveTheCompletionArenaWithoutTruncation(t *testing.T) {
	line := strings.Repeat("x", 60*1024)
	data := strings.Repeat("data: "+line+"\n", 6) + "\n"
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, data)
	}))
	defer peer.Close()
	response, err := newClient(t).Events(context.Background(), Request{Method: "GET", URL: peer.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	event, err := response.Events.Next()
	expected := strings.Join([]string{line, line, line, line, line, line}, "\n")
	if err != nil || event.Data != expected || event.Type != "message" {
		t.Fatalf("large event: %d bytes, %v", len(event.Data), err)
	}
	if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("large event EOF: %v", err)
	}
}

func TestEventsRejectInvalidResponsesAndDecodingLimits(t *testing.T) {
	for _, test := range []struct {
		name, contentType, encoding, body, failure string
		status                                     int
		limits                                     *SSELimits
	}{
		{name: "204", status: 204, contentType: "text/event-stream", failure: "sse_unexpected_status"},
		{name: "wrong-type", status: 200, contentType: "application/json", failure: "sse_invalid_content_type"},
		{name: "missing-type", status: 200, failure: "sse_invalid_content_type"},
		{name: "encoded", status: 200, contentType: "text/event-stream", encoding: "gzip", failure: "sse_unsupported_content_encoding"},
		{name: "line", status: 200, contentType: "text/event-stream", body: "data: too long\n\n", limits: &SSELimits{4, 128}, failure: "sse_line_too_long"},
		{name: "event", status: 200, contentType: "text/event-stream", body: "data: too long\n\n", limits: &SSELimits{128, 4}, failure: "sse_event_too_large"},
		{name: "zero", status: 200, contentType: "text/event-stream", body: "data: x\n\n", limits: &SSELimits{}, failure: "sse_line_too_long"},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.contentType != "" {
					w.Header().Set("Content-Type", test.contentType)
				}
				if test.encoding != "" {
					w.Header().Set("Content-Encoding", test.encoding)
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer peer.Close()
			response, err := newClient(t).Events(context.Background(), Request{Method: "GET", URL: peer.URL}, test.limits)
			if err == nil {
				defer response.Events.Close()
				_, err = response.Events.Next()
				if _, next := response.Events.Next(); !errors.Is(next, io.EOF) {
					t.Errorf("terminal error repeated: %v", next)
				}
			}
			if kind(err) != test.failure {
				t.Fatalf("failure: %v, want %s", err, test.failure)
			}
		})
	}
}

func TestEventsReleaseHandlesAfterRepeatedDecodingFailures(t *testing.T) {
	var hits atomic.Uint64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: too long\n\n")
	}))
	defer peer.Close()
	client := newClient(t)
	for index := range 68 {
		response, err := client.Events(context.Background(), Request{Method: "GET", URL: peer.URL}, &SSELimits{4, 128})
		if err != nil {
			t.Fatalf("request %d: %v", index, err)
		}
		if _, err := response.Events.Next(); kind(err) != "sse_line_too_long" {
			t.Fatalf("read %d: %v", index, err)
		}
	}
	response, err := client.Events(context.Background(), Request{Method: "GET", URL: peer.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Events.Close()
	if event, err := response.Events.Next(); err != nil || event.Data != "too long" {
		t.Fatalf("recovered event: %+v, %v", event, err)
	}
	if _, err := response.Events.Next(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if hits.Load() != 69 {
		t.Fatalf("requests: %d", hits.Load())
	}
}
