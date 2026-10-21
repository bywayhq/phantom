package phantom

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
)

func responseTrailers(t *testing.T, response *Response, state ResponseTrailersState) []Header {
	t.Helper()
	result, err := response.Trailers()
	if err != nil || result.State != state {
		t.Fatalf("trailers state=%s, expected=%s: %v", result.State, state, err)
	}
	return result.Headers
}

func TestResponseTrailerCacheOwnsCopiesAndFirstTerminalWins(t *testing.T) {
	var complete responseTrailersCache
	if result, err := complete.snapshot(); err != nil || result.State != TrailersPending {
		t.Fatalf("initial state: %+v, %v", result, err)
	}
	complete.settle(ResponseTrailers{State: TrailersComplete, Headers: []Header{
		{Name: "X-One", Value: []byte{255}, Sensitive: true},
		{Name: "x-two", Value: []byte("second")},
		{Name: "X-One", Value: []byte("last")},
	}}, nil)
	complete.settle(ResponseTrailers{State: TrailersUnavailable}, context.Canceled)
	first, _ := complete.snapshot()
	first.Headers[0].Value[0], first.Headers[1].Name = 0, "changed"
	second, err := complete.snapshot()
	if err != nil || second.State != TrailersComplete || second.Headers[0].Value[0] != 255 ||
		!second.Headers[0].Sensitive || second.Headers[1].Name != "x-two" || second.Headers[2].Name != "X-One" {
		t.Fatalf("terminal metadata changed: %+v, %v", second, err)
	}
	var closed responseTrailersCache
	closed.settle(ResponseTrailers{State: TrailersUnavailable}, nil)
	closed.settle(ResponseTrailers{State: TrailersComplete}, nil)
	if result, _ := closed.snapshot(); result.State != TrailersUnavailable {
		t.Fatalf("abandonment became complete: %+v", result)
	}
	var race responseTrailersCache
	var workers sync.WaitGroup
	for index := 0; index < 20; index++ {
		workers.Go(func() {
			race.settle(ResponseTrailers{State: TrailersComplete, Headers: []Header{{Name: "x", Value: []byte("value")}}}, nil)
			value, _ := race.snapshot()
			value.Headers[0].Value[0] = 0
		})
	}
	workers.Wait()
	if result, _ := race.snapshot(); string(result.Headers[0].Value) != "value" {
		t.Fatal("concurrent snapshot changed retained bytes")
	}
}

func TestResponseTrailerProjectionRejectsUnknownOrIncompleteNativeMetadata(t *testing.T) {
	for _, test := range []struct{ data, kind string }{
		{`{"state":"complete","headers":[]}`, ""},
		{`{"state":"unavailable","headers":[]}`, ""},
		{`{"state":"future","headers":[]}`, "unsupported_response_trailers"},
		{`{"state":"pending","headers":[]}`, "unsupported_response_trailers"},
		{`{"state":"complete"}`, "native_abi"},
		{`{"state":"unavailable","headers":[{"name":"x","value":[1]}]}`, "native_abi"},
		{`null`, "native_abi"},
	} {
		if _, err := decodeResponseTrailers([]byte(test.data)); kind(err) != test.kind {
			t.Fatalf("metadata %s: %v", test.data, err)
		}
	}
	failure := &Error{Kind: "metadata_limit"}
	var cache responseTrailersCache
	cache.settle(ResponseTrailers{State: TrailersUnavailable}, trailerProjectionError(failure))
	if result, err := cache.snapshot(); result.State != TrailersUnavailable || !errors.Is(err, failure) {
		t.Fatalf("projection failure lost: %+v, %v", result, err)
	}
}

func TestHTTP1ResponseTrailersRetainRawOrderOnlyAfterEOF(t *testing.T) {
	url, done := requestBodyPeer(t, func(connection net.Conn, reader *bufio.Reader) error {
		if _, err := requestBodyHead(reader); err != nil {
			return err
		}
		_, err := io.WriteString(connection, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-One: first\r\nX-Two: \xff\r\nx-one: last\r\n\r\n")
		return err
	})
	client := newClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response, err := client.Do(ctx, Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseTrailers(t, response, TrailersPending)
	data := make([]byte, 2)
	if _, err := io.ReadFull(response.Body, data); err != nil || string(data) != "ok" {
		t.Fatalf("body %q: %v", data, err)
	}
	responseTrailers(t, response, TrailersPending)
	if n, err := response.Body.Read(data); n != 0 || err != io.EOF {
		t.Fatalf("EOF %d: %v", n, err)
	}
	expected := []Header{{Name: "X-One", Value: []byte("first")}, {Name: "X-Two", Value: []byte{255}}, {Name: "x-one", Value: []byte("last")}}
	if headers := responseTrailers(t, response, TrailersComplete); !reflect.DeepEqual(headers, expected) {
		t.Fatalf("wire order: %+v", headers)
	}
	// Neither cancellation nor repeated close after observed EOF invalidates it.
	cancel()
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := response.Body.ReadAll(-1); kind(err) != "invalid_body_limit" {
		t.Fatalf("post-EOF invalid collection limit: %v", err)
	}
	if headers := responseTrailers(t, response, TrailersComplete); !reflect.DeepEqual(headers, expected) {
		t.Fatalf("post-close trailers: %+v", headers)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHTTP1ResponseTrailersRequireSuccessfulContentDecoding(t *testing.T) {
	encoded := gzipBytes(t, []byte("ok"))
	for _, truncated := range []bool{false, true} {
		t.Run(fmt.Sprintf("truncated=%t", truncated), func(t *testing.T) {
			data := encoded
			if truncated {
				data = data[:len(data)-4]
			}
			url, done := requestBodyPeer(t, func(connection net.Conn, reader *bufio.Reader) error {
				if _, err := requestBodyHead(reader); err != nil {
					return err
				}
				wire := fmt.Sprintf("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n%x\r\n", len(data))
				wire += string(data) + "\r\n0\r\nX-End: retained\r\n\r\n"
				_, err := io.WriteString(connection, wire)
				return err
			})
			client := newClient(t)
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: url,
				Headers: []Header{{Name: "Accept-Encoding", Value: []byte("gzip")}}, ContentDecoding: AdvertisedDecoding(2)})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := response.Body.ReadAll(2)
			if truncated {
				if kind(err) != "content_decoding" {
					t.Fatalf("truncated coding: %v", err)
				}
				responseTrailers(t, response, TrailersUnavailable)
			} else {
				if err != nil || string(body) != "ok" {
					t.Fatalf("decoded body %q: %v", body, err)
				}
				headers := responseTrailers(t, response, TrailersComplete)
				if len(headers) != 1 || headers[0].Name != "X-End" || string(headers[0].Value) != "retained" {
					t.Fatalf("decoded trailers: %+v", headers)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTP1ResponseTrailerTerminalStates(t *testing.T) {
	for _, test := range []struct {
		name, wire string
		maximum    int
		close      bool
		state      ResponseTrailersState
		failure    string
	}{
		{"absent", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 2, false, TrailersComplete, ""},
		{"empty", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 0, false, TrailersComplete, ""},
		{"malformed", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\ninvalid trailer\r\n\r\n", 0, false, TrailersUnavailable, "http1"},
		{"limited", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-End: hidden\r\n\r\n", 1, false, TrailersUnavailable, "response_body_limit"},
		{"closed", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 2, true, TrailersUnavailable, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			url, done := requestBodyPeer(t, func(connection net.Conn, reader *bufio.Reader) error {
				if _, err := requestBodyHead(reader); err != nil {
					return err
				}
				_, err := io.WriteString(connection, test.wire)
				return err
			})
			client := newClient(t)
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: url})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if test.close {
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
			} else if _, err := response.Body.ReadAll(test.maximum); kind(err) != test.failure {
				t.Fatalf("body: %v", err)
			}
			if headers := responseTrailers(t, response, test.state); len(headers) != 0 {
				t.Fatalf("unexpected fields: %+v", headers)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
