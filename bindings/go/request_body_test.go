package phantom

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func requestBodyPeer(t *testing.T, exchange func(net.Conn, *bufio.Reader) error) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var accepted net.Conn
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		if accepted != nil {
			_ = accepted.Close()
		}
	})
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		mu.Lock()
		accepted = connection
		mu.Unlock()
		if err := connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
			done <- err
			return
		}
		done <- exchange(connection, bufio.NewReader(io.LimitReader(connection, 64*1024)))
	}()
	return "http://" + listener.Addr().String(), done
}

func requestBodyHead(reader *bufio.Reader) (string, error) {
	var head strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		head.WriteString(line)
		if line == "\r\n" {
			return head.String(), nil
		}
	}
}

func TestStaticTrailersKeepHTTP1SpellingDuplicateOrderAndChunkedFraming(t *testing.T) {
	url, done := requestBodyPeer(t, func(connection net.Conn, reader *bufio.Reader) error {
		head, err := requestBodyHead(reader)
		if err != nil {
			return err
		}
		lower := strings.ToLower(head)
		if !strings.Contains(lower, "\r\ntransfer-encoding: chunked\r\n") || strings.Contains(lower, "\r\ncontent-length:") {
			return fmt.Errorf("invalid trailer framing: %q", head)
		}
		var body strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			size, err := strconv.ParseUint(strings.TrimSuffix(line, "\r\n"), 16, 16)
			if err != nil || size > 32 {
				return fmt.Errorf("invalid fixture chunk: %q", line)
			}
			if size == 0 {
				break
			}
			data := make([]byte, int(size)+2)
			if _, err := io.ReadFull(reader, data); err != nil {
				return err
			}
			if string(data[len(data)-2:]) != "\r\n" || body.Len()+int(size) > 32 {
				return fmt.Errorf("invalid fixture data frame")
			}
			body.Write(data[:len(data)-2])
		}
		trailers, err := requestBodyHead(reader)
		if err != nil {
			return err
		}
		if body.String() != "hello" || trailers != "X-Proof: one\r\nx-other: two\r\nX-Proof: three\r\n\r\n" {
			return fmt.Errorf("body=%q trailers=%q", body.String(), trailers)
		}
		_, err = io.WriteString(connection, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		return err
	})
	client := newClient(t)
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: url, Body: []byte("hello"), Trailers: []Header{
		{Name: "X-Proof", Value: []byte("one"), Sensitive: true},
		{Name: "x-other", Value: []byte("two")},
		{Name: "X-Proof", Value: []byte("three")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := response.Body.ReadAll(0); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExpectContinueWaitsForPeerAndEarlyFinalSendsNoBody(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			url, done := requestBodyPeer(t, func(connection net.Conn, reader *bufio.Reader) error {
				head, err := requestBodyHead(reader)
				if err != nil {
					return err
				}
				if !strings.Contains(strings.ToLower(head), "\r\nexpect: 100-continue\r\n") {
					return fmt.Errorf("missing expectation: %q", head)
				}
				if err := connection.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
					return err
				}
				_, err = reader.Peek(1)
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					return fmt.Errorf("body did not wait for Continue: %v", err)
				}
				if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return err
				}
				if reject {
					if _, err := io.WriteString(connection, "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); err != nil {
						return err
					}
					var byte [1]byte
					count, err := reader.Read(byte[:])
					if count != 0 || err == nil {
						return fmt.Errorf("early final received body bytes")
					}
					if errors.As(err, &timeout) && timeout.Timeout() {
						return fmt.Errorf("early-final connection remained open: %w", err)
					}
					return nil
				}
				if _, err := io.WriteString(connection, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
					return err
				}
				body := make([]byte, 5)
				if _, err := io.ReadFull(reader, body); err != nil {
					return err
				}
				if string(body) != "hello" {
					return fmt.Errorf("unexpected upload %q", body)
				}
				_, err = io.WriteString(connection, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
				return err
			})
			client := newClient(t)
			source := &ownedUpload{Reader: strings.NewReader("hello")}
			wait, length := 4*time.Second, uint64(5)
			response, err := client.Do(context.Background(), Request{Method: "POST", URL: url, Upload: source, UploadLength: &length, ExpectContinue: &wait})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := response.Body.ReadAll(0); err != nil {
				t.Fatal(err)
			}
			if (response.Status == 417) != reject {
				t.Fatalf("unexpected status %d", response.Status)
			}
			waitUploadClosed(t, &source.closes)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvalidRequestBodyControlsPreserveAttemptBudget(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client := newClient(t)
	budget, err := NewAttemptBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	negative := -time.Nanosecond
	for _, test := range []struct {
		request Request
		kind    string
	}{
		{Request{ExpectContinue: &negative}, "invalid_expect_continue"},
		{Request{Trailers: make([]Header, 257)}, "input_limit"},
		{Request{Headers: make([]Header, 255), Trailers: make([]Header, 2)}, "input_limit"},
		{Request{Trailers: []Header{{Name: "x-proof", Value: []byte(strings.Repeat("a", 64*1024))}}}, "input_limit"},
		{Request{Trailers: []Header{{Name: "x-proof", Value: []byte("bad\r\nvalue")}}}, "invalid_header"},
		{Request{Trailers: []Header{{Name: "x-proof", Value: []byte("ok")}}, Headers: []Header{{Name: "Content-Length", Value: []byte("5")}}}, "http1"},
	} {
		test.request.Method, test.request.URL, test.request.Body, test.request.Budget = "POST", "http://"+listener.Addr().String(), []byte("hello"), budget
		if response, err := client.Do(context.Background(), test.request); response != nil || kind(err) != test.kind {
			t.Fatalf("expected %s, response=%v error=%v", test.kind, response, err)
		}
		if remaining, err := budget.Remaining(); err != nil || remaining != 1 {
			t.Fatalf("invalid input spent budget: remaining=%d error=%v", remaining, err)
		}
	}
	if err := listener.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if connection != nil {
		_ = connection.Close()
		t.Fatal("invalid request opened a connection")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("connection observation: %v", err)
	}
}

func TestZeroExpectWaitKeepsExplicitOptInAndEmptyBodyOmitsExpectation(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		expectation := ""
		if len(body) != 0 {
			expectation = "100-continue"
		}
		if request.Header.Get("Expect") != expectation {
			t.Errorf("body=%q expectation=%q", body, request.Header.Get("Expect"))
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer peer.Close()
	client := newClient(t)
	zero := time.Duration(0)
	for _, body := range [][]byte{nil, {}, []byte("hello")} {
		response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Body: body, ExpectContinue: &zero})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := response.Body.ReadAll(0); err != nil {
			t.Fatal(err)
		}
	}
}
