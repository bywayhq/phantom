package phantom

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTP2WebSocketReusesPoolAndCancelsOnlyItsStream(t *testing.T) {
	// Reuse Go's generated test identity with a raw HTTP/2 peer. The standard
	// server itself is not used because it does not enable extended CONNECT.
	identity := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	configuration := identity.TLS.Clone()
	configuration.NextProtos = []string{"h2"}
	root := identity.Certificate().Raw
	identity.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer := tls.NewListener(listener, configuration)
	done := make(chan error, 1)
	live := make(chan struct{})
	go func() { done <- serveHTTP2WebSocketPeer(peer, live) }()
	client, err := New(Config{Profile: profile, Protocol: "h2", AdditionalRootsDER: [][]byte{root}, Timeout: 8 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	url := "https://" + listener.Addr().String()
	request := func(path string) *Response {
		t.Helper()
		response, err := client.Do(ctx, Request{Method: "GET", URL: url + path})
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	body := func(response *Response, expected string) {
		t.Helper()
		defer response.Body.Close()
		data, err := response.Body.ReadAll(len(expected))
		if err != nil || string(data) != expected || response.Protocol != "h2" {
			t.Fatalf("response %q: %v", data, err)
		}
	}
	body(request("/warm"), "ok")
	// Empty selection uses the profile's policy and must reuse the warmed H2
	// connection advertising SETTINGS_ENABLE_CONNECT_PROTOCOL.
	socket, err := client.WebSocket(ctx, "wss://"+listener.Addr().String()+"/events", WebSocketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Abort()
	if head := socket.Handshake(); head.Protocol != "h2" || head.Status != 200 {
		t.Fatalf("handshake %+v", head)
	}
	if err := socket.Write(ctx, TextMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if kind, data, err := socket.Read(ctx); err != nil || kind != TextMessage || string(data) != "hello" {
		t.Fatalf("H2 message %d %q %v", kind, data, err)
	}
	reading, cancel := context.WithCancel(ctx)
	defer cancel()
	pending := make(chan error, 1)
	go func() { _, _, err := socket.Read(reading); pending <- err }()
	awaitWebSocketOperation(t)
	healthy := request("/healthy")
	defer healthy.Body.Close()
	select {
	case <-live:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	select {
	case err := <-pending:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	body(healthy, "healthy")
	body(request("/reuse"), "ok")
	if err := client.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	awaitWebSocketPeer(t, done)
}

func serveHTTP2WebSocketPeer(listener net.Listener, live chan<- struct{}) error {
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	preface := make([]byte, 24)
	if _, err := io.ReadFull(connection, preface); err != nil {
		return err
	}
	if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		return fmt.Errorf("invalid HTTP/2 preface")
	}
	write := func(kind, flags byte, stream uint32, data []byte) error {
		header := []byte{byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data)), kind, flags, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(header[5:], stream)
		if _, err := connection.Write(header); err != nil {
			return err
		}
		_, err := connection.Write(data)
		return err
	}
	if err := write(4, 0, 0, []byte{0, 8, 0, 0, 0, 1}); err != nil {
		return err
	}
	var websocket, sibling uint32
	count := 0
	cancelled := false
	var pending bytes.Buffer
	for {
		var header [9]byte
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			if errors.Is(err, io.EOF) && count == 4 && cancelled {
				return nil
			}
			return err
		}
		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		if length > 1024*1024 {
			return fmt.Errorf("unbounded HTTP/2 peer input")
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(connection, data); err != nil {
			return err
		}
		stream := binary.BigEndian.Uint32(header[5:]) & 0x7fffffff
		switch header[3] {
		case 4:
			if header[4]&1 == 0 {
				if err := write(4, 1, 0, nil); err != nil {
					return err
				}
			}
		case 6:
			if header[4]&1 == 0 {
				if err := write(6, 1, 0, data); err != nil {
					return err
				}
			}
		case 1:
			count++
			if err := write(1, 4, stream, []byte{0x88}); err != nil {
				return err
			}
			switch count {
			case 1:
				if err := write(0, 1, stream, []byte("ok")); err != nil {
					return err
				}
			case 2:
				websocket = stream
			case 3:
				sibling = stream
				if err := write(0, 0, stream, []byte("heal")); err != nil {
					return err
				}
				close(live)
			case 4:
				if !cancelled {
					return fmt.Errorf("reuse preceded selected-stream cancellation")
				}
				if err := write(0, 1, stream, []byte("ok")); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unexpected extra request")
			}
		case 0:
			if stream != websocket || header[4]&1 != 0 {
				return fmt.Errorf("unexpected HTTP/2 DATA")
			}
			pending.Write(data)
			if pending.Len() > 4096 {
				return fmt.Errorf("unbounded WebSocket input")
			}
			if pending.Len() >= 2 {
				wire := pending.Bytes()
				size := int(wire[1] & 127)
				if size >= 126 {
					return fmt.Errorf("expected a short client message")
				}
				if pending.Len() >= 6+size {
					opcode, payload, err := readWebSocketFrame(&pending)
					if err != nil {
						return err
					}
					if opcode != 1 || string(payload) != "hello" {
						return fmt.Errorf("unexpected WebSocket message")
					}
					var echo bytes.Buffer
					if err := writeWebSocketFrame(&echo, 1, true, payload); err != nil {
						return err
					}
					if err := write(0, 0, stream, echo.Bytes()); err != nil {
						return err
					}
				}
			}
		case 3:
			if stream != websocket || len(data) != 4 || binary.BigEndian.Uint32(data) != 8 || sibling == 0 {
				return fmt.Errorf("wrong stream or cancellation code")
			}
			cancelled = true
			if err := write(0, 1, sibling, []byte("thy")); err != nil {
				return err
			}
		}
	}
}
