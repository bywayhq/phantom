package phantom

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"
)

func awaitWebSocketOperation(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		pump.mu.Lock()
		pending := len(pump.pending)
		pump.mu.Unlock()
		if pending != 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("WebSocket read was not admitted")
		}
		runtime.Gosched()
	}
}

func TestWebSocketConcurrentReadWriteAndShutdownRetry(t *testing.T) {
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	url, done, _ := websocketPeer(t, func(_ net.Conn, peer *bufio.ReadWriter, _ *http.Request) error {
		opcode, data, err := readWebSocketFrame(peer)
		if err != nil {
			return err
		}
		if opcode != 1 || string(data) != "during read" {
			return fmt.Errorf("concurrent write was lost")
		}
		select {
		case <-release:
		case <-time.After(10 * time.Second):
			return fmt.Errorf("test did not release WebSocket response")
		}
		if err := writeWebSocketFrame(peer, 1, true, data); err != nil {
			return err
		}
		if err := peer.Flush(); err != nil {
			return err
		}
		opcode, data, err = readWebSocketFrame(peer)
		if err != nil {
			return err
		}
		if opcode != 8 || len(data) != 0 {
			return fmt.Errorf("expected statusless Close")
		}
		if err := writeWebSocketFrame(peer, 8, true, nil); err != nil {
			return err
		}
		return peer.Flush()
	})
	client := newClient(t)
	socket, err := client.WebSocket(context.Background(), url, WebSocketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Abort()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type readResult struct {
		kind MessageType
		data []byte
		err  error
	}
	result := make(chan readResult, 1)
	go func() { kind, data, err := socket.Read(ctx); result <- readResult{kind, data, err} }()
	awaitWebSocketOperation(t)
	if _, _, err := socket.Read(ctx); kind(err) != "websocket_read_pending" {
		t.Fatalf("competing reader: %v", err)
	}
	if err := socket.Write(ctx, TextMessage, []byte("during read")); err != nil {
		t.Fatal(err)
	}
	closing, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if err := client.Shutdown(closing); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown did not retain active socket: %v", err)
	}
	close(release)
	select {
	case value := <-result:
		if value.err != nil || value.kind != TextMessage || string(value.data) != "during read" {
			t.Fatalf("retained read: %+v", value)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := socket.Close(ctx, nil); err != nil {
		t.Fatal(err)
	}
	_, _, err = socket.Read(ctx)
	var closed *WebSocketCloseError
	if !errors.As(err, &closed) || closed.Frame != nil {
		t.Fatalf("statusless close: %v", err)
	}
	awaitWebSocketPeer(t, done)
	if err := client.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketReadCancellationAndForkIsolation(t *testing.T) {
	url, done, _ := websocketPeer(t, func(_ net.Conn, peer *bufio.ReadWriter, _ *http.Request) error {
		_, err := peer.ReadByte()
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("cancelled read did not release transport: %w", err)
		}
		return nil
	})
	client := newClient(t)
	fork, err := client.Fork(SessionSharing{Cookies: true})
	if err != nil {
		t.Fatal(err)
	}
	defer fork.Close()
	socket, err := fork.WebSocket(context.Background(), url, WebSocketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Abort()
	if err := client.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, _, err := socket.Read(ctx); result <- err }()
	awaitWebSocketOperation(t)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled read did not settle")
	}
	if _, _, err := socket.Read(context.Background()); kind(err) != "websocket_closed" {
		t.Fatalf("cancelled socket reused: %v", err)
	}
	awaitWebSocketPeer(t, done)
	if err := fork.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
