package phantom

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func websocketRouteProxy(t *testing.T, target string) (string, *atomic.Int32) {
	t.Helper()
	var tunnels atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != "CONNECT" || request.Host != target {
			t.Errorf("proxy received wrong tunnel: %s %s", request.Method, request.Host)
			w.WriteHeader(400)
			return
		}
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("route-user:route-secret"))
		if request.Header.Get("Proxy-Authorization") == "" {
			w.Header().Set("Proxy-Authenticate", `Basic realm="route-test"`)
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(407)
			return
		}
		if request.Header.Get("Proxy-Authorization") != expected {
			t.Error("proxy received incorrect route credentials")
			w.WriteHeader(403)
			return
		}
		upstream, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err != nil {
			t.Error(err)
			w.WriteHeader(502)
			return
		}
		defer upstream.Close()
		if err := upstream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		connection, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		tunnels.Add(1)
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := buffered.Flush(); err != nil {
			t.Error(err)
			return
		}
		done := make(chan struct{})
		go func() {
			// Either peer may close the tunnel after receiving the test frame.
			_, _ = io.Copy(upstream, buffered)
			_ = upstream.Close()
			close(done)
		}()
		// Abort and TLS shutdown can end either relay with a reset.
		_, _ = io.Copy(connection, upstream)
		_ = connection.Close()
		<-done
	}))
	t.Cleanup(peer.Close)
	return peer.URL, &tunnels
}

func websocketRouteOpening(t *testing.T, client *Client, url string, options WebSocketOptions) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := readWebSocketRoute(ctx, client, url, options); err != nil {
		t.Fatal(err)
	}
}

func readWebSocketRoute(ctx context.Context, client *Client, url string, options WebSocketOptions) error {
	socket, err := client.WebSocket(ctx, url, options)
	if err != nil {
		return err
	}
	defer socket.Abort()
	message, data, err := socket.Read(ctx)
	if err != nil {
		return fmt.Errorf("read routed socket frame: %w", err)
	}
	if message != TextMessage || string(data) != "route" {
		return fmt.Errorf("unexpected routed socket frame: %d %q", message, data)
	}
	return nil
}

func TestNativeWebSocketDirectOverridePreservesClientProxyDefault(t *testing.T) {
	url, done, roots := websocketPeer(t, func(_ net.Conn, peer *bufio.ReadWriter, request *http.Request) error {
		if request.Header.Get("Proxy-Authorization") != "" {
			return fmt.Errorf("proxy credentials reached the WebSocket origin")
		}
		if err := writeWebSocketFrame(peer, 1, true, []byte("route")); err != nil {
			return err
		}
		return peer.Flush()
	}, true)
	proxy, tunnels := websocketRouteProxy(t, strings.TrimPrefix(url, "wss://"))
	client, err := New(Config{Profile: profile, Protocol: "h1", Proxy: proxy,
		ProxyCredentials: &ProxyCredentials{Username: "route-user", Password: "route-secret"}, AdditionalRootsDER: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	direct := ""
	for _, test := range []struct {
		options WebSocketOptions
		tunnels int32
	}{{WebSocketOptions{Protocol: "h1"}, 1}, {WebSocketOptions{Protocol: "h1", Proxy: &direct}, 1}, {WebSocketOptions{Protocol: "h1"}, 2}} {
		websocketRouteOpening(t, client, url, test.options)
		awaitWebSocketPeer(t, done)
		if tunnels.Load() != test.tunnels {
			t.Fatalf("opening changed client route: tunnels=%d want=%d", tunnels.Load(), test.tunnels)
		}
	}
}

func TestNativeWebSocketProxyOverridePreservesDirectDefault(t *testing.T) {
	url, done, roots := websocketPeer(t, func(_ net.Conn, peer *bufio.ReadWriter, request *http.Request) error {
		if request.Header.Get("Proxy-Authorization") != "" {
			return fmt.Errorf("override credentials reached the WebSocket origin")
		}
		if err := writeWebSocketFrame(peer, 1, true, []byte("route")); err != nil {
			return err
		}
		return peer.Flush()
	}, true)
	proxy, tunnels := websocketRouteProxy(t, strings.TrimPrefix(url, "wss://"))
	client, err := New(Config{Profile: profile, Protocol: "h1", AdditionalRootsDER: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	websocketRouteOpening(t, client, url, WebSocketOptions{Protocol: "h1", Proxy: &proxy,
		ProxyCredentials: &ProxyCredentials{Username: "route-user", Password: "route-secret"}})
	awaitWebSocketPeer(t, done)
	websocketRouteOpening(t, client, url, WebSocketOptions{Protocol: "h1"})
	awaitWebSocketPeer(t, done)
	if tunnels.Load() != 1 {
		t.Fatalf("override changed direct client default: %d tunnels", tunnels.Load())
	}
	for _, proxy := range []string{"http://route-private:secret@127.0.0.1:bad", "private://127.0.0.1:1080"} {
		socket, err := client.WebSocket(context.Background(), url, WebSocketOptions{Protocol: "h1", Proxy: &proxy})
		if socket != nil {
			if abortErr := socket.Abort(); abortErr != nil {
				t.Error(abortErr)
			}
		}
		if err == nil || (kind(err) != "invalid_http_proxy" && kind(err) != "invalid_proxy_scheme") || strings.Contains(err.Error(), "private") {
			t.Fatalf("invalid route did not produce a redacted error: %v", err)
		}
	}
	if tunnels.Load() != 1 {
		t.Fatal("invalid override fell back to another proxy")
	}
}

func TestNativeWebSocketConcurrentRoutesRemainIsolated(t *testing.T) {
	url, done, roots := websocketPeer(t, func(_ net.Conn, peer *bufio.ReadWriter, request *http.Request) error {
		if request.Header.Get("Proxy-Authorization") != "" {
			return fmt.Errorf("proxy credentials reached the WebSocket origin")
		}
		if err := writeWebSocketFrame(peer, 1, true, []byte("route")); err != nil {
			return err
		}
		return peer.Flush()
	}, true)
	proxy, tunnels := websocketRouteProxy(t, strings.TrimPrefix(url, "wss://"))
	client, err := New(Config{Profile: profile, Protocol: "h1", AdditionalRootsDER: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 2)
	for _, options := range []WebSocketOptions{{Protocol: "h1"}, {Protocol: "h1", Proxy: &proxy,
		ProxyCredentials: &ProxyCredentials{Username: "route-user", Password: "route-secret"}}} {
		go func() { finished <- readWebSocketRoute(ctx, client, url, options) }()
	}
	for range 2 {
		select {
		case err := <-finished:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		awaitWebSocketPeer(t, done)
	}
	if tunnels.Load() != 1 {
		t.Fatalf("concurrent routes leaked: %d proxy tunnels", tunnels.Load())
	}
}
