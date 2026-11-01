package phantom

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestStateTransferNativeRealTicketsResumeReceiverWithoutConsumingSource(t *testing.T) {
	peer := tlsPeer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 {
			t.Error("ticket peer did not negotiate TLS 1.3")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Every request needs a fresh handshake, so pool reuse cannot look like
		// successful ticket resumption. The TLS peer owns the independent oracle.
		w.Header().Set("Connection", "close")
		if _, err := fmt.Fprintf(w, "%t", request.TLS.DidResume); err != nil {
			t.Error(err)
		}
	}))
	config := Config{Profile: profile, Protocol: "h1", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeout: 5 * time.Second}
	source, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	receiver, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request := func(client *Client, want string) {
		t.Helper()
		response, err := client.Do(ctx, Request{Method: "GET", URL: peer.URL})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := response.Body.ReadAll(16)
		if err != nil || response.Protocol != "h1" || string(body) != want {
			t.Fatalf("peer resumption=%q want=%q protocol=%q: %v", body, want, response.Protocol, err)
		}
	}
	request(source, "false")
	key := [32]byte{42}
	ciphertext, err := source.ExportSessionTickets(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.ImportSessionTickets(ctx, ciphertext, key, nil); err != nil {
		t.Fatal(err)
	}
	request(receiver, "true")
	request(source, "true")
}

func TestStateTransferNativeRealRequestOnlyRouteRequiresExplicitReceivingRoute(t *testing.T) {
	resumptions := make(chan bool, 3)
	url, done, roots := websocketPeer(t, func(_ net.Conn, stream *bufio.ReadWriter, request *http.Request) error {
		if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 {
			return fmt.Errorf("route peer did not negotiate TLS 1.3")
		}
		if request.Header.Get("Proxy-Authorization") != "" {
			return fmt.Errorf("proxy credentials reached origin")
		}
		resumptions <- request.TLS.DidResume
		if err := writeWebSocketFrame(stream, 1, true, []byte("route")); err != nil {
			return err
		}
		return stream.Flush()
	}, true)
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	config := Config{Profile: profile, Protocol: "h1", Proxy: proxy.URL, AdditionalRootsDER: roots, Timeout: 5 * time.Second}
	source, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	receiver, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	direct := ""
	opening := func(client *Client, want bool) {
		t.Helper()
		if err := readWebSocketRoute(ctx, client, url, WebSocketOptions{Protocol: "h1", Proxy: &direct}); err != nil {
			t.Fatal(err)
		}
		awaitWebSocketPeer(t, done)
		select {
		case resumed := <-resumptions:
			if resumed != want {
				t.Fatalf("route resumption=%t want=%t", resumed, want)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// Direct is an opening-only override; both clients default to the proxy.
	opening(source, false)
	key := [32]byte{43}
	ciphertext, err := source.ExportSessionTickets(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	err = receiver.ImportSessionTickets(ctx, ciphertext, key, nil)
	var failure *StateTransferError
	if !errors.As(err, &failure) || failure.Kind != "session_ticket_policy" {
		t.Fatalf("request-only route silently admitted: %v", err)
	}
	if err := receiver.ImportSessionTickets(ctx, ciphertext, key, []SessionRoute{{}}); err != nil {
		t.Fatal(err)
	}
	opening(receiver, true)
	opening(source, true)
	if proxyHits.Load() != 0 {
		t.Fatalf("direct route changed or import performed I/O: %d proxy requests", proxyHits.Load())
	}
}
