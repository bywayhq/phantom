//go:build unix

package phantom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type unixConnectionKey struct{}

// Keep paths short on macOS without depending on the checkout or TMPDIR length.
func unixSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "pu-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	return filepath.Join(directory, "s")
}

func unixHTTPPeer(t *testing.T, secure, h2 bool, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	path := unixSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	peer := httptest.NewUnstartedServer(handler)
	if err := peer.Listener.Close(); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	peer.Listener = listener
	var connections atomic.Uint64
	peer.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, unixConnectionKey{}, connections.Add(1))
	}
	peer.Config.ErrorLog = log.New(io.Discard, "", 0)
	peer.Config.ReadHeaderTimeout = 5 * time.Second
	if secure {
		peer.EnableHTTP2 = h2
		peer.TLS = networkTLSConfig(t)
		peer.StartTLS()
	} else {
		peer.Start()
	}
	t.Cleanup(peer.Close)
	return peer, path
}

func TestUnixSocketPreservesURLIdentityPoolsAndCheckpointPolicy(t *testing.T) {
	for _, mode := range []string{"plain", "tls-h1", "tls-h2"} {
		t.Run(mode, func(t *testing.T) {
			type observation struct {
				Connection                uint64
				Host, SNI, Method, Target string
				Protocol                  int
			}
			peer, path := unixHTTPPeer(t, mode != "plain", mode == "tls-h2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sni := ""
				if r.TLS != nil {
					sni = r.TLS.ServerName
				}
				if err := json.NewEncoder(w).Encode(observation{r.Context().Value(unixConnectionKey{}).(uint64), r.Host, sni, r.Method, r.RequestURI, r.ProtoMajor}); err != nil {
					t.Error(err)
				}
			}))
			protocol, scheme, major := "h1", "http", 1
			if mode != "plain" {
				scheme = "https"
			}
			if mode == "tls-h2" {
				protocol, major = "h2", 2
			}
			config := Config{Profile: profile, Protocol: protocol, Network: &NetworkOptions{UnixSocket: &path}, Timeout: 5 * time.Second}
			if mode != "plain" {
				config.AdditionalRootsDER = [][]byte{peer.Certificate().Raw}
			}
			client, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// Construction owns the path; it does not retain the caller's pointer.
			original := path
			path += ".changed"
			url := scheme + "://" + networkHost + "/literal?q=1"
			observe := func(owner *Client) observation {
				t.Helper()
				response, err := owner.Do(context.Background(), Request{Method: "GET", URL: url})
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := response.Body.ReadAll(2048)
				if err != nil {
					t.Fatal(err)
				}
				var got observation
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				wantSNI := ""
				if mode != "plain" {
					wantSNI = networkHost
				}
				if got.Host != networkHost || got.SNI != wantSNI || got.Method != "GET" || got.Target != "/literal?q=1" || got.Protocol != major || response.Protocol != protocol {
					t.Fatalf("Unix URL identity: %+v, protocol %s", got, response.Protocol)
				}
				return got
			}
			first := observe(client)
			if observe(client).Connection != first.Connection {
				t.Fatal("source connection was not reused")
			}
			child, err := client.Fork(SessionSharing{})
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			second := observe(child)
			if second.Connection == first.Connection {
				t.Fatal("fork shared source pool")
			}
			if err := child.Close(); err != nil {
				t.Fatal(err)
			}
			if observe(client).Connection != first.Connection {
				t.Fatal("closing fork changed source pool")
			}
			child, err = client.Fork(SessionSharing{})
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			observe(child)
			key := [32]byte{17}
			_, err = child.ExportSession(context.Background(), key)
			var snapshotError *SessionSnapshotError
			if !errors.As(err, &snapshotError) || snapshotError.Kind != "unsupported" {
				t.Fatalf("Unix export: %v", err)
			}
			ordinary, err := New(Config{Profile: profile, Protocol: "h1"})
			if err != nil {
				t.Fatal(err)
			}
			defer ordinary.Close()
			snapshot, err := ordinary.ExportSession(context.Background(), key)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := child.RestoreSession(context.Background(), snapshot, key, nil)
			if restored != nil {
				_ = restored.Close()
				t.Fatal("Unix restore unexpectedly published an owner")
			}
			if !errors.As(err, &snapshotError) || snapshotError.Kind != "unsupported" {
				t.Fatalf("Unix restore: %v", err)
			}
			if mode != "plain" {
				path = original
				untrusted := config
				untrusted.AdditionalRootsDER = nil
				for _, test := range []struct {
					config Config
					url    string
				}{{untrusted, url}, {config, "https://wrong.phantom.invalid/"}} {
					owner, err := New(test.config)
					if err != nil {
						t.Fatal(err)
					}
					response, err := owner.Do(context.Background(), Request{Method: "GET", URL: test.url})
					if response != nil {
						_ = response.Body.Close()
					}
					if closeError := owner.Close(); closeError != nil {
						t.Error(closeError)
					}
					if kind(err) != "tls" {
						t.Fatalf("Unix trust/hostname: %v", err)
					}
				}
			}
		})
	}
}

func TestUnixSocketNeverFallsBackAndRejectsConflictingPolicies(t *testing.T) {
	var hits atomic.Int32
	tcp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer tcp.Close()
	path := unixSocketPath(t)
	client, err := New(Config{Profile: profile, Protocol: "h1", Network: &NetworkOptions{UnixSocket: &path}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: tcp.URL})
	if response != nil {
		_ = response.Body.Close()
	}
	if kind(err) != "connect" || strings.Contains(err.Error(), path) || hits.Load() != 0 {
		t.Fatalf("missing Unix socket fallback/error: %v hits=%d", err, hits.Load())
	}
	for _, network := range []NetworkOptions{
		{UnixSocket: &path, HostOverrides: []HostOverride{{Host: networkHost}}},
		{UnixSocket: &path, LocalAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{UnixSocket: &path, Interface: "lo"},
	} {
		owner, err := New(Config{Profile: profile, Protocol: "h1", Network: &network})
		if owner != nil {
			_ = owner.Close()
		}
		if kind(err) != "invalid_client_configuration" {
			t.Fatalf("Unix conflicting policy: %v", err)
		}
	}
	owner, err := New(Config{Profile: profile, Protocol: "h1", Network: &NetworkOptions{UnixSocket: &path}, Proxy: tcp.URL})
	if owner != nil {
		_ = owner.Close()
	}
	if kind(err) != "invalid_client_configuration" {
		t.Fatalf("Unix proxy conflict: %v", err)
	}
	h3, err := New(Config{Profile: profile, Protocol: "h3", Network: &NetworkOptions{UnixSocket: &path}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer h3.Close()
	response, err = h3.Do(context.Background(), Request{Method: "GET", URL: "https://" + networkHost + "/"})
	if response != nil {
		_ = response.Body.Close()
	}
	if kind(err) != "protocol_unavailable" {
		t.Fatalf("Unix H3: %v", err)
	}
}

func TestUnixHTTP2CancellationPreservesLiveSibling(t *testing.T) {
	release := make(chan struct{})
	pending := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	peer, path := unixHTTPPeer(t, true, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pending" {
			close(pending)
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
				t.Error("pending peer request was not cancelled")
			}
			return
		}
		w.Header().Set("X-Connection", strconv.FormatUint(r.Context().Value(unixConnectionKey{}).(uint64), 10))
		w.Header().Set("Content-Length", "2")
		if _, err := io.WriteString(w, "a"); err != nil {
			t.Error(err)
			return
		}
		w.(http.Flusher).Flush()
		if r.URL.Path == "/selected" {
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
				t.Error("selected peer stream was not cancelled")
			}
			return
		}
		select {
		case <-release:
			if _, err := io.WriteString(w, "b"); err != nil {
				t.Error(err)
			}
		case <-r.Context().Done():
		}
	}))
	client, err := New(Config{Profile: profile, Protocol: "h2", Network: &NetworkOptions{UnixSocket: &path}, AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeouts: Timeouts{Connect: LimitTimeout(5 * time.Second), ResponseHead: LimitTimeout(5 * time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	selected, err := client.Do(ctx, Request{Method: "GET", URL: "https://" + networkHost + "/selected"})
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Body.Close()
	ctxSibling, cancelSibling := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelSibling()
	sibling, err := client.Do(ctxSibling, Request{Method: "GET", URL: "https://" + networkHost + "/sibling"})
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Body.Close()
	connection := func(response *Response) string {
		t.Helper()
		for _, field := range response.Headers {
			if strings.EqualFold(field.Name, "x-connection") {
				return string(field.Value)
			}
		}
		t.Fatal("missing connection identity")
		return ""
	}
	firstConnection := connection(selected)
	if connection(sibling) != firstConnection {
		t.Fatal("sibling opened a different connection")
	}
	prefix := make([]byte, 1)
	if _, err := io.ReadFull(sibling.Body, prefix); err != nil || string(prefix) != "a" {
		t.Fatalf("live sibling prefix: %q %v", prefix, err)
	}
	cancel()
	if _, err := selected.Body.ReadAll(16); !errors.Is(err, context.Canceled) {
		t.Fatalf("selected cancellation: %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	data, err := sibling.Body.ReadAll(16)
	if err != nil || string(data) != "b" {
		t.Fatalf("live sibling: %q %v", data, err)
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: "https://" + networkHost + "/reuse"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if connection(response) != firstConnection {
		t.Fatal("connection replaced after cancellation")
	}
	data, err = response.Body.ReadAll(16)
	if err != nil || string(data) != "ab" {
		t.Fatalf("connection reuse: %q %v", data, err)
	}
	pendingCtx, cancelPending := context.WithCancel(context.Background())
	defer cancelPending()
	type result struct {
		hadHead bool
		err     error
	}
	finished := make(chan result, 1)
	go func() {
		response, err := client.Do(pendingCtx, Request{Method: "GET", URL: "https://" + networkHost + "/pending"})
		if response != nil {
			err = errors.Join(err, response.Body.Close())
		}
		finished <- result{response != nil, err}
	}()
	select {
	case <-pending:
	case <-time.After(5 * time.Second):
		t.Fatal("pending request did not reach peer")
	}
	cancelPending()
	select {
	case got := <-finished:
		if got.hadHead || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("pending request cancellation: head=%v err=%v", got.hadHead, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending cancellation did not settle")
	}
}
