package phantom

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkInputBoundariesBeforeNative(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	for _, test := range []struct {
		name  string
		input NetworkOptions
		want  string
	}{
		{"invalid address", NetworkOptions{LocalAddresses: []netip.Addr{{}}}, "invalid_network_address"},
		{"zone", NetworkOptions{HostOverrides: []HostOverride{{Host: "private.invalid", Addresses: []netip.Addr{netip.MustParseAddr("fe80::1%private")}}}}, "invalid_network_address"},
		{"UTF8", NetworkOptions{Interface: string([]byte{255})}, "invalid_network_options"},
		{"count", NetworkOptions{HostOverrides: make([]HostOverride, 1024), LocalAddresses: []netip.Addr{loopback}}, "input_limit"},
		{"address count", NetworkOptions{HostOverrides: []HostOverride{{Host: "private.invalid", Addresses: make([]netip.Addr, 1024)}}}, "input_limit"},
		{"bytes", NetworkOptions{Interface: strings.Repeat("x", 64*1024+1)}, "input_limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(Config{Network: &test.input})
			if kind(err) != test.want || strings.Contains(err.Error(), "private") {
				t.Fatalf("expected redacted %s before native invocation: %v", test.want, err)
			}
		})
	}
	if size, err := networkInputSize(&NetworkOptions{Interface: strings.Repeat("é", 32768)}); size != 64*1024 || err != nil {
		t.Fatalf("exact UTF8 byte limit: %d %v", size, err)
	}
	input := &NetworkOptions{HostOverrides: []HostOverride{{Host: "x", Addresses: make([]netip.Addr, 1022)}}, LocalAddresses: []netip.Addr{loopback}}
	for index := range input.HostOverrides[0].Addresses {
		input.HostOverrides[0].Addresses[index] = loopback
	}
	if _, err := networkInputSize(input); err != nil {
		t.Fatalf("combined 1024 entries: %v", err)
	}
}

func TestNetworkWireRetainsOrderedEmptyOverridesAndOwnsSlices(t *testing.T) {
	if networkWire(nil) != nil {
		t.Fatal("absent network changed")
	}
	zero, err := json.Marshal(networkWire(&NetworkOptions{}))
	if err != nil || string(zero) != "{}" {
		t.Fatalf("zero network: %s %v", zero, err)
	}
	input := &NetworkOptions{
		HostOverrides:  []HostOverride{{Host: "EXAMPLE.invalid", Addresses: []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}}, {Host: "example.invalid"}},
		LocalAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Interface: "loopback",
	}
	wire := networkWire(input)
	input.HostOverrides[0].Addresses[0] = netip.MustParseAddr("127.0.0.2")
	input.HostOverrides[1].Host = "changed.invalid"
	input.LocalAddresses[0] = netip.MustParseAddr("::1")
	data, err := json.Marshal(wire)
	want := `{"host_overrides":[{"host":"EXAMPLE.invalid","addresses":["::1","127.0.0.1"]},{"host":"example.invalid","addresses":[]}],"local_addresses":["127.0.0.1"],"interface":"loopback"}`
	if err != nil || string(data) != want {
		t.Fatalf("ordered owned wire: %s %v", data, err)
	}
}

const networkHost = "network.phantom.invalid"

type networkConnectionKey struct{}

// The peer's only DNS SAN is the logical name, independently of its socket IP.
func networkTLSPeer(t *testing.T, h2 bool, handler http.Handler) *httptest.Server {
	t.Helper()
	peer := httptest.NewUnstartedServer(handler)
	peer.EnableHTTP2 = h2
	peer.TLS = networkTLSConfig(t)
	peer.Config.ErrorLog = log.New(io.Discard, "", 0)
	var connections atomic.Uint64
	peer.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, networkConnectionKey{}, connections.Add(1))
	}
	peer.StartTLS()
	t.Cleanup(peer.Close)
	return peer
}

func networkTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: networkHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{networkHost},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func TestUnixSocketInputAndOwnedWireBeforeNative(t *testing.T) {
	for _, path := range []string{"", "private\x00socket", string([]byte{255})} {
		_, err := New(Config{Network: &NetworkOptions{UnixSocket: &path}})
		if kind(err) != "invalid_network_options" || strings.Contains(fmt.Sprint(err), "private") {
			t.Fatalf("invalid socket path before native: %v", err)
		}
	}
	path := strings.Repeat("é", 32768)
	if size, err := networkInputSize(&NetworkOptions{UnixSocket: &path}); err != nil || size != 65536 {
		t.Fatalf("exact path byte bound: %d %v", size, err)
	}
	if _, err := networkInputSize(&NetworkOptions{UnixSocket: &path, Interface: "x"}); kind(err) != "input_limit" {
		t.Fatalf("combined path bound: %v", err)
	}
	path = "/private/original.sock"
	input := NetworkOptions{UnixSocket: &path}
	wire := networkWire(&input)
	path = "/private/changed.sock"
	data, err := json.Marshal(wire)
	if err != nil || string(data) != `{"unix_socket":"/private/original.sock"}` {
		t.Fatalf("owned socket path: %s %v", data, err)
	}
	for _, text := range []string{fmt.Sprint(input), fmt.Sprintf("%+v", &input), fmt.Sprintf("%#v", input)} {
		if strings.Contains(text, "private") || strings.Contains(text, "sock") {
			t.Fatalf("path leaked in formatting: %s", text)
		}
	}
}

func TestNetworkOverridesPreserveVerifiedHostSourceAndFork(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			type observation struct {
				Connection        uint64
				Host, SNI, Remote string
				Protocol          int
			}
			peer := networkTLSPeer(t, protocol == "h2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				connection, _ := r.Context().Value(networkConnectionKey{}).(uint64)
				if err := json.NewEncoder(w).Encode(observation{connection, r.Host, r.TLS.ServerName, r.RemoteAddr, r.ProtoMajor}); err != nil {
					t.Error(err)
				}
			}))
			_, port, err := net.SplitHostPort(peer.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			settings := &NetworkOptions{
				HostOverrides:  []HostOverride{{Host: strings.ToUpper(networkHost)}, {Host: networkHost, Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}},
				LocalAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")},
			}
			config := Config{Profile: profile, Protocol: protocol, AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Network: settings, Timeout: 5 * time.Second}
			client, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// New owns its configuration; later caller edits cannot replace it.
			settings.HostOverrides[1].Addresses[0] = netip.MustParseAddr("127.0.0.2")
			settings.LocalAddresses[1] = netip.MustParseAddr("::1")
			url := "https://" + networkHost + ":" + port + "/"
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
				if got.Connection == 0 {
					t.Fatal("missing peer connection identity")
				}
				host, _, err := net.SplitHostPort(got.Remote)
				major := 1
				if protocol == "h2" {
					major = 2
				}
				if err != nil || host != "127.0.0.1" || got.Host != networkHost+":"+port || got.SNI != networkHost || got.Protocol != major {
					t.Fatalf("logical identity/source/protocol changed: %+v %v", got, err)
				}
				return got
			}
			first := observe(client)
			if got := observe(client); got.Connection != first.Connection {
				t.Fatal("connection not reused")
			}
			child, err := client.Fork(SessionSharing{})
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if got := observe(child); got.Connection == first.Connection {
				t.Fatal("fork reused source pool")
			}
			key := [32]byte{7}
			snapshot, err := child.ExportSession(context.Background(), key)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := child.RestoreSession(context.Background(), snapshot, key, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			if err := child.Close(); err != nil {
				t.Fatal(err)
			}
			observe(restored)
			// Supplying the override never substitutes for normal certificate trust.
			config.Network = &NetworkOptions{HostOverrides: []HostOverride{{Host: networkHost, Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}}
			config.AdditionalRootsDER = nil
			untrusted, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer untrusted.Close()
			response, err := untrusted.Do(context.Background(), Request{Method: "GET", URL: url})
			if response != nil {
				_ = response.Body.Close()
			}
			if kind(err) != "tls" {
				t.Fatalf("untrusted override: %v", err)
			}
		})
	}
}

func TestNetworkEmptyOverrideAndIncompatibleSourceNeverConnect(t *testing.T) {
	var connections atomic.Int32
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected request") }))
	peer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	peer.Start()
	defer peer.Close()
	_, port, err := net.SplitHostPort(peer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		network NetworkOptions
		want    string
	}{
		{"empty last duplicate", NetworkOptions{HostOverrides: []HostOverride{
			{Host: networkHost, Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, {Host: strings.ToUpper(networkHost)},
		}}, "connect"},
		{"incompatible source", NetworkOptions{HostOverrides: []HostOverride{{Host: networkHost, Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}, LocalAddresses: []netip.Addr{netip.MustParseAddr("::1")}}, "connect"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := New(Config{Profile: profile, Protocol: "h1", Network: &test.network, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: "http://" + networkHost + ":" + port + "/"})
			if response != nil {
				_ = response.Body.Close()
			}
			if kind(err) != test.want {
				t.Fatalf("expected %s: %v", test.want, err)
			}
		})
	}
	if got := connections.Load(); got != 0 {
		t.Fatalf("unexpected unbound/default resolution fallback: %d connections", got)
	}
}

func TestNetworkCoreRejectsInvalidNamesBindingsAndInterface(t *testing.T) {
	for _, settings := range []NetworkOptions{
		{HostOverrides: []HostOverride{{Host: "127.0.0.1"}}},
		{HostOverrides: []HostOverride{{Host: "private.invalid/secret"}}},
		{LocalAddresses: []netip.Addr{netip.MustParseAddr("0.0.0.0")}},
		{LocalAddresses: []netip.Addr{netip.MustParseAddr("224.0.0.1")}},
		{Interface: "private\x00secret"},
	} {
		client, err := New(Config{Profile: profile, Protocol: "h1", Network: &settings})
		if client != nil {
			_ = client.Close()
		}
		if kind(err) != "invalid_client_configuration" || strings.Contains(fmt.Sprint(err), "private") {
			t.Fatalf("core policy error: %v", err)
		}
	}
}

func TestPublicOnlyDeniesLiteralAndOverriddenLoopback(t *testing.T) {
	var connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("denied request reached peer") }))
	defer server.Close()
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	client, err := New(Config{Profile: profile, Protocol: "h1", Timeout: 5 * time.Second,
		Network: &NetworkOptions{PublicOnly: true, HostOverrides: []HostOverride{{Host: "network.invalid", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	port := server.Listener.Addr().(*net.TCPAddr).Port
	for _, host := range []string{"127.0.0.1", "network.invalid"} {
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: fmt.Sprintf("http://%s:%d/", host, port)})
		if response != nil {
			if err := response.Body.Close(); err != nil {
				t.Error(err)
			}
			t.Fatal("denied request returned a response")
		}
		if kind(err) != "destination_denied" {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if connections.Load() != 0 {
		t.Fatal("denied address was connected")
	}
}
