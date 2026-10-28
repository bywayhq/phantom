package phantom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func dnsClient(t *testing.T, options DNSOptions, cacheDisabled bool) *Client {
	t.Helper()
	client, err := New(Config{Profile: profile, Protocol: "h1", Timeout: 8 * time.Second,
		Network: &NetworkOptions{DNS: options, DisableDNSCache: cacheDisabled}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func dnsOrigin(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if _, err := io.WriteString(w, "origin"); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "http://origin.phantom.invalid:" + port + "/", &hits
}

func TestNativeEncryptedDNSUsesIndependentHTTPSAndTLSPeers(t *testing.T) {
	for _, transport := range []string{"https-post", "https-get", "tls"} {
		t.Run(transport, func(t *testing.T) {
			method := DNSPost
			if transport == "https-get" {
				method = DNSGet
			}
			protocol := "https"
			if transport == "tls" {
				protocol = "tls"
			}
			peer := newEncryptedDNSPeer(t, protocol, method, "", 30, 0)
			options := peer.options()
			if https, ok := options.(*DNSOverHTTPS); ok {
				https.QueryID, https.Wire = 42, DNSChromium154
			}
			client := dnsClient(t, options, true)
			url, hits := dnsOrigin(t)
			if err := dnsRequest(t, client, context.Background(), url); err != nil {
				t.Fatal(err)
			}
			question := peer.wait(t, "origin.phantom.invalid")
			if question.kind != 1 || hits.Load() != 1 {
				t.Fatalf("one IPv4 lookup and origin request: %+v hits=%d", question, hits.Load())
			}
			if protocol == "https" {
				expected := "POST"
				if method == DNSGet {
					expected = "GET"
				}
				if question.method != expected || question.protocol != "HTTP/2.0" || question.id != 42 || question.size%128 != 0 || question.additional != 1 {
					t.Fatalf("DoH settings did not reach the wire: %+v", question)
				}
			}
			if err := client.RefreshConnections(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := dnsRequest(t, client, context.Background(), url); err != nil || peer.count("origin.phantom.invalid") != 2 {
				t.Fatalf("disabled address cache reused an answer: %v", err)
			}
		})
	}
}

func TestNativeEncryptedDNSCacheForkAndExpiry(t *testing.T) {
	for _, transport := range []string{"https", "tls"} {
		t.Run(transport, func(t *testing.T) {
			peer := newEncryptedDNSPeer(t, transport, DNSPost, "", 30, 0)
			client := dnsClient(t, peer.options(), false)
			url, _ := dnsOrigin(t)
			request := func(owner *Client) {
				t.Helper()
				if err := owner.RefreshConnections(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := dnsRequest(t, owner, context.Background(), url); err != nil {
					t.Fatal(err)
				}
			}
			request(client)
			shared, err := client.Fork(SessionSharing{DNS: true})
			if err != nil {
				t.Fatal(err)
			}
			defer shared.Close()
			request(shared)
			if got := peer.count("origin.phantom.invalid"); got != 1 {
				t.Fatalf("shared cache repeated lookup: %d", got)
			}
			independent, err := client.Fork(SessionSharing{})
			if err != nil {
				t.Fatal(err)
			}
			defer independent.Close()
			request(independent)
			if got := peer.count("origin.phantom.invalid"); got != 2 {
				t.Fatalf("independent cache reused answer: %d", got)
			}
			if err := client.ClearDNSCache(); err != nil {
				t.Fatal(err)
			}
			request(shared)
			if got := peer.count("origin.phantom.invalid"); got != 3 {
				t.Fatalf("shared cache clear did not propagate: %d", got)
			}
		})
	}
}

func TestNativeEncryptedDNSDoesNotExtendRecordTTL(t *testing.T) {
	for _, transport := range []string{"https", "tls"} {
		t.Run(transport, func(t *testing.T) {
			peer := newEncryptedDNSPeer(t, transport, DNSPost, "", 1, 0)
			client := dnsClient(t, peer.options(), false)
			url, _ := dnsOrigin(t)
			if err := dnsRequest(t, client, context.Background(), url); err != nil {
				t.Fatal(err)
			}
			time.Sleep(1100 * time.Millisecond) // Past the peer's one-second TTL.
			if err := client.RefreshConnections(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := dnsRequest(t, client, context.Background(), url); err != nil {
				t.Fatal(err)
			}
			if got := peer.count("origin.phantom.invalid"); got != 2 {
				t.Fatalf("DNS TTL was extended by profile cache settings: %d", got)
			}
		})
	}
}

func TestNativeEncryptedDNSCancelledLookupPreservesSiblingAndBody(t *testing.T) {
	for _, transport := range []string{"https", "tls"} {
		t.Run(transport, func(t *testing.T) {
			peer := newEncryptedDNSPeer(t, transport, DNSPost, "held.phantom.invalid", 30, 0)
			client := dnsClient(t, peer.options(), true)
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.WriteString(w, "live"); err != nil {
					t.Error(err)
				}
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer live.Close()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: live.URL, Context: "raw"})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			url, hits := dnsOrigin(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- dnsRequest(t, client, ctx, strings.Replace(url, "origin.", "held.", 1)) }()
			held := peer.wait(t, "held.phantom.invalid")
			if err := dnsRequest(t, client, context.Background(), url); err != nil {
				t.Fatalf("lookup sibling failed: %v", err)
			}
			sibling := peer.wait(t, "origin.phantom.invalid")
			if held.connection == 0 || held.connection != sibling.connection {
				t.Fatalf("lookups did not multiplex on one DNS connection: held=%d sibling=%d", held.connection, sibling.connection)
			}
			cancel()
			select {
			case err := <-finished:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("lookup cancellation: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled lookup did not complete")
			}
			buffer := make([]byte, 4)
			if _, err := io.ReadFull(response.Body, buffer); err != nil || string(buffer) != "live" || hits.Load() != 1 {
				t.Fatalf("unrelated active body was interrupted: %q %v hits=%d", buffer, err, hits.Load())
			}
			close(peer.release)
			if err := dnsRequest(t, client, context.Background(), url); err != nil {
				t.Fatalf("resolver unusable after cancellation: %v", err)
			}
		})
	}
}

func TestNativeEncryptedDNSOverridesAndProxyResolution(t *testing.T) {
	for _, transport := range []string{"https", "tls"} {
		t.Run(transport, func(t *testing.T) {
			peer := newEncryptedDNSPeer(t, transport, DNSPost, "", 30, 0)
			url, _ := dnsOrigin(t)
			client, err := New(Config{Profile: profile, Protocol: "h1", Timeout: 5 * time.Second,
				Network: &NetworkOptions{DNS: peer.options(), HostOverrides: []HostOverride{{Host: "origin.phantom.invalid", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := dnsRequest(t, client, context.Background(), url); err != nil || peer.count("origin.phantom.invalid") != 0 {
				t.Fatalf("override did not bypass DNS: %v", err)
			}
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Host != "proxy-resolved.phantom.invalid" {
					t.Errorf("wrong proxy destination: %s", r.URL.Host)
				}
				if _, err := io.WriteString(w, "origin"); err != nil {
					t.Error(err)
				}
			}))
			defer proxy.Close()
			_, port, err := net.SplitHostPort(proxy.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			proxied, err := New(Config{Profile: profile, Protocol: "h1", Proxy: "http://proxy.phantom.invalid:" + port,
				Timeout: 5 * time.Second, Network: &NetworkOptions{DNS: peer.options()}})
			if err != nil {
				t.Fatal(err)
			}
			defer proxied.Close()
			if err := dnsRequest(t, proxied, context.Background(), "http://proxy-resolved.phantom.invalid/"); err != nil {
				t.Fatal(err)
			}
			if peer.count("proxy.phantom.invalid") != 1 || peer.count("proxy-resolved.phantom.invalid") != 0 {
				t.Fatal("encrypted DNS did not respect proxy resolution boundary")
			}
		})
	}
}

func TestNativeEncryptedDNSDoesNotInheritApplicationTrustOrFollowRedirects(t *testing.T) {
	for _, transport := range []string{"https", "tls"} {
		t.Run(transport, func(t *testing.T) {
			peer := newEncryptedDNSPeer(t, transport, DNSPost, "", 30, 0)
			options := peer.options()
			var roots [][]byte
			switch dns := options.(type) {
			case *DNSOverHTTPS:
				roots, dns.AdditionalRootsDER = dns.AdditionalRootsDER, nil
			case *DNSOverTLS:
				roots, dns.AdditionalRootsDER = dns.AdditionalRootsDER, nil
			}
			client, err := New(Config{Profile: profile, Protocol: "h1", Timeout: 5 * time.Second, AdditionalRootsDER: roots,
				Network: &NetworkOptions{DNS: options}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			url, hits := dnsOrigin(t)
			if err := dnsRequest(t, client, context.Background(), url); kind(err) != "connect" || strings.Contains(fmt.Sprint(err), "private") {
				t.Fatalf("DNS endpoint inherited unrelated trust: %v", err)
			}
			if hits.Load() != 0 || peer.count("origin.phantom.invalid") != 0 {
				t.Fatal("unverified DNS reached the query or origin")
			}
		})
	}
	peer := newEncryptedDNSPeer(t, "https", DNSPost, "", 30, http.StatusFound)
	client := dnsClient(t, peer.options(), true)
	url, hits := dnsOrigin(t)
	if err := dnsRequest(t, client, context.Background(), url); kind(err) != "connect" {
		t.Fatalf("DoH redirect did not fail resolution: %v", err)
	}
	if hits.Load() != 0 || peer.count("origin.phantom.invalid") != 1 {
		t.Fatal("DoH redirect was followed or resolution fell back")
	}
}

func TestNativeEncryptedDNSBuildFailuresAndHTTP2Requirement(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*DNSOverHTTPS)
		want string
	}{
		{"credentials", func(dns *DNSOverHTTPS) { dns.Endpoint = "https://private:secret@dns.invalid/query" }, "invalid_dns_endpoint"},
		{"IP bootstrap identity", func(dns *DNSOverHTTPS) { dns.Endpoint = "https://127.0.0.2/query" }, "invalid_dns_bootstrap"},
		{"DER trust", func(dns *DNSOverHTTPS) { dns.AdditionalRootsDER = [][]byte{[]byte("private")} }, "invalid_dns_roots"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dns := validHTTPSDNS()
			test.edit(dns)
			client, err := New(Config{Profile: profile, Protocol: "h1", Network: &NetworkOptions{DNS: dns}})
			if client != nil {
				if closeErr := client.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if kind(err) != test.want || strings.Contains(fmt.Sprint(err), "private") {
				t.Fatalf("expected redacted %s: %v", test.want, err)
			}
		})
	}
	peer := networkTLSPeer(t, false, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("DoH silently fell back to HTTP/1")
	}))
	dns := validHTTPSDNS()
	dns.Endpoint = fmt.Sprintf("https://%s:%d/dns-query", networkHost, peer.Listener.Addr().(*net.TCPAddr).Port)
	dns.AdditionalRootsDER = [][]byte{peer.Certificate().Raw}
	client := dnsClient(t, dns, true)
	url, hits := dnsOrigin(t)
	if err := dnsRequest(t, client, context.Background(), url); kind(err) != "connect" || hits.Load() != 0 {
		t.Fatalf("missing HTTP/2 did not fail resolution: %v hits=%d", err, hits.Load())
	}
}

func TestNativeEncryptedDNSKeepsApplicationDestinationRestrictions(t *testing.T) {
	for _, transport := range []string{"https", "tls"} {
		t.Run(transport, func(t *testing.T) {
			peer := newEncryptedDNSPeer(t, transport, DNSPost, "", 30, 0)
			client, err := New(Config{Profile: profile, Protocol: "h1", Timeout: 5 * time.Second,
				Network: &NetworkOptions{DNS: peer.options(), PublicOnly: true}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			url, hits := dnsOrigin(t)
			if err := dnsRequest(t, client, context.Background(), url); err == nil {
				t.Fatal("DNS answer bypassed origin destination restrictions")
			}
			if hits.Load() != 0 || peer.count("origin.phantom.invalid") != 1 {
				t.Fatal("application restriction applied to DNS transport or failed to check its answer")
			}
		})
	}
}
