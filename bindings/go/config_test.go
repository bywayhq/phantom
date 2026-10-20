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
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTimeoutModesRetainNanosecondsAndLegacyDefaults(t *testing.T) {
	for _, test := range []struct {
		value Timeout
		want  string
	}{
		{Timeout{}, `{"mode":"inherit"}`},
		{Timeout{Mode: TimeoutDisabled}, `{"mode":"disabled"}`},
		{LimitTimeout(0), `{"mode":"limit","nanoseconds":0}`},
		{LimitTimeout(7 * time.Nanosecond), `{"mode":"limit","nanoseconds":7}`},
	} {
		wire, err := timeoutWire(test.value)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(wire)
		if err != nil || string(data) != test.want {
			t.Fatalf("mode encoding %q, %v; want %s", data, err, test.want)
		}
	}
	for _, value := range []Timeout{{Mode: "other"}, {Duration: 1}, {Mode: TimeoutDisabled, Duration: 1}, LimitTimeout(-1)} {
		if _, err := timeoutWire(value); kind(err) != "invalid_timeout" {
			t.Fatalf("invalid mode accepted: %v", err)
		}
	}
	legacy, err := timeoutsWire(Timeouts{}, 1500*time.Microsecond)
	if err != nil || legacy.Total.Nanoseconds == nil || *legacy.Total.Nanoseconds != uint64(time.Millisecond) {
		t.Fatalf("legacy rounding: %v", err)
	}
	for _, test := range []struct {
		settings Timeouts
		legacy   time.Duration
	}{
		{Timeouts{}, time.Nanosecond},
		{Timeouts{Total: LimitTimeout(0)}, time.Second},
		{Timeouts{Total: Timeout{Mode: TimeoutDisabled}}, time.Second},
	} {
		if _, err := timeoutsWire(test.settings, test.legacy); kind(err) != "invalid_timeout" {
			t.Fatalf("ambiguous or invalid timeout: %v", err)
		}
	}
}

// Distinct self-signed CAs ensure origin and proxy roots cannot cover each other.
func tlsPeer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "loopback"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestAdditionalOriginRootsAndBaseURL(t *testing.T) {
	peer := tlsPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/api/a%2Fb?x=a%20b" {
			t.Errorf("request target %q", r.RequestURI)
		}
		_, _ = io.WriteString(w, "trusted")
	}))
	for _, trusted := range []bool{false, true} {
		config := Config{Profile: profile, Protocol: "h1", BaseURL: peer.URL + "/api/", Timeout: 5 * time.Second}
		if trusted {
			config.AdditionalRootsDER = [][]byte{peer.Certificate().Raw}
		}
		client, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: "a%2Fb?x=a%20b"})
		if !trusted {
			if kind(err) != "tls" {
				t.Errorf("untrusted peer: %v", err)
			}
		} else if err != nil {
			t.Error(err)
		} else if bytes, err := response.Body.ReadAll(7); err != nil || string(bytes) != "trusted" {
			t.Errorf("trusted body %q: %v", bytes, err)
		}
		if response != nil {
			_ = response.Body.Close()
		}
		if trusted {
			if removed, err := client.ClearSessionTickets(); err != nil || removed == 0 {
				t.Errorf("learned TLS tickets not cleared: %d %v", removed, err)
			}
			if removed, err := client.ClearSessionTickets(); err != nil || removed != 0 {
				t.Errorf("tickets survived clearing: %d %v", removed, err)
			}
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, config := range []Config{
		{Profile: profile, Protocol: "h1", BaseURL: "https://secret@example.com/"},
		{Profile: profile, Protocol: "h1", AdditionalRootsDER: [][]byte{[]byte("private invalid DER")}},
	} {
		_, err := New(config)
		if kind(err) != "invalid_base_url" && kind(err) != "invalid_trust_store" {
			t.Fatalf("configuration classification: %v", err)
		}
		if strings.Contains(fmt.Sprint(err), "secret") || strings.Contains(fmt.Sprint(err), "private") {
			t.Fatal("configuration error leaked input")
		}
	}
}

func TestHTTPSProxyRootsAndBasicCredentialsStaySeparate(t *testing.T) {
	origin := tlsPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "" {
			t.Error("proxy credentials reached origin")
		}
		_, _ = io.WriteString(w, "origin")
	}))
	proxy := tlsPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != strings.TrimPrefix(origin.URL, "https://") {
			t.Error("unexpected proxy target")
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Proxy-Authorization") == "" {
			w.Header().Set("Proxy-Authenticate", `Basic realm="loopback"`)
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(407)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpzZWNyZXQ=" {
			t.Error("incorrect Basic credentials")
			w.WriteHeader(403)
			return
		}
		upstream, err := net.DialTimeout("tcp", strings.TrimPrefix(origin.URL, "https://"), 3*time.Second)
		if err != nil {
			t.Error(err)
			w.WriteHeader(502)
			return
		}
		defer upstream.Close()
		_ = upstream.SetDeadline(time.Now().Add(8 * time.Second))
		connection, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := buffered.Flush(); err != nil {
			t.Error(err)
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close(); close(done) }()
		_, _ = io.Copy(connection, upstream)
		_ = connection.Close()
		<-done
	}))
	for _, roots := range []struct{ origin, proxy bool }{{false, true}, {true, false}, {true, true}} {
		config := Config{Profile: profile, Protocol: "h1", Proxy: proxy.URL, Timeout: 5 * time.Second,
			ProxyCredentials: &ProxyCredentials{Username: "user", Password: "secret"}}
		if roots.origin {
			config.AdditionalRootsDER = [][]byte{origin.Certificate().Raw}
		}
		if roots.proxy {
			config.ProxyAdditionalRootsDER = [][]byte{proxy.Certificate().Raw}
		}
		client, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: origin.URL})
		if !roots.origin || !roots.proxy {
			if kind(err) != "tls" && kind(err) != "proxy" {
				t.Errorf("missing trust: %v", err)
			}
		} else if err != nil {
			t.Error(err)
		} else if data, err := response.Body.ReadAll(6); err != nil || string(data) != "origin" {
			t.Errorf("tunnel body %q: %v", data, err)
		}
		if response != nil {
			_ = response.Body.Close()
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
	credentials := ProxyCredentials{Username: "private-user", Password: "private-password"}
	for _, formatted := range []string{fmt.Sprint(credentials), fmt.Sprintf("%+v", credentials), fmt.Sprintf("%#v", credentials),
		fmt.Sprintf("%+v", Config{ProxyCredentials: &credentials}), fmt.Sprintf("%#v", Config{ProxyCredentials: &credentials})} {
		if strings.Contains(formatted, "private") {
			t.Fatal("credential formatting leaked values")
		}
	}
	for _, proxy := range []string{"", "socks4://127.0.0.1:1"} {
		_, err := New(Config{Profile: profile, Protocol: "h1", Proxy: proxy, ProxyCredentials: &credentials})
		if kind(err) != "invalid_proxy_credentials" {
			t.Fatalf("credential route mismatch: %v", err)
		}
	}
}

func TestPhaseTimeoutInheritanceDisabledAndFiniteZero(t *testing.T) {
	release := make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/head" {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "a")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "b")
		case <-r.Context().Done():
		}
	}))
	defer peer.Close()
	client, err := New(Config{Profile: profile, Protocol: "h1", Timeouts: Timeouts{ReadIdle: LimitTimeout(0), Total: LimitTimeout(5 * time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = response.Body.ReadAll(2)
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != "timeout" || failure.TimeoutPhase != "read_idle" {
		t.Fatalf("inherited finite zero: %v", err)
	}
	response, err = client.Do(context.Background(), Request{Method: "GET", URL: peer.URL, Timeouts: Timeouts{ReadIdle: Timeout{Mode: TimeoutDisabled}}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	first := make([]byte, 1)
	if n, err := response.Body.Read(first); n != 1 || err != nil {
		t.Fatalf("first body byte: %d %v", n, err)
	}
	done := make(chan error, 1)
	go func() {
		data, err := response.Body.ReadAll(1)
		if err == nil && string(data) != "b" {
			err = fmt.Errorf("unexpected remaining body")
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("disabled timeout completed before peer released: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/head", Timeouts: Timeouts{ResponseHead: LimitTimeout(0)}})
	if !errors.As(err, &failure) || failure.Kind != "timeout" || failure.TimeoutPhase != "response_head" {
		t.Fatalf("explicit head zero: %v", err)
	}
}
