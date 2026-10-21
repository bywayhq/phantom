package phantom

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSPKIPinLimitsFailBeforeLoadingNativeCode(t *testing.T) {
	for _, pins := range [][][32]byte{{}, make([][32]byte, 33)} {
		for _, proxy := range []bool{false, true} {
			config := Config{Profile: profile, Protocol: "h1"}
			want := "invalid_server_spki_pins"
			if proxy {
				config.ProxyServerSPKIPins = pins
				want = "invalid_proxy_server_spki_pins"
			} else {
				config.ServerSPKIPins = pins
			}
			if client, err := New(config); client != nil || kind(err) != want {
				t.Fatalf("invalid pin count: client=%v, error=%v", client, err)
			}
		}
	}
}

func TestSPKIPinsSupplementTrustAndRetainOwnedConfiguration(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			var hits atomic.Int32
			peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if (protocol == "h2") != (r.ProtoMajor == 2) {
					t.Error("request used the wrong protocol")
				}
				_, _ = io.WriteString(w, "pinned")
			}))
			peer.EnableHTTP2 = protocol == "h2"
			peer.Config.ErrorLog = log.New(io.Discard, "", 0)
			peer.StartTLS()
			defer peer.Close()
			good := sha256.Sum256(peer.Certificate().RawSubjectPublicKeyInfo)

			for _, scenario := range []struct {
				name    string
				trusted bool
				pins    [][32]byte
				want    string
			}{
				{"matching", true, [][32]byte{good}, ""},
				{"rotation", true, [][32]byte{{1}, good, good}, ""},
				{"wrong", true, [][32]byte{{2}}, "tls"},
				{"untrusted", false, [][32]byte{good}, "tls"},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					config := Config{Profile: profile, Protocol: protocol, ServerSPKIPins: scenario.pins, Timeout: 5 * time.Second}
					if scenario.trusted {
						config.AdditionalRootsDER = [][]byte{peer.Certificate().Raw}
					}
					client, err := New(config)
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					// New has copied the policy; later caller edits cannot change it.
					for index := range config.ServerSPKIPins {
						config.ServerSPKIPins[index] = [32]byte{3}
					}
					before := hits.Load()
					response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL})
					if scenario.want != "" {
						if response != nil || kind(err) != scenario.want || hits.Load() != before {
							t.Fatalf("failed verification sent HTTP: response=%v error=%v", response, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					data, err := response.Body.ReadAll(6)
					if err != nil || string(data) != "pinned" {
						t.Fatalf("verified response %q: %v", data, err)
					}
					fork, err := client.Fork(SessionSharing{Tickets: true})
					if err != nil {
						t.Fatal(err)
					}
					defer fork.Close()
					if err := client.Close(); err != nil {
						t.Fatal(err)
					}
					response, err = fork.Do(context.Background(), Request{Method: "GET", URL: peer.URL})
					if err != nil {
						t.Fatal(err)
					}
					if data, err := response.Body.ReadAll(6); err != nil || string(data) != "pinned" || hits.Load() != before+2 {
						t.Fatalf("fork lost pin policy: %q %v", data, err)
					}
				})
			}
		})
	}
}

func TestSPKIPinPolicyRejectsCleartextWithoutSending(t *testing.T) {
	var hits atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer peer.Close()
	for _, proxy := range []bool{false, true} {
		config := Config{Profile: profile, Protocol: "h1", Timeout: 5 * time.Second}
		if proxy {
			config.Proxy = peer.URL
			config.ProxyServerSPKIPins = [][32]byte{{1}}
		} else {
			config.ServerSPKIPins = [][32]byte{{1}}
		}
		client, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL})
		if response != nil || kind(err) != "server_pin_policy" || hits.Load() != 0 {
			t.Fatalf("plaintext pin policy admitted HTTP: %v %v", response, err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTPSProxySPKIPoliciesAndTrustStayIndependent(t *testing.T) {
	var originHits, proxyHits atomic.Int32
	origin := tlsPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials reached origin")
		}
		_, _ = io.WriteString(w, "origin")
	}))
	var tunnels sync.WaitGroup
	proxy := tlsPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		if r.Method != "CONNECT" || r.Host != strings.TrimPrefix(origin.URL, "https://") {
			t.Error("unexpected HTTPS proxy target")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		upstream, err := net.DialTimeout("tcp", strings.TrimPrefix(origin.URL, "https://"), 3*time.Second)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		if err := upstream.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		connection, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		tunnels.Add(1)
		defer tunnels.Done()
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := buffered.Flush(); err != nil {
			t.Error(err)
			return
		}
		// A rejected inner TLS handshake also tears down the byte relay.
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close(); close(done) }()
		_, _ = io.Copy(connection, upstream)
		_ = connection.Close()
		<-done
	}))
	defer func() {
		done := make(chan struct{})
		go func() { tunnels.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Error("HTTPS proxy tunnels did not settle")
		}
	}()
	originPin := sha256.Sum256(origin.Certificate().RawSubjectPublicKeyInfo)
	proxyPin := sha256.Sum256(proxy.Certificate().RawSubjectPublicKeyInfo)
	if originPin == proxyPin {
		t.Fatal("origin and proxy must have distinct keys")
	}
	for _, scenario := range []struct {
		name                  string
		originRoot, proxyRoot []byte
		originPin, proxyPin   [32]byte
		want                  string
		connects              int32
	}{
		{"matching", origin.Certificate().Raw, proxy.Certificate().Raw, originPin, proxyPin, "", 1},
		{"wrong-origin", origin.Certificate().Raw, proxy.Certificate().Raw, [32]byte{1}, proxyPin, "tls", 1},
		{"wrong-proxy", origin.Certificate().Raw, proxy.Certificate().Raw, originPin, [32]byte{2}, "proxy", 0},
		{"swapped-pins", origin.Certificate().Raw, proxy.Certificate().Raw, proxyPin, originPin, "proxy", 0},
		{"origin-trust-not-proxy-trust", proxy.Certificate().Raw, proxy.Certificate().Raw, originPin, proxyPin, "tls", 1},
		{"proxy-trust-not-origin-trust", origin.Certificate().Raw, origin.Certificate().Raw, originPin, proxyPin, "proxy", 0},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client, err := New(Config{Profile: profile, Protocol: "h1", Proxy: proxy.URL,
				AdditionalRootsDER: [][]byte{scenario.originRoot}, ProxyAdditionalRootsDER: [][]byte{scenario.proxyRoot},
				ServerSPKIPins: [][32]byte{scenario.originPin}, ProxyServerSPKIPins: [][32]byte{scenario.proxyPin}, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := client.Close(); err != nil {
					t.Error(err)
				}
			}()
			beforeOrigin, beforeProxy := originHits.Load(), proxyHits.Load()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: origin.URL})
			if scenario.want != "" {
				if response != nil || kind(err) != scenario.want {
					t.Fatalf("pin/trust failure: response=%v error=%v", response, err)
				}
				if originHits.Load() != beforeOrigin {
					t.Fatal("rejected origin received HTTP")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if data, err := response.Body.ReadAll(6); err != nil || string(data) != "origin" {
					t.Fatalf("tunnel body %q: %v", data, err)
				}
				if originHits.Load() != beforeOrigin+1 {
					t.Fatal("missing verified origin request")
				}
			}
			if proxyHits.Load() != beforeProxy+scenario.connects {
				t.Fatal("unexpected CONNECT count")
			}
		})
	}
}

func TestSPKIPinCheckpointCanonicalizationAndTransactionalRejection(t *testing.T) {
	key := [32]byte{17}
	url := "https://state.example/"
	first, second := [32]byte{1}, [32]byte{2}
	proxyFirst, proxySecond := [32]byte{3}, [32]byte{4}
	source, err := New(Config{Profile: profile, Protocol: "h1", ServerSPKIPins: [][32]byte{second, first, second}, ProxyServerSPKIPins: [][32]byte{proxySecond, proxyFirst, proxySecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	receiverConfig := Config{Profile: profile, Protocol: "h1", ServerSPKIPins: [][32]byte{first, second}, ProxyServerSPKIPins: [][32]byte{proxyFirst, proxySecond}}
	receiver, err := New(receiverConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	for _, populated := range []bool{false, true} {
		if populated {
			if err := source.SetCookie(url, "source=original; Secure; Path=/"); err != nil {
				t.Fatal(err)
			}
		}
		snapshot, err := source.ExportSession(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		if err := receiver.SetCookie(url, "receiver=untouched; Secure; Path=/"); err != nil {
			t.Fatal(err)
		}
		if populated {
			if err := source.SetCookie(url, "source=changed; Secure; Path=/"); err != nil {
				t.Fatal(err)
			}
		}
		child, err := receiver.RestoreSession(context.Background(), snapshot, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		expected := ""
		if populated {
			expected = "source=original"
		}
		if value, err := child.CookiesForURL(url); err != nil || value != expected {
			t.Fatalf("restored cookie %q: %v", value, err)
		}
		if err := child.Close(); err != nil {
			t.Fatal(err)
		}
		for _, changed := range []struct {
			name            string
			pins, proxyPins [][32]byte
		}{
			{"origin-absent", nil, receiverConfig.ProxyServerSPKIPins},
			{"origin-changed", [][32]byte{{9}}, receiverConfig.ProxyServerSPKIPins},
			{"proxy-absent", receiverConfig.ServerSPKIPins, nil},
			{"proxy-changed", receiverConfig.ServerSPKIPins, [][32]byte{{9}}},
		} {
			t.Run(changed.name, func(t *testing.T) {
				config := receiverConfig
				config.ServerSPKIPins, config.ProxyServerSPKIPins = changed.pins, changed.proxyPins
				recipient, err := New(config)
				if err != nil {
					t.Fatal(err)
				}
				defer recipient.Close()
				if err := recipient.SetCookie(url, "recipient=untouched; Secure; Path=/"); err != nil {
					t.Fatal(err)
				}
				restored, err := recipient.RestoreSession(context.Background(), snapshot, key, nil)
				var failure *SessionSnapshotError
				if restored != nil {
					_ = restored.Close()
					t.Fatal("failed restore published a client")
				}
				if !errors.As(err, &failure) || failure.Kind != "incompatible" {
					t.Fatalf("changed pin policy: %v", err)
				}
				if value, err := recipient.CookiesForURL(url); err != nil || value != "recipient=untouched" {
					t.Fatalf("recipient changed: %q %v", value, err)
				}
			})
		}
		if value, err := receiver.CookiesForURL(url); err != nil || value != "receiver=untouched" {
			t.Fatalf("receiver changed: %q %v", value, err)
		}
		expectedSource := ""
		if populated {
			expectedSource = "source=changed"
		}
		if value, err := source.CookiesForURL(url); err != nil || value != expectedSource {
			t.Fatalf("source changed: %q %v", value, err)
		}
	}
}
