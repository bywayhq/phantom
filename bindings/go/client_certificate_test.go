package phantom

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientCertificateInputLimitsWithoutNativeCode(t *testing.T) {
	for _, chain := range [][][]byte{nil, make([][]byte, 257)} {
		if owner, err := ParseClientCertificateDER(chain, nil); owner != nil || kind(err) != "client_certificate_invalid_chain_count" {
			t.Fatalf("chain bound: %v %v", owner, err)
		}
	}
	large := make([]byte, maxUpload+1)
	for _, input := range []struct{ chain, key []byte }{{large, nil}, {nil, large}, {large[:maxUpload], []byte{1}}} {
		if owner, err := ParseClientCertificatePEM(input.chain, input.key); owner != nil || kind(err) != "input_limit" {
			t.Fatalf("aggregate bound: %v %v", owner, err)
		}
	}
	owner := &ClientCertificate{}
	owner.id.Store(123)
	if fmt.Sprintf("%v %#v", owner, owner) != "phantom.ClientCertificate([redacted]) phantom.ClientCertificate([redacted])" {
		t.Fatal("owner formatting exposes state")
	}
	owner.id.Store(0)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	var absent *ClientCertificate
	if err := absent.Close(); err != nil {
		t.Fatal(err)
	}
	for _, config := range []Config{
		{ClientCertificate: owner},
		{ClientCertificatesFor: []ClientCertificateOrigin{{Origin: "https://example.test", Certificate: nil}}},
	} {
		if _, _, err := certificatesWire(config); kind(err) != "client_certificate_closed" {
			t.Fatalf("closed identity: %v", err)
		}
	}
	owner.id.Store(123)
	mappings := make([]ClientCertificateOrigin, 256)
	for index := range mappings {
		mappings[index] = ClientCertificateOrigin{Origin: "https://example.test", Certificate: owner}
	}
	if _, values, err := certificatesWire(Config{ClientCertificatesFor: mappings}); err != nil || len(values) != 256 {
		t.Fatalf("valid mapping boundary: %v", err)
	}
	for _, mappings := range [][]ClientCertificateOrigin{
		append(mappings, mappings[0]),
		{{Origin: strings.Repeat("x", 64*1024+1), Certificate: owner}},
		{{Origin: string([]byte{0xff}), Certificate: owner}},
	} {
		if _, _, err := certificatesWire(Config{ClientCertificatesFor: mappings}); err == nil {
			t.Fatal("invalid mapping accepted")
		}
	}
}

type clientIdentityFixture struct {
	ca, leaf, key []byte
	chainPEM      []byte
	keyPEM        []byte
}

// Only generated clientAuth keys exist in memory; no fixture/private-key files.
func newClientIdentityFixture(t *testing.T) clientIdentityFixture {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "client identity"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return clientIdentityFixture{caDER, leafDER, keyDER, chainPEM,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}
}

func (fixture clientIdentityFixture) parse(t *testing.T, der bool) *ClientCertificate {
	t.Helper()
	var owner *ClientCertificate
	var err error
	if der {
		owner, err = ParseClientCertificateDER([][]byte{fixture.leaf, fixture.ca}, fixture.key)
	} else {
		owner, err = ParseClientCertificatePEM(fixture.chainPEM, fixture.keyPEM)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	return owner
}

func clientIdentityPeer(t *testing.T, identity clientIdentityFixture, h2 bool, handler http.Handler) *httptest.Server {
	t.Helper()
	authority, err := x509.ParseCertificate(identity.ca)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	peer := httptest.NewUnstartedServer(handler)
	peer.EnableHTTP2 = h2
	peer.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	peer.Config.ErrorLog = log.New(io.Discard, "", 0)
	peer.StartTLS()
	t.Cleanup(peer.Close)
	return peer
}

func readClientIdentityResponse(t *testing.T, client *Client, url string) {
	t.Helper()
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatal(err)
	}
	data, err := response.Body.ReadAll(2)
	if err != nil || string(data) != "ok" {
		t.Fatalf("authenticated response %q: %v", data, err)
	}
}

func TestClientCertificateVerifiedPeersRetainOwnedIdentity(t *testing.T) {
	identity, wrongIdentity := newClientIdentityFixture(t), newClientIdentityFixture(t)
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			good := identity.parse(t, protocol == "h2")
			wrong := wrongIdentity.parse(t, false)
			var hits atomic.Int32
			var mu sync.Mutex
			connections := map[string]bool{}
			peer := clientIdentityPeer(t, identity, protocol == "h2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, identity.leaf) {
					t.Error("peer did not verify the selected client identity")
				}
				if (protocol == "h2") != (r.ProtoMajor == 2) {
					t.Error("wrong HTTP protocol")
				}
				hits.Add(1)
				mu.Lock()
				connections[r.RemoteAddr] = true
				mu.Unlock()
				_, _ = io.WriteString(w, "ok")
			}))
			config := Config{Profile: profile, Protocol: protocol, Timeout: 5 * time.Second,
				AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, ClientCertificate: wrong,
				ClientCertificatesFor: []ClientCertificateOrigin{{Origin: peer.URL, Certificate: wrong}, {Origin: peer.URL + "/", Certificate: good}}}
			client, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			fork, err := client.Fork(SessionSharing{Tickets: true})
			if err != nil {
				t.Fatal(err)
			}
			defer fork.Close()
			key := [32]byte{23}
			snapshot, err := client.ExportSession(context.Background(), key)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := client.RestoreSession(context.Background(), snapshot, key, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			if err := good.Close(); err != nil {
				t.Fatal(err)
			}
			if err := wrong.Close(); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				readClientIdentityResponse(t, client, peer.URL)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			readClientIdentityResponse(t, fork, peer.URL)
			readClientIdentityResponse(t, restored, peer.URL)
			mu.Lock()
			count := len(connections)
			mu.Unlock()
			if hits.Load() != 4 || count != 3 {
				t.Fatalf("identity/reuse/independent pools: requests=%d connections=%d", hits.Load(), count)
			}
		})
	}
}

func TestClientCertificateDefaultVerificationAndFailures(t *testing.T) {
	identity, other := newClientIdentityFixture(t), newClientIdentityFixture(t)
	good, wrong := identity.parse(t, false), other.parse(t, true)
	var hits atomic.Int32
	peer := clientIdentityPeer(t, identity, false, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	for _, scenario := range []struct {
		name     string
		owner    *ClientCertificate
		trusted  bool
		mappings []ClientCertificateOrigin
		want     string
	}{
		{"default", good, true, nil, ""},
		{"missing", nil, true, nil, "tls"},
		{"wrong", wrong, true, nil, "tls"},
		{"unmapped", nil, true, []ClientCertificateOrigin{{Origin: "https://unmapped.test", Certificate: good}}, "tls"},
		{"untrusted-server", good, false, nil, "tls"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			config := Config{Profile: profile, Protocol: "h1", Timeout: 5 * time.Second,
				ClientCertificate: scenario.owner, ClientCertificatesFor: scenario.mappings}
			if scenario.trusted {
				config.AdditionalRootsDER = [][]byte{peer.Certificate().Raw}
			}
			client, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			before := hits.Load()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL})
			if response != nil {
				_, err = response.Body.ReadAll(2)
			}
			if scenario.want == "" {
				if err != nil || response == nil || hits.Load() != before+1 {
					t.Fatalf("default identity: %v", err)
				}
			} else if err == nil || hits.Load() != before {
				t.Fatalf("rejected identity reached HTTP: %v", err)
			} else if value := kind(err); value != "tls" && value != "http1" {
				// TLS 1.3 rejection can arrive after the request head was returned.
				t.Fatalf("unexpected TLS rejection category: %v", err)
			}
		})
	}
	if owner, err := ParseClientCertificatePEM(identity.chainPEM, other.keyPEM); owner != nil || kind(err) != "client_certificate_key_mismatch" {
		t.Fatalf("mismatched key: %v %v", owner, err)
	}
	if owner, err := ParseClientCertificatePEM([]byte("private material"), identity.keyPEM); owner != nil || kind(err) != "client_certificate_certificate" || strings.Contains(fmt.Sprint(err), "private material") {
		t.Fatalf("redacted parse error: %v %v", owner, err)
	}
	if owner, err := ParseClientCertificatePEM(identity.chainPEM, []byte("private material")); owner != nil || kind(err) != "client_certificate_private_key" || strings.Contains(fmt.Sprint(err), "private material") {
		t.Fatalf("redacted key error: %v %v", owner, err)
	}
	if client, err := New(Config{Profile: profile, Protocol: "h1", ClientCertificatesFor: []ClientCertificateOrigin{{Origin: "https://secret.test/private", Certificate: good}}}); client != nil || kind(err) != "invalid_client_configuration" || strings.Contains(fmt.Sprint(err), "secret") {
		t.Fatalf("invalid origin: %v %v", client, err)
	}
}

func TestClientCertificateCheckpointIdentityIsTransactional(t *testing.T) {
	identity, other := newClientIdentityFixture(t), newClientIdentityFixture(t)
	pemOwner, derOwner, different := identity.parse(t, false), identity.parse(t, true), other.parse(t, false)
	key := [32]byte{41}
	url := "https://state.example/"
	source, err := New(Config{Profile: profile, Protocol: "h1", ClientCertificate: pemOwner})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	snapshot, err := source.ExportSession(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name     string
		owner    *ClientCertificate
		accepted bool
	}{
		{"same-chain-DER", derOwner, true}, {"changed", different, false}, {"absent", nil, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			receiver, err := New(Config{Profile: profile, Protocol: "h1", ClientCertificate: scenario.owner})
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			if err := receiver.SetCookie(url, "receiver=untouched; Secure; Path=/"); err != nil {
				t.Fatal(err)
			}
			restored, err := receiver.RestoreSession(context.Background(), snapshot, key, nil)
			if scenario.accepted {
				if err != nil {
					t.Fatal(err)
				}
				if value, err := restored.CookiesForURL(url); err != nil || value != "" {
					t.Fatalf("empty snapshot: %q %v", value, err)
				}
				if err := restored.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				var failure *SessionSnapshotError
				if restored != nil {
					_ = restored.Close()
					t.Fatal("failed restore published an owner")
				}
				if !errors.As(err, &failure) || failure.Kind != "incompatible" {
					t.Fatalf("identity policy: %v", err)
				}
			}
			if value, err := receiver.CookiesForURL(url); err != nil || value != "receiver=untouched" {
				t.Fatalf("receiver mutated: %q %v", value, err)
			}
		})
	}
	if sha256.Sum256(identity.leaf) == sha256.Sum256(other.leaf) {
		t.Fatal("distinct identities unexpectedly match")
	}
}
