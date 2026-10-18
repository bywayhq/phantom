package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCollectionAndStreamingVerifyContentAndLength(t *testing.T) {
	for _, mode := range []string{"collect", "stream"} {
		for _, body := range []string{"ZZZ", "ZZ", "ZZZZ", "ZXZ", ""} {
			c := validConfig()
			c.Consume, c.Bytes = mode, 3
			record := sample{}
			err := consumeBody(strings.NewReader(body), c, &record, time.Now())
			if (err == nil) != (body == "ZZZ") {
				t.Fatalf("%s %q: unexpected result %v", mode, body, err)
			}
			if mode == "collect" && record.FirstByteNS != nil {
				t.Fatal("collection invented a first-delivery timestamp")
			}
			if mode == "stream" && len(body) > 0 && record.FirstByteNS == nil {
				t.Fatal("nonempty stream omitted its first-delivery timestamp")
			}
		}
	}
}

type terminalReader struct{ err error }

func (r terminalReader) Read(buffer []byte) (int, error) {
	buffer[0] = 'Z'
	return 1, r.err
}

func TestStreamingRetainsDataReturnedWithEOFOrError(t *testing.T) {
	failed := errors.New("body interrupted")
	c := validConfig()
	c.Bytes = 1
	for _, terminal := range []error{io.EOF, failed} {
		record := sample{}
		err := consumeBody(terminalReader{terminal}, c, &record, time.Now())
		if record.Bytes != 1 || record.FirstByteNS == nil {
			t.Fatal("data accompanying terminal read was lost")
		}
		if terminal == failed && !errors.Is(err, failed) {
			t.Fatalf("body error was lost: %v", err)
		}
		if terminal == io.EOF && err != nil {
			t.Fatal(err)
		}
	}
}

func TestEmptyBodiesDoNotInventFirstDelivery(t *testing.T) {
	for _, mode := range []string{"collect", "stream"} {
		c := validConfig()
		c.Bytes, c.Consume = 0, mode
		record := sample{}
		if err := consumeBody(strings.NewReader(""), c, &record, time.Now()); err != nil {
			t.Fatal(err)
		}
		if record.FirstByteNS != nil {
			t.Fatal("empty body acquired a first-delivery timestamp")
		}
	}
}

func TestPublicSessionChecksTLSProtocolAndHeaderSelection(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, template := range []bool{false, true} {
			observed := make(chan *http.Request, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed <- r.Clone(r.Context())
				if _, err := io.WriteString(w, "ZZZ"); err != nil {
					t.Error(err)
				}
			}))
			server.EnableHTTP2 = protocol == "h2"
			server.StartTLS()
			c := validConfig()
			c.Protocol, c.Template, c.Bytes = protocol, template, 3
			r := ready{URLs: []string{server.URL}, RootDER: server.Certificate().Raw}
			shared, err := newClient(c, r)
			if err != nil {
				server.Close()
				t.Fatal(err)
			}
			record := sample{}
			execute(c, r, shared, &record)
			shared.Close()
			server.Close()
			if record.Error != nil {
				t.Fatalf("%s template=%t: %s", protocol, template, *record.Error)
			}
			if record.HeadNS == nil || record.Bytes != 3 {
				t.Fatalf("missing real response observation: %+v", record)
			}
			request := <-observed
			if (request.ProtoMajor == 2) != (protocol == "h2") {
				t.Fatalf("wrong peer protocol: %s", request.Proto)
			}
			if strings.Contains(request.UserAgent(), "Chrome/") != template {
				t.Fatalf("wrong automatic header selection: %v", request.Header)
			}
			if !template && (request.Header.Get("Sec-Ch-Ua") != "" || request.Header.Get("Sec-Fetch-Mode") != "") {
				t.Fatalf("unexpected browser headers: %v", request.Header)
			}
		}
	}
}

func TestUntrustedPeerFailsBeforeSendingHTTP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	wrongRoot, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"h1", "h2"} {
		observed := make(chan struct{}, 1)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { observed <- struct{}{} }))
		server.EnableHTTP2 = protocol == "h2"
		server.StartTLS()
		c := validConfig()
		c.Protocol = protocol
		shared, err := newClient(c, ready{URLs: []string{server.URL}, RootDER: wrongRoot})
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		record := sample{}
		execute(c, ready{URLs: []string{server.URL}}, shared, &record)
		shared.Close()
		server.Close()
		if record.Error == nil || record.HeadNS != nil {
			t.Fatalf("untrusted TLS peer accepted: %+v", record)
		}
		select {
		case <-observed:
			t.Fatal("HTTP was sent to an untrusted peer")
		default:
		}
	}
}
