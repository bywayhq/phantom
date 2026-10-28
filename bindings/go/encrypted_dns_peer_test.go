package phantom

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type dnsQuestion struct {
	host, method, protocol string
	id, kind               uint16
	size                   int
	additional             uint16
	connection             uint64
}

type encryptedDNSPeer struct {
	mu       sync.Mutex
	queries  []dnsQuestion
	arrivals chan dnsQuestion
	stop     chan struct{}
	release  chan struct{}
	heldHost string
	ttl      uint32
	status   int
	options  func() DNSOptions
}

// This peer implements just one uncompressed RFC 1035 question and an A answer.
// It validates the query independently of Phantom's DNS encoder and decoder.
func (peer *encryptedDNSPeer) answer(query []byte, method, protocol string, connection uint64) ([]byte, error) {
	if len(query) < 17 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, fmt.Errorf("invalid DNS question")
	}
	position := 12
	var labels []string
	for {
		if position >= len(query) {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(query[position])
		position++
		if length == 0 {
			break
		}
		if length > 63 || position+length > len(query) {
			return nil, fmt.Errorf("invalid DNS label")
		}
		labels = append(labels, string(query[position:position+length]))
		position += length
	}
	if position+4 > len(query) || binary.BigEndian.Uint16(query[position+2:position+4]) != 1 {
		return nil, fmt.Errorf("invalid DNS class")
	}
	question := dnsQuestion{host: strings.Join(labels, "."), kind: binary.BigEndian.Uint16(query[position : position+2]), id: binary.BigEndian.Uint16(query[:2]), method: method, protocol: protocol, size: len(query), additional: binary.BigEndian.Uint16(query[10:12]), connection: connection}
	peer.mu.Lock()
	peer.queries = append(peer.queries, question)
	peer.mu.Unlock()
	select {
	case peer.arrivals <- question:
	default:
		return nil, fmt.Errorf("DNS peer observation limit exceeded")
	}
	if question.host == peer.heldHost {
		select {
		case <-peer.release:
		case <-peer.stop:
			return nil, net.ErrClosed
		}
	}
	response := make([]byte, 12, position+20)
	copy(response[:2], query[:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[4:6], 1)
	response = append(response, query[12:position+4]...)
	if strings.HasPrefix(question.host, "missing.") {
		response[3] = 0x83
	} else if question.kind == 1 {
		binary.BigEndian.PutUint16(response[6:8], 1)
		answer := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1}
		binary.BigEndian.PutUint32(answer[6:10], peer.ttl)
		response = append(response, answer...)
	}
	return response, nil
}

func (peer *encryptedDNSPeer) count(host string) int {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	count := 0
	for _, question := range peer.queries {
		if question.host == host {
			count++
		}
	}
	return count
}

func (peer *encryptedDNSPeer) wait(t *testing.T, host string) dnsQuestion {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case question := <-peer.arrivals:
			if question.host == host {
				return question
			}
		case <-timer.C:
			t.Fatalf("DNS query for %s did not arrive", host)
			return dnsQuestion{}
		}
	}
}

func newEncryptedDNSPeer(t *testing.T, transport string, method DNSOverHTTPSMethod, heldHost string, ttl uint32, status int) *encryptedDNSPeer {
	t.Helper()
	peer := &encryptedDNSPeer{arrivals: make(chan dnsQuestion, 32), stop: make(chan struct{}), release: make(chan struct{}), heldHost: heldHost, ttl: ttl, status: status}
	if transport == "https" {
		server := networkTLSPeer(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var query []byte
			var err error
			if r.Method == "GET" {
				query, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			} else if r.Method == "POST" && r.Header.Get("Content-Type") == "application/dns-message" {
				query, err = io.ReadAll(io.LimitReader(r.Body, 65536))
			} else {
				t.Errorf("unexpected DNS HTTP request: %s", r.Method)
				w.WriteHeader(400)
				return
			}
			if err != nil || len(query) > 65535 || r.ProtoMajor != 2 || r.URL.Path != "/dns-query" {
				t.Errorf("invalid DoH query: %v", err)
				w.WriteHeader(400)
				return
			}
			connection, ok := r.Context().Value(networkConnectionKey{}).(uint64)
			if !ok {
				t.Error("DNS peer connection identity missing")
				w.WriteHeader(500)
				return
			}
			answer, err := peer.answer(query, r.Method, r.Proto, connection)
			if err != nil {
				select {
				case <-peer.stop:
				default:
					t.Errorf("decode DoH query: %v", err)
				}
				return // Cleanup releases held queries by closing stop.
			}
			w.Header().Set("Content-Type", "application/dns-message")
			if peer.status != 0 {
				w.Header().Set("Location", "/must-not-follow")
				w.WriteHeader(peer.status)
				return
			}
			if _, err := w.Write(answer); err != nil && r.Context().Err() == nil {
				t.Errorf("write DoH reply: %v", err)
			}
		}))
		port := server.Listener.Addr().(*net.TCPAddr).Port
		peer.options = func() DNSOptions {
			return &DNSOverHTTPS{Endpoint: fmt.Sprintf("https://%s:%d/dns-query", networkHost, port), Bootstrap: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, LookupTimeout: 5 * time.Second, MaxConcurrent: 4, Method: method, Families: DNSIPv4Only, AdditionalRootsDER: [][]byte{server.Certificate().Raw}}
		}
		t.Cleanup(func() { close(peer.stop) }) // Before httptest waits for handlers.
		return peer
	}
	settings := networkTLSConfig(t)
	settings.NextProtos = []string{"dot"}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", settings)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	workers.Go(func() {
		var sequence uint64
		for {
			connection, err := listener.Accept()
			if err != nil {
				return // Cleanup closes the listener.
			}
			mu.Lock()
			connections[connection] = struct{}{}
			mu.Unlock()
			sequence++
			connectionID := sequence
			workers.Go(func() {
				defer connection.Close()
				defer func() { mu.Lock(); delete(connections, connection); mu.Unlock() }()
				if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
					t.Errorf("bound DoT connection: %v", err)
					return
				}
				var writes sync.Mutex
				for {
					var length [2]byte
					if _, err := io.ReadFull(connection, length[:]); err != nil {
						return // Includes deliberate trust failures and client cancellation.
					}
					if size := binary.BigEndian.Uint16(length[:]); size < 17 {
						t.Error("short DoT frame")
						return
					}
					query := make([]byte, binary.BigEndian.Uint16(length[:]))
					if _, err := io.ReadFull(connection, query); err != nil {
						return // Client can cancel an incomplete frame.
					}
					if connection.(*tls.Conn).ConnectionState().NegotiatedProtocol != "dot" {
						t.Error("DoT ALPN was not dot")
						return
					}
					workers.Go(func() {
						answer, err := peer.answer(query, "", "dot", connectionID)
						if err != nil {
							select {
							case <-peer.stop:
							default:
								t.Errorf("decode DoT query: %v", err)
							}
							return // Cleanup releases held queries.
						}
						frame := make([]byte, 2, len(answer)+2)
						binary.BigEndian.PutUint16(frame, uint16(len(answer)))
						frame = append(frame, answer...)
						writes.Lock()
						defer writes.Unlock()
						_, err = io.Copy(connection, bytes.NewReader(frame))
						if err != nil {
							return // A canceled lookup can close its connection before the reply.
						}
					})
				}
			})
		}
	})
	peer.options = func() DNSOptions {
		return &DNSOverTLS{ServerName: networkHost, Bootstrap: []netip.AddrPort{netip.MustParseAddrPort(listener.Addr().String())}, LookupTimeout: 5 * time.Second, MaxConcurrent: 4, Families: DNSIPv4Only, AdditionalRootsDER: [][]byte{settings.Certificates[0].Certificate[0]}}
	}
	t.Cleanup(func() {
		close(peer.stop)
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
		mu.Lock()
		for connection := range connections {
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
		}
		mu.Unlock()
		workers.Wait()
	})
	return peer
}

func dnsRequest(t *testing.T, client *Client, ctx context.Context, url string) error {
	t.Helper()
	response, err := client.Do(ctx, Request{Method: "GET", URL: url, Context: "raw"})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := response.Body.ReadAll(1024)
	if err == nil && string(body) != "origin" {
		t.Errorf("unexpected origin body: %q", body)
	}
	return err
}
