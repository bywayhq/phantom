package phantom

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func validHTTPSDNS() *DNSOverHTTPS {
	return &DNSOverHTTPS{Endpoint: "https://private.invalid/dns-query",
		Bootstrap:     []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		LookupTimeout: time.Second, MaxConcurrent: 2}
}

func TestEncryptedDNSInputsBeforeNative(t *testing.T) {
	var typedNil *DNSOverHTTPS
	for _, test := range []struct {
		name string
		edit func(*DNSOverHTTPS) DNSOptions
		want string
	}{
		{"nil", func(_ *DNSOverHTTPS) DNSOptions { return typedNil }, "invalid_dns"},
		{"bootstrap", func(v *DNSOverHTTPS) DNSOptions { v.Bootstrap = nil; return v }, "invalid_dns_bootstrap"},
		{"invalid address", func(v *DNSOverHTTPS) DNSOptions { v.Bootstrap[0] = netip.Addr{}; return v }, "invalid_dns_bootstrap"},
		{"scoped address", func(v *DNSOverHTTPS) DNSOptions { v.Bootstrap[0] = netip.MustParseAddr("fe80::1%private"); return v }, "invalid_dns_bootstrap"},
		{"timeout", func(v *DNSOverHTTPS) DNSOptions { v.LookupTimeout = 0; return v }, "invalid_dns_timeout"},
		{"negative timeout", func(v *DNSOverHTTPS) DNSOptions { v.LookupTimeout = -1; return v }, "invalid_dns_timeout"},
		{"concurrency", func(v *DNSOverHTTPS) DNSOptions { v.MaxConcurrent = 0; return v }, "invalid_dns_limits"},
		{"method", func(v *DNSOverHTTPS) DNSOptions { v.Method = "private"; return v }, "invalid_dns_method"},
		{"families", func(v *DNSOverHTTPS) DNSOptions { v.Families = "private"; return v }, "invalid_dns_families"},
		{"wire", func(v *DNSOverHTTPS) DNSOptions { v.Wire = "private"; return v }, "invalid_dns_wire"},
		{"identity", func(v *DNSOverHTTPS) DNSOptions { v.Endpoint = string([]byte{255}); return v }, "invalid_dns_identity"},
		{"identity bytes", func(v *DNSOverHTTPS) DNSOptions { v.Endpoint = strings.Repeat("x", 65537); return v }, "input_limit"},
		{"roots bytes", func(v *DNSOverHTTPS) DNSOptions { v.AdditionalRootsDER = [][]byte{make([]byte, 65536)}; return v }, "input_limit"},
		{"count", func(v *DNSOverHTTPS) DNSOptions { v.AdditionalRootsDER = make([][]byte, 1024); return v }, "input_limit"},
		{"TLS port", func(_ *DNSOverHTTPS) DNSOptions {
			return &DNSOverTLS{ServerName: "private.invalid", Bootstrap: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")}, LookupTimeout: time.Second, MaxConcurrent: 1}
		}, "invalid_dns_bootstrap"},
		{"TLS limit", func(_ *DNSOverHTTPS) DNSOptions {
			return &DNSOverTLS{ServerName: "private.invalid", Bootstrap: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:853")}, LookupTimeout: time.Second, MaxConcurrent: 32768}
		}, "invalid_dns_limits"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(Config{Network: &NetworkOptions{DNS: test.edit(validHTTPSDNS())}})
			if kind(err) != test.want || strings.Contains(err.Error(), "private") {
				t.Fatalf("expected redacted %s before loading native: %v", test.want, err)
			}
		})
	}
	if _, err := networkInputSize(&NetworkOptions{DNS: validHTTPSDNS(), HostOverrides: make([]HostOverride, 1024)}); kind(err) != "input_limit" {
		t.Fatalf("shared count limit: %v", err)
	}
	path := "/private/socket"
	if _, err := networkInputSize(&NetworkOptions{DNS: validHTTPSDNS(), UnixSocket: &path}); kind(err) != "invalid_network_options" {
		t.Fatalf("socket owns resolution: %v", err)
	}
}

func TestEncryptedDNSWireOwnsInputsAndExplicitPadding(t *testing.T) {
	block := uint16(128)
	input := validHTTPSDNS()
	input.AdditionalRootsDER = [][]byte{{0, 128, 255}}
	input.Wire, input.Method, input.Families = DNSChromium154, DNSGet, DNSIPv4Only
	input.QueryID, input.PaddingBlock = 42, &block
	if _, err := networkInputSize(&NetworkOptions{DNS: input}); err != nil {
		t.Fatal(err)
	}
	wire := networkWire(&NetworkOptions{DNS: input, DisableDNSCache: true})
	input.Endpoint = "changed"
	input.Bootstrap[0] = netip.MustParseAddr("127.0.0.2")
	input.AdditionalRootsDER[0][0] = 99
	block = 0
	encoded, err := json.Marshal(wire)
	want := `{"dns":{"kind":"https","endpoint":"https://private.invalid/dns-query","bootstrap":["127.0.0.1"],"timeout_ns":1000000000,"max_concurrent":2,"families":"ipv4","additional_roots_der":[[0,128,255]],"method":"get","wire":"chromium154","query_id":42,"padding_block":128},"disable_dns_cache":true}`
	if err != nil || string(encoded) != want {
		t.Fatalf("owned config: %s %v", encoded, err)
	}
	for _, padding := range []*uint16{nil, &block} {
		input = validHTTPSDNS()
		input.PaddingBlock = padding
		encoded, err = json.Marshal(dnsWire(input))
		if err != nil || strings.Contains(string(encoded), `"padding_block":0`) != (padding != nil) {
			t.Fatalf("inherit versus disabled padding: %s %v", encoded, err)
		}
	}
	for _, value := range []DNSOptions{input, &DNSOverTLS{ServerName: "private.invalid"}} {
		if strings.Contains(fmt.Sprintf("%v %#v", value, value), "private") {
			t.Fatal("DNS configuration leaked through formatting")
		}
	}
}
