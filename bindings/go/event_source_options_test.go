package phantom

import (
	"strings"
	"testing"
	"time"
)

func TestEventSourceOptionsRejectUnsupportedOrUnboundedInput(t *testing.T) {
	negative := -time.Nanosecond
	proxy := "http://proxy.example:8080"
	cases := []struct {
		name    string
		options EventSourceOptions
		kind    string
	}{
		{"protocol", EventSourceOptions{}, "invalid_event_source_protocol"},
		{"read-idle", EventSourceOptions{Protocol: "h1", Timeouts: Timeouts{ReadIdle: LimitTimeout(time.Second)}}, "event_source_read_idle_unsupported"},
		{"disabled-read-idle", EventSourceOptions{Protocol: "h1", Timeouts: Timeouts{ReadIdle: Timeout{Mode: TimeoutDisabled}}}, "event_source_read_idle_unsupported"},
		{"negative-idle", EventSourceOptions{Protocol: "h1", IdleTimeout: &negative}, "invalid_timeout"},
		{"oversized-line", EventSourceOptions{Protocol: "h1", Limits: &SSELimits{1024*1024 + 1, 128}}, "invalid_sse_limits"},
		{"credentials-without-proxy", EventSourceOptions{Protocol: "h1", ProxyCredentials: &ProxyCredentials{Username: "secret", Password: "secret"}}, "invalid_proxy_credentials"},
		{"zero-header", EventSourceOptions{Protocol: "h1", Headers: []SSEHeader{{}}}, "invalid_event_source_header"},
		{"many-headers", EventSourceOptions{Protocol: "h1", Headers: make([]SSEHeader, 257)}, "input_limit"},
		{"large-secret", EventSourceOptions{Protocol: "h1", Proxy: &proxy, ProxyCredentials: &ProxyCredentials{Password: strings.Repeat("s", 65536)}}, "input_limit"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := eventSourceOpeningValue(1, "http://example.test/", test.options)
			if kind(err) != test.kind {
				t.Fatalf("got %v, want %s", err, test.kind)
			}
		})
	}
}

func TestEventSourceOptionsRetainDefaultsAndExplicitZero(t *testing.T) {
	inherited, err := eventSourceOpeningValue(1, "http://example.test/", EventSourceOptions{Protocol: "h2"})
	if err != nil || inherited.descriptor.Flags != 0 || inherited.descriptor.HeadersPresent != 0 || inherited.descriptor.Line != 65536 || inherited.descriptor.Event != 1048576 {
		t.Fatalf("inherited: %+v, %v", inherited.descriptor, err)
	}
	zero := time.Duration(0)
	maximum := uint64(0)
	direct := ""
	explicit, err := eventSourceOpeningValue(1, "http://example.test/", EventSourceOptions{Protocol: "h3", Headers: []SSEHeader{}, IdleTimeout: &zero, InitialRetry: &zero, MinRetry: &zero, MaxReconnects: &maximum, Proxy: &direct, Timeouts: Timeouts{Total: LimitTimeout(0), Connect: Timeout{Mode: TimeoutDisabled}}})
	if err != nil || explicit.descriptor.Flags != 31 || explicit.descriptor.HeadersPresent != 1 || explicit.descriptor.Timeouts[1].Mode != 1 || explicit.descriptor.Timeouts[4].Mode != 2 {
		t.Fatalf("explicit: %+v, %v", explicit.descriptor, err)
	}
}
