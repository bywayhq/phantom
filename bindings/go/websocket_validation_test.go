package phantom

import (
	"context"
	"errors"
	"testing"
	"time"
	"unsafe"
)

func TestWebSocketOpeningValidation(t *testing.T) {
	negative := -time.Second
	for _, test := range []struct {
		name    string
		options WebSocketOptions
		want    string
	}{
		{"protocol", WebSocketOptions{Protocol: "negotiated"}, "invalid_websocket_protocol"},
		{"frame exceeds message", WebSocketOptions{Limits: &WebSocketLimits{8, 4, 1}}, "invalid_websocket_limits"},
		{"zero fragments", WebSocketOptions{Limits: &WebSocketLimits{1, 1, 0}}, "invalid_websocket_limits"},
		{"oversized message", WebSocketOptions{Limits: &WebSocketLimits{1, 64*1024*1024 + 1, 1}}, "invalid_websocket_limits"},
		{"negative timeout", WebSocketOptions{HandshakeTimeout: &negative}, "invalid_timeout"},
		{"unused retry delay", WebSocketOptions{SetupRetryDelay: time.Second}, "invalid_websocket_retry"},
		{"placeholder with literal", WebSocketOptions{Template: []WebSocketHeader{{Kind: "key", Name: "Sec-WebSocket-Key", Value: []byte("fixed")}}}, "invalid_websocket_template"},
		{"unknown placeholder", WebSocketOptions{Template: []WebSocketHeader{{Kind: "maybe", Name: "X-Field"}}}, "invalid_websocket_template"},
		{"duplicate compression parameter", WebSocketOptions{Deflate: &WebSocketDeflate{Parameters: []WebSocketDeflateParameter{{Kind: "clientMaxWindowBits"}, {Kind: "clientMaxWindowBits", Bits: 15}}}}, "invalid_websocket_deflate"},
		{"server window without value", WebSocketOptions{Deflate: &WebSocketDeflate{Parameters: []WebSocketDeflateParameter{{Kind: "serverMaxWindowBits"}}}}, "invalid_websocket_deflate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := websocketOpeningValue(1, "ws://localhost/events", test.options)
			if kind(err) != test.want {
				t.Fatalf("got %v; want %s", err, test.want)
			}
		})
	}
}

func TestWebSocketOpeningPreservesFieldsAndExplicitChoices(t *testing.T) {
	zero := time.Duration(0)
	level := uint8(0)
	compressEmpty := false
	value, err := websocketOpeningValue(19, "wss://example.com/events", WebSocketOptions{
		Protocol: "h2", HandshakeTimeout: &zero,
		Headers:  []Header{{Name: "X-Token", Value: []byte{255}, Sensitive: true}},
		Template: []WebSocketHeader{{Kind: "caller", Name: "X-Token"}, {Kind: "field", Name: "sec-websocket-version", Value: []byte("13")}},
		Deflate:  &WebSocketDeflate{Parameters: []WebSocketDeflateParameter{{Kind: "serverNoContextTakeover"}, {Kind: "clientMaxWindowBits", Bits: 12}}, WindowBits: 13, Level: &level, CompressEmpty: &compressEmpty},
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.descriptor.Client != 19 || value.descriptor.Protocol != 2 || value.descriptor.Timeout.Mode != 1 || value.descriptor.Timeout.Nanoseconds != 0 {
		t.Fatalf("opening: %+v", value.descriptor)
	}
	if value.headers[0].Sensitive != 1 || string(unsafe.Slice((*byte)(value.headers[0].Name.Pointer), int(value.headers[0].Name.Length))) != "X-Token" {
		t.Fatal("ordered field spelling or sensitivity lost")
	}
	if value.template[0].Kind != 4 || value.template[1].Kind != 5 || value.descriptor.TemplatePresent != 1 {
		t.Fatal("template order lost")
	}
	if policy := value.descriptor.Deflate; policy.Flags != 1 || policy.Level != 0 || policy.Window != 13 || value.parameters[0].Kind != 1 || value.parameters[1].Bits != 12 {
		t.Fatalf("compression: %+v", policy)
	}
	for _, template := range [][]WebSocketHeader{nil, {}} {
		value, err := websocketOpeningValue(1, "ws://localhost/", WebSocketOptions{Template: template})
		if err != nil || value.descriptor.TemplatePresent != boolean(template != nil) {
			t.Fatalf("nil versus empty: %+v, %v", value.descriptor, err)
		}
	}
}

func TestWebSocketCancelledValidationLeavesOwnerUsable(t *testing.T) {
	owner := &websocketLifetime{}
	owner.id.Store(11)
	socket := &WebSocket{owner: owner}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := socket.Read(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := socket.Write(ctx, BinaryMessage, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if owner.id.Load() != 11 {
		t.Fatal("unadmitted cancellation aborted the socket")
	}
	if err := socket.Write(context.Background(), TextMessage, []byte{255}); kind(err) != "websocket_invalid_utf8" {
		t.Fatal(err)
	}
	if err := socket.Close(context.Background(), &WebSocketCloseFrame{Code: 1014}); kind(err) != "invalid_websocket_close" {
		t.Fatal(err)
	}
	if err := socket.Write(context.Background(), PingMessage, make([]byte, 126)); kind(err) != "websocket_capacity" {
		t.Fatal(err)
	}
	if owner.id.Load() != 11 {
		t.Fatal("invalid outbound message aborted the socket")
	}
}

func TestWebSocketMetadataCopyDoesNotExposeOwnerStorage(t *testing.T) {
	socket := &WebSocket{handshake: WebSocketHandshake{Status: 101, Protocol: "h1", Headers: []Header{{Name: "X-Choice", Value: []byte("first")}}, Compression: &WebSocketCompression{ClientWindowBits: 15}}}
	copy := socket.Handshake()
	copy.Headers[0].Name = "changed"
	copy.Headers[0].Value[0] = 'X'
	copy.Compression.ClientWindowBits = 8
	if string(socket.Handshake().Headers[0].Value) != "first" || socket.Handshake().Headers[0].Name != "X-Choice" || socket.Handshake().Compression.ClientWindowBits != 15 {
		t.Fatal("metadata mutation reached native owner")
	}
	var closeError *WebSocketCloseError
	if !errors.As(&WebSocketCloseError{Frame: &WebSocketCloseFrame{Code: 1000, Reason: "secret"}}, &closeError) || closeError.Error() != "phantom: websocket_close" {
		t.Fatal("close status must remain typed and redacted")
	}
}
