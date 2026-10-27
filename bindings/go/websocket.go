package phantom

import (
	"context"
	"runtime"
	"sync/atomic"
	"unicode/utf8"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

// MessageType names complete messages, including observable control frames.
type MessageType uint8

const (
	TextMessage   MessageType = 2
	BinaryMessage MessageType = 3
	PingMessage   MessageType = 4
	PongMessage   MessageType = 5
)

// WebSocketCloseFrame is a peer or caller close status and UTF-8 reason.
// A nil frame represents a Close with no status, distinct from status 1000.
type WebSocketCloseFrame struct {
	Code   uint16
	Reason string
}

// WebSocketCloseError reports a received Close. Frame is nil without a status.
// The reason is available explicitly and omitted from the error text.
type WebSocketCloseError struct{ Frame *WebSocketCloseFrame }

func (*WebSocketCloseError) Error() string { return "phantom: websocket_close" }

// WebSocketHandshakeError owns a rejected opening's ordinary response. Read or
// close Response.Body. Unwrap exposes the native failure category.
type WebSocketHandshakeError struct {
	Response *Response
	cause    error
}

func (*WebSocketHandshakeError) Error() string         { return "phantom: websocket_handshake_rejected" }
func (failure *WebSocketHandshakeError) Unwrap() error { return failure.cause }

// WebSocketCompression describes the accepted RFC 7692 settings.
type WebSocketCompression struct {
	ServerNoContextTakeover, ClientNoContextTakeover bool
	ServerWindowBits, ClientWindowBits               uint8
}

// WebSocketHandshake preserves the accepted response's ordered fields.
type WebSocketHandshake struct {
	Status           int
	Protocol         string
	Headers          []Header
	SelectedProtocol string
	Compression      *WebSocketCompression
}

type websocketLifetime struct{ id atomic.Uint64 }

func (owner *websocketLifetime) abort() error {
	id := owner.id.Swap(0)
	if id == 0 {
		return nil
	}
	_, err := websocketOperation(3, id, 0, 0, nil)
	return err
}

// WebSocket allows one concurrent Read and one Write/Close. Competing operations
// in the same direction fail instead of queuing. There is no background reader,
// reconnect or heartbeat. Keep reading to handle Ping and the peer's Close.
type WebSocket struct {
	owner     *websocketLifetime
	client    *Client
	handshake WebSocketHandshake
}

// WebSocket opens a profile-policy or exact-protocol connection. ctx bounds
// setup only; later operations use their own contexts. Existing client route,
// trust, destination policy and cookies apply. Ordinary HTTP request templates,
// timeout/retry policies and caller attempt budgets do not apply to openings.
func (c *Client) WebSocket(ctx context.Context, url string, options WebSocketOptions) (*WebSocket, error) {
	if ctx == nil {
		return nil, &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil || c.closing.Load() || c.id.Load() == 0 {
		return nil, &Error{Kind: "client_closed"}
	}
	opening, err := websocketOpeningValue(c.id.Load(), url, options)
	if err != nil {
		return nil, err
	}
	if err := ensureNativeIdentity(); err != nil {
		return nil, err
	}
	if err := nativeBoundaryError(native.LoadWebSocket()); err != nil {
		return nil, err
	}
	var socket *WebSocket
	var rejection *Response
	err = performSubmitted(ctx, func() (uint64, error) {
		var reply native.Reply
		err := nativeBoundaryError(native.WebSocketOpen(&opening.descriptor, &reply))
		runtime.KeepAlive(opening)
		runtime.KeepAlive(options)
		runtime.KeepAlive(url)
		if err != nil {
			return 0, err
		}
		return reply.Operation, nativeRecordError(reply.Error)
	}, nil, func(event completion) error {
		if event.head == nil {
			return &Error{Kind: "native_abi"}
		}
		value, data, err := native.ReadWebSocketResult(event.Operation)
		if err != nil {
			return nativeBoundaryError(err)
		}
		head := event.head
		switch value.Kind {
		case 1:
			if !utf8.Valid(data) {
				return &Error{Kind: "native_abi"}
			}
			owner := &websocketLifetime{}
			owner.id.Store(head.Body)
			socket = &WebSocket{owner: owner, client: c, handshake: WebSocketHandshake{Status: head.Status, Protocol: head.Protocol, Headers: head.Headers, SelectedProtocol: string(data)}}
			if value.Compression != 0 {
				socket.handshake.Compression = &WebSocketCompression{ServerNoContextTakeover: value.Compression&2 != 0, ClientNoContextTakeover: value.Compression&4 != 0, ServerWindowBits: uint8(value.ServerWindow), ClientWindowBits: uint8(value.ClientWindow)}
			}
			runtime.SetFinalizer(socket, func(value *WebSocket) { _ = value.Abort() })
		case 7:
			rejection = &Response{Status: head.Status, Protocol: head.Protocol, Headers: head.Headers, Body: newBody(ctx, c, head.Body, nil), EffectiveURL: head.EffectiveURL}
		default:
			return &Error{Kind: "native_abi"}
		}
		return nil
	})
	runtime.KeepAlive(c)
	if err != nil {
		if socket != nil {
			_ = socket.Abort()
		}
		if rejection != nil {
			_ = rejection.Body.Close()
		}
		return nil, err
	}
	if rejection != nil {
		return nil, &WebSocketHandshakeError{Response: rejection, cause: &Error{Kind: "websocket_handshake_rejected"}}
	}
	return socket, nil
}

// Handshake returns an independent copy of the accepted opening metadata.
func (socket *WebSocket) Handshake() WebSocketHandshake {
	if socket == nil {
		return WebSocketHandshake{}
	}
	value := socket.handshake
	value.Headers = append([]Header(nil), value.Headers...)
	for i := range value.Headers {
		value.Headers[i].Value = append([]byte(nil), value.Headers[i].Value...)
	}
	if value.Compression != nil {
		compression := *value.Compression
		value.Compression = &compression
	}
	return value
}

// Read returns one complete text/binary/Ping/Pong message. Rust validates UTF-8,
// reassembles fragments and flushes automatic Ping/Close replies. A received
// Close returns *WebSocketCloseError; an unclean transport end is a native error.
// Cancellation after admission aborts this socket, preserving sibling streams.
func (socket *WebSocket) Read(ctx context.Context) (MessageType, []byte, error) {
	if err := socket.ready(ctx); err != nil {
		return 0, nil, err
	}
	var value native.WebSocketResult
	var data []byte
	admitted := false
	err := performSubmitted(ctx, func() (uint64, error) { return websocketOperation(1, socket.owner.id.Load(), 0, 0, nil) }, func() { admitted = true }, func(event completion) error {
		if event.kind != 1 {
			return &Error{Kind: "native_abi"}
		}
		var err error
		value, data, err = native.ReadWebSocketResult(event.Operation)
		if err != nil {
			return nativeBoundaryError(err)
		}
		if value.Kind < 2 || value.Kind > 6 || ((value.Kind == 2 || value.Kind == 6) && !utf8.Valid(data)) {
			return &Error{Kind: "native_abi"}
		}
		return nil
	})
	runtime.KeepAlive(socket)
	if err != nil {
		if admitted {
			_ = socket.Abort()
		}
		return 0, nil, err
	}
	if value.Kind == 6 {
		_ = socket.Abort()
		var frame *WebSocketCloseFrame
		if value.Code != 0 {
			frame = &WebSocketCloseFrame{Code: uint16(value.Code), Reason: string(data)}
		}
		return 0, nil, &WebSocketCloseError{Frame: frame}
	}
	return MessageType(value.Kind), data, nil
}

// Write sends and flushes a complete message. Ping/Pong payloads are at most
// 125 bytes. Cancellation after admission aborts this socket; never blindly
// resend a cancelled write because the peer may have received part or all of it.
func (socket *WebSocket) Write(ctx context.Context, kind MessageType, data []byte) error {
	if kind < TextMessage || kind > PongMessage {
		return &Error{Kind: "invalid_websocket_message"}
	}
	if len(data) > native.MaxWebSocketMessage || ((kind == PingMessage || kind == PongMessage) && len(data) > 125) {
		return &Error{Kind: "websocket_capacity"}
	}
	if kind == TextMessage && !utf8.Valid(data) {
		return &Error{Kind: "websocket_invalid_utf8"}
	}
	return socket.write(ctx, uint64(kind), 0, data)
}

// Close sends and flushes a Close frame. Continue Read to receive the peer's
// Close; this call alone does not complete the close handshake. Abort releases
// a connection immediately when you do not need to wait for the peer.
func (socket *WebSocket) Close(ctx context.Context, frame *WebSocketCloseFrame) error {
	if frame == nil {
		return socket.write(ctx, 6, 0, nil)
	}
	if !validWebSocketCloseCode(frame.Code) || !utf8.ValidString(frame.Reason) {
		return &Error{Kind: "invalid_websocket_close"}
	}
	if len(frame.Reason) > 123 {
		return &Error{Kind: "websocket_capacity"}
	}
	return socket.write(ctx, 6, uint64(frame.Code), []byte(frame.Reason))
}

// Abort immediately closes this socket and interrupts its pending operations.
// It is idempotent and safe concurrently with Read, Write and client shutdown.
func (socket *WebSocket) Abort() error {
	if socket == nil || socket.owner == nil {
		return nil
	}
	runtime.SetFinalizer(socket, nil)
	err := socket.owner.abort()
	runtime.KeepAlive(socket)
	return err
}

func (socket *WebSocket) ready(ctx context.Context) error {
	if ctx == nil {
		return &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if socket == nil || socket.owner == nil || socket.owner.id.Load() == 0 {
		return &Error{Kind: "websocket_closed"}
	}
	return nil
}

func (socket *WebSocket) write(ctx context.Context, kind, code uint64, data []byte) error {
	if err := socket.ready(ctx); err != nil {
		return err
	}
	admitted := false
	err := performSubmitted(ctx, func() (uint64, error) { return websocketOperation(2, socket.owner.id.Load(), kind, code, data) }, func() { admitted = true }, func(event completion) error {
		if event.kind != 1 {
			return &Error{Kind: "native_abi"}
		}
		return nil
	})
	runtime.KeepAlive(socket)
	if err != nil && admitted {
		_ = socket.Abort()
	}
	return err
}

func websocketOperation(verb, socket, kind, code uint64, data []byte) (uint64, error) {
	var reply native.Reply
	if err := nativeBoundaryError(native.WebSocketOperation(verb, socket, kind, code, data, &reply)); err != nil {
		return 0, err
	}
	return reply.Operation, nativeRecordError(reply.Error)
}

func validWebSocketCloseCode(code uint16) bool {
	return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1013) || (code >= 3000 && code <= 4999)
}
