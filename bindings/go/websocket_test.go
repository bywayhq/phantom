package phantom

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebSocketIncomingFailuresReleaseTheOwner(t *testing.T) {
	for _, test := range []struct {
		name    string
		opcode  byte
		payload []byte
		want    string
	}{
		{"invalid text", 1, []byte{255}, "websocket_invalid_utf8"},
		{"frame limit", 2, []byte("too large"), "websocket_capacity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			url, done, _ := websocketPeer(t, func(_ net.Conn, peer *bufio.ReadWriter, _ *http.Request) error {
				if err := writeWebSocketFrame(peer, test.opcode, true, test.payload); err != nil {
					return err
				}
				return peer.Flush()
			})
			client := newClient(t)
			socket, err := client.WebSocket(context.Background(), url, WebSocketOptions{Limits: &WebSocketLimits{4, 4, 2}})
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Abort()
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, _, err := socket.Read(ctx); kind(err) != test.want {
				t.Fatalf("invalid incoming frame: %v", err)
			}
			if _, _, err := socket.Read(ctx); kind(err) != "websocket_closed" {
				t.Fatalf("failed owner remained readable: %v", err)
			}
			awaitWebSocketPeer(t, done)
			if err := client.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// This RFC 6455 peer checks masked client frames independently of Rust framing.
func websocketPeer(t *testing.T, action func(net.Conn, *bufio.ReadWriter, *http.Request) error, secure ...bool) (string, <-chan error, [][]byte) {
	t.Helper()
	done := make(chan error, 1)
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		connection, stream, err := w.(http.Hijacker).Hijack()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			done <- err
			return
		}
		key := request.Header.Get("Sec-WebSocket-Key")
		if decoded, err := base64.StdEncoding.DecodeString(key); err != nil || len(decoded) != 16 {
			done <- fmt.Errorf("invalid opening key")
			return
		}
		accept := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		protocol := ""
		if request.Header.Get("Sec-WebSocket-Protocol") != "" {
			protocol = "Sec-WebSocket-Protocol: chat\r\n"
		}
		extensions := ""
		if request.Header.Get("Sec-WebSocket-Extensions") != "" {
			extensions = "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n"
		}
		_, err = fmt.Fprintf(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s%sX-Duplicate: one\r\nX-Duplicate: two\r\n\r\n", base64.StdEncoding.EncodeToString(accept[:]), protocol, extensions)
		if err == nil {
			err = stream.Flush()
		}
		if err == nil {
			err = action(connection, stream, request)
		}
		done <- err
	}))
	var roots [][]byte
	if len(secure) != 0 && secure[0] {
		peer.StartTLS()
		roots = [][]byte{peer.Certificate().Raw}
	} else {
		peer.Start()
	}
	t.Cleanup(peer.Close)
	return "ws" + strings.TrimPrefix(peer.URL, "http"), done, roots
}

func writeWebSocketFrame(writer io.Writer, opcode byte, final bool, payload []byte) error {
	first := opcode
	if final {
		first |= 128
	}
	header := []byte{first}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 65535:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		header = append(header, 127)
		header = binary.BigEndian.AppendUint64(header, uint64(len(payload)))
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

func readWebSocketFrame(reader io.Reader) (byte, []byte, error) {
	return readWebSocketFrameCompression(reader, false)
}
func readWebSocketFrameCompression(reader io.Reader, compressed bool) (byte, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil {
		return 0, nil, err
	}
	if head[0]&0x80 == 0 || (head[0]&0x70 != 0 && (!compressed || head[0]&0x70 != 0x40)) || head[1]&0x80 == 0 {
		return 0, nil, fmt.Errorf("invalid client framing")
	}
	length := uint64(head[1] & 127)
	if length == 126 {
		var size [2]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(size[:]))
	} else if length == 127 {
		var size [8]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(size[:])
	}
	if length > 10*1024*1024 {
		return 0, nil, fmt.Errorf("unbounded peer input")
	}
	var mask [4]byte
	if _, err := io.ReadFull(reader, mask[:]); err != nil {
		return 0, nil, err
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(reader, data); err != nil {
		return 0, nil, err
	}
	for i := range data {
		data[i] ^= mask[i%4]
	}
	return head[0] & 0x4f, data, nil
}

func awaitWebSocketPeer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("WebSocket peer did not settle")
	}
}

func TestWebSocketMessagesControlsAndLargeTransfer(t *testing.T) {
	large := bytes.Repeat([]byte{0, 255, 1}, 3*1024*1024)
	url, done, _ := websocketPeer(t, func(_ net.Conn, peer *bufio.ReadWriter, request *http.Request) error {
		if request.Header.Get("Sec-WebSocket-Extensions") != "" || request.Header.Get("X-Caller") != "value" {
			return fmt.Errorf("opening options: %v", request.Header)
		}
		if err := writeWebSocketFrame(peer, 1, false, []byte("hel")); err != nil {
			return err
		}
		if err := writeWebSocketFrame(peer, 0, true, []byte("lo")); err != nil {
			return err
		}
		if err := writeWebSocketFrame(peer, 9, true, []byte("automatic")); err != nil {
			return err
		}
		if err := peer.Flush(); err != nil {
			return err
		}
		opcode, data, err := readWebSocketFrame(peer)
		if err != nil {
			return err
		}
		if opcode != 10 || string(data) != "automatic" {
			return fmt.Errorf("missing automatic pong")
		}
		for _, expected := range []struct {
			opcode byte
			data   []byte
		}{{9, []byte("caller")}, {10, []byte("explicit")}, {2, large}, {2, nil}} {
			opcode, data, err := readWebSocketFrame(peer)
			if err != nil {
				return err
			}
			if opcode != expected.opcode || !bytes.Equal(data, expected.data) {
				return fmt.Errorf("unexpected client opcode %d, bytes %d", opcode, len(data))
			}
			if opcode == 9 {
				opcode = 10
			}
			if err := writeWebSocketFrame(peer, opcode, true, data); err != nil {
				return err
			}
			if err := peer.Flush(); err != nil {
				return err
			}
		}
		opcode, data, err = readWebSocketFrame(peer)
		if err != nil {
			return err
		}
		if opcode != 8 || !bytes.Equal(data, []byte{3, 232, 'd', 'o', 'n', 'e'}) {
			return fmt.Errorf("invalid close")
		}
		if err := writeWebSocketFrame(peer, 8, true, data); err != nil {
			return err
		}
		return peer.Flush()
	})
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	socket, err := client.WebSocket(ctx, url+"/chat", WebSocketOptions{Headers: []Header{{Name: "Sec-WebSocket-Protocol", Value: []byte("chat")}, {Name: "X-Caller", Value: []byte("value")}}})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Abort()
	metadata := socket.Handshake()
	if metadata.Status != 101 || metadata.Protocol != "h1" || metadata.SelectedProtocol != "chat" || metadata.Compression != nil {
		t.Fatalf("handshake: %+v", metadata)
	}
	var duplicate []string
	for _, header := range metadata.Headers {
		if strings.EqualFold(header.Name, "x-duplicate") {
			duplicate = append(duplicate, string(header.Value))
		}
	}
	if strings.Join(duplicate, ",") != "one,two" {
		t.Fatalf("ordered headers: %v", duplicate)
	}
	for _, expected := range []struct {
		kind MessageType
		data []byte
	}{{TextMessage, []byte("hello")}, {PingMessage, []byte("automatic")}} {
		kind, data, err := socket.Read(ctx)
		if err != nil || kind != expected.kind || !bytes.Equal(data, expected.data) {
			t.Fatalf("received %d %q %v", kind, data, err)
		}
	}
	for _, item := range []struct {
		send, receive MessageType
		data          []byte
	}{{PingMessage, PongMessage, []byte("caller")}, {PongMessage, PongMessage, []byte("explicit")}, {BinaryMessage, BinaryMessage, large}, {BinaryMessage, BinaryMessage, nil}} {
		if err := socket.Write(ctx, item.send, item.data); err != nil {
			t.Fatal(err)
		}
		kind, data, err := socket.Read(ctx)
		if err != nil || kind != item.receive || !bytes.Equal(data, item.data) {
			t.Fatalf("transfer type %d length %d: %v", kind, len(data), err)
		}
	}
	if err := socket.Close(ctx, &WebSocketCloseFrame{1000, "done"}); err != nil {
		t.Fatal(err)
	}
	_, _, err = socket.Read(ctx)
	var closed *WebSocketCloseError
	if !errors.As(err, &closed) || closed.Frame == nil || closed.Frame.Code != 1000 || closed.Frame.Reason != "done" {
		t.Fatalf("close: %v", err)
	}
	awaitWebSocketPeer(t, done)
}

func TestWebSocketRejectedBodySurvivesShutdownTimeout(t *testing.T) {
	content := strings.Repeat("denied", 60*1024)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("X-Duplicate", "one")
		w.Header().Add("X-Duplicate", "two")
		w.WriteHeader(403)
		_, _ = io.WriteString(w, content)
	}))
	defer peer.Close()
	client := newClient(t)
	_, err := client.WebSocket(context.Background(), "ws"+strings.TrimPrefix(peer.URL, "http"), WebSocketOptions{})
	var rejected *WebSocketHandshakeError
	if !errors.As(err, &rejected) || rejected.Response.Status != 403 || kind(err) != "websocket_handshake_rejected" {
		t.Fatalf("rejection: %v", err)
	}
	defer rejected.Response.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := client.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	body, err := rejected.Response.Body.ReadAll(len(content))
	if err != nil || string(body) != content {
		t.Fatalf("rejection body length %d: %v", len(body), err)
	}
	if err := client.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketTLSCompressionPolicyAndRoundTrip(t *testing.T) {
	text := bytes.Repeat([]byte("compressed message "), 128)
	url, done, roots := websocketPeer(t, func(_ net.Conn, peer *bufio.ReadWriter, request *http.Request) error {
		if request.Header.Get("Sec-WebSocket-Extensions") != "permessage-deflate; server_no_context_takeover; client_no_context_takeover" {
			return fmt.Errorf("compression offer %q", request.Header.Get("Sec-WebSocket-Extensions"))
		}
		opcode, encoded, err := readWebSocketFrameCompression(peer, true)
		if err != nil {
			return err
		}
		if opcode != 0x41 {
			return fmt.Errorf("message was not compressed")
		}
		// RFC 7692 removes the sync-flush tail. Supply a final empty block too,
		// so Go's independent raw DEFLATE reader observes a complete stream.
		input := append(append([]byte(nil), encoded...), 0, 0, 255, 255, 1, 0, 0, 255, 255)
		decoder := flate.NewReader(bytes.NewReader(input))
		decoded, err := io.ReadAll(io.LimitReader(decoder, 8192))
		closeError := decoder.Close()
		if err != nil || closeError != nil {
			return errors.Join(err, closeError)
		}
		if !bytes.Equal(decoded, text) {
			return fmt.Errorf("decompressed client message mismatch")
		}
		var output bytes.Buffer
		encoder, err := flate.NewWriter(&output, flate.DefaultCompression)
		if err != nil {
			return err
		}
		if _, err := encoder.Write(text); err != nil {
			return err
		}
		if err := encoder.Flush(); err != nil {
			return err
		}
		payload := append([]byte(nil), output.Bytes()[:output.Len()-4]...)
		if err := encoder.Close(); err != nil {
			return err
		}
		if err := writeWebSocketFrame(peer, 0x41, true, payload); err != nil {
			return err
		}
		if err := peer.Flush(); err != nil {
			return err
		}
		_, _, err = readWebSocketFrame(peer)
		if err != nil {
			return err
		}
		if err := writeWebSocketFrame(peer, 8, true, nil); err != nil {
			return err
		}
		return peer.Flush()
	}, true)
	client, err := New(Config{Profile: profile, Protocol: "h1", AdditionalRootsDER: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket, err := client.WebSocket(ctx, url, WebSocketOptions{Protocol: "h1", Deflate: &WebSocketDeflate{Parameters: []WebSocketDeflateParameter{{Kind: "serverNoContextTakeover"}, {Kind: "clientNoContextTakeover"}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Abort()
	compression := socket.Handshake().Compression
	if compression == nil || !compression.ServerNoContextTakeover || !compression.ClientNoContextTakeover || compression.ClientWindowBits != 15 || compression.ServerWindowBits != 15 {
		t.Fatalf("compression: %+v", compression)
	}
	if err := socket.Write(ctx, TextMessage, text); err != nil {
		t.Fatal(err)
	}
	if kind, data, err := socket.Read(ctx); err != nil || kind != TextMessage || !bytes.Equal(data, text) {
		t.Fatalf("decoded type %d bytes %d: %v", kind, len(data), err)
	}
	if err := socket.Close(ctx, nil); err != nil {
		t.Fatal(err)
	}
	_, _, err = socket.Read(ctx)
	var closed *WebSocketCloseError
	if !errors.As(err, &closed) || closed.Frame != nil {
		t.Fatalf("Close: %v", err)
	}
	awaitWebSocketPeer(t, done)
}
