package phantom

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// Only integer/string framing is needed: the sentinel values are one raw
// high byte, whose Huffman encoding is longer under this Chrome profile.
func hpackLiteralModes(block []byte) (map[byte]byte, error) {
	position := 0
	integer := func(prefix uint) (int, error) {
		if position >= len(block) {
			return 0, io.ErrUnexpectedEOF
		}
		mask := byte((1 << prefix) - 1)
		value := int(block[position] & mask)
		position++
		if value != int(mask) {
			return value, nil
		}
		for shift := uint(0); shift < 28; shift += 7 {
			if position >= len(block) {
				return 0, io.ErrUnexpectedEOF
			}
			next := block[position]
			position++
			value += int(next&127) << shift
			if next&128 == 0 {
				return value, nil
			}
		}
		return 0, fmt.Errorf("oversized HPACK integer")
	}
	stringValue := func() ([]byte, bool, error) {
		if position >= len(block) {
			return nil, false, io.ErrUnexpectedEOF
		}
		huffman := block[position]&128 != 0
		length, err := integer(7)
		if err != nil {
			return nil, false, err
		}
		if length > len(block)-position {
			return nil, false, io.ErrUnexpectedEOF
		}
		value := block[position : position+length]
		position += length
		return value, huffman, nil
	}
	modes := make(map[byte]byte)
	for position < len(block) {
		first := block[position]
		if first&128 != 0 {
			if _, err := integer(7); err != nil {
				return nil, err
			}
			continue
		}
		if first&0xe0 == 0x20 {
			if _, err := integer(5); err != nil {
				return nil, err
			}
			continue
		}
		prefix := uint(4)
		if first&0x40 != 0 {
			prefix = 6
		}
		name, err := integer(prefix)
		if err != nil {
			return nil, err
		}
		if name == 0 {
			if _, _, err := stringValue(); err != nil {
				return nil, err
			}
		}
		value, huffman, err := stringValue()
		if err != nil {
			return nil, err
		}
		if !huffman && len(value) == 1 && (value[0] == 255 || value[0] == 254) {
			modes[value[0]] = first & 0xf0
		}
	}
	return modes, nil
}

func TestSensitiveHeaderUsesHTTP2NeverIndexedLiteral(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	bodyConsumed := make(chan struct{})
	var client *Client
	defer func() {
		if client != nil {
			if err := client.Close(); err != nil {
				t.Error(err)
			}
		}
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(8 * time.Second):
			t.Error("H2 peer did not settle")
		}
	}()
	go func() {
		done <- func() error {
			connection, err := listener.Accept()
			if err != nil {
				return err
			}
			defer connection.Close()
			if err := connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
				return err
			}
			preface := make([]byte, 24)
			if _, err := io.ReadFull(connection, preface); err != nil {
				return err
			}
			if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
				return fmt.Errorf("invalid H2 preface")
			}
			writeFrame := func(kind, flags byte, stream uint32, data []byte) error {
				header := []byte{byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data)), kind, flags, 0, 0, 0, 0}
				binary.BigEndian.PutUint32(header[5:], stream)
				if _, err := connection.Write(header); err != nil {
					return err
				}
				_, err := connection.Write(data)
				return err
			}
			if err := writeFrame(4, 0, 0, nil); err != nil {
				return err
			}
			var block []byte
			var requestStream uint32
			responseSent := false
			for {
				header := make([]byte, 9)
				if _, err := io.ReadFull(connection, header); err != nil {
					if err == io.EOF && responseSent {
						select {
						case <-bodyConsumed:
							return nil
						default:
						}
					}
					return err
				}
				length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
				if length > 64*1024 {
					return fmt.Errorf("unbounded H2 fixture frame")
				}
				data := make([]byte, length)
				if _, err := io.ReadFull(connection, data); err != nil {
					return err
				}
				stream := binary.BigEndian.Uint32(header[5:]) & 0x7fffffff
				if header[3] == 4 && header[4]&1 == 0 {
					if err := writeFrame(4, 1, 0, nil); err != nil {
						return err
					}
				}
				if header[3] == 6 && header[4]&1 == 0 {
					if err := writeFrame(6, 1, 0, data); err != nil {
						return err
					}
				}
				if responseSent {
					continue
				}
				if header[3] != 1 && header[3] != 9 {
					continue
				}
				if header[3] == 1 {
					requestStream = stream
					if header[4]&8 != 0 {
						if len(data) == 0 || int(data[0])+1 > len(data) {
							return fmt.Errorf("invalid H2 padding")
						}
						data = data[1 : len(data)-int(data[0])]
					}
					if header[4]&0x20 != 0 {
						if len(data) < 5 {
							return fmt.Errorf("invalid H2 priority")
						}
						data = data[5:]
					}
				}
				if stream != requestStream || len(block)+len(data) > 64*1024 {
					return fmt.Errorf("unexpected H2 continuation")
				}
				block = append(block, data...)
				if header[4]&4 == 0 {
					continue
				}
				modes, err := hpackLiteralModes(block)
				if err != nil {
					return err
				}
				secret, secretFound := modes[255]
				public, publicFound := modes[254]
				if !secretFound || secret != 0x10 || !publicFound || public == 0x10 {
					return fmt.Errorf("sensitivity not reflected in HPACK literals: %v", modes)
				}
				if err := writeFrame(1, 4, requestStream, []byte{0x88}); err != nil {
					return err
				}
				if err := writeFrame(0, 1, requestStream, []byte("ok")); err != nil {
					return err
				}
				// Drain control frames until the caller consumes the body and closes
				// the client; closing here can reset unread response bytes on Windows.
				responseSent = true
			}
		}()
	}()
	client, err = New(Config{Profile: profile, Protocol: "h2", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: "http://" + listener.Addr().String(), Headers: []Header{
		{Name: "x-secret-flag", Value: []byte{255}, Sensitive: true},
		{Name: "x-public-flag", Value: []byte{254}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := response.Body.ReadAll(2); err != nil || string(data) != "ok" {
		t.Fatalf("H2 body %q: %v", data, err)
	}
	close(bodyConsumed)
}
