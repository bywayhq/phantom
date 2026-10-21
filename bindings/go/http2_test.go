package phantom

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// This peer needs only literal :status 200. Request HPACK stays opaque: stream
// arrival order chooses the held request and the two independent controls.
type http2CancellationCause uint8

const (
	http2CancelContext http2CancellationCause = iota
	http2CancelDecodedLimit
	http2CancelTransferLimit
	http2CancelTransferPacing
	http2CancelTransferTotal
)

func TestHTTP2CancellationPreservesOtherStreamsAndConnection(t *testing.T) {
	t.Run("context", func(t *testing.T) { http2CancellationPreservesOtherStreams(t, http2CancelContext) })
	t.Run("decoded limit", func(t *testing.T) { http2CancellationPreservesOtherStreams(t, http2CancelDecodedLimit) })
	t.Run("transfer limit", func(t *testing.T) { http2CancellationPreservesOtherStreams(t, http2CancelTransferLimit) })
	t.Run("transfer pacing", func(t *testing.T) { http2CancellationPreservesOtherStreams(t, http2CancelTransferPacing) })
	t.Run("transfer total timeout", func(t *testing.T) { http2CancellationPreservesOtherStreams(t, http2CancelTransferTotal) })
}

func http2CancellationPreservesOtherStreams(t *testing.T, cause http2CancellationCause) {
	firstData := []byte("a")
	firstHeaders := []byte{0x88}
	if cause == http2CancelDecodedLimit {
		firstData = gzipBytes(t, []byte("decoded bytes exceed zero"))
		// Literal Content-Encoding name index26, value gzip; no indexing.
		firstHeaders = append(firstHeaders, 0x0f, 0x0b, 4, 'g', 'z', 'i', 'p')
	} else if cause == http2CancelTransferPacing || cause == http2CancelTransferTotal {
		firstData = []byte("reserved body waits for its pace")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int64
	reset := make(chan uint32, 1)
	peerDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			peerDone <- err
			return
		}
		accepted.Add(1)
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
		preface := make([]byte, 24)
		if _, err = io.ReadFull(connection, preface); err != nil {
			peerDone <- err
			return
		}
		if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
			peerDone <- fmt.Errorf("invalid preface")
			return
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
		if err = writeFrame(4, 0, 0, nil); err != nil {
			peerDone <- err
			return
		}
		var held, waiting uint32
		cancelled := false
		count := 0
		for {
			header := make([]byte, 9)
			if _, err = io.ReadFull(connection, header); err != nil {
				peerDone <- err
				return
			}
			length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
			if length > 1024*1024 {
				peerDone <- fmt.Errorf("unbounded frame")
				return
			}
			data := make([]byte, length)
			if _, err = io.ReadFull(connection, data); err != nil {
				peerDone <- err
				return
			}
			stream := binary.BigEndian.Uint32(header[5:]) & 0x7fffffff
			switch header[3] {
			case 4:
				if header[4]&1 == 0 {
					err = writeFrame(4, 1, 0, nil)
				}
			case 6:
				if header[4]&1 == 0 {
					err = writeFrame(6, 1, 0, data)
				}
			case 1:
				count++
				responseHeaders := []byte{0x88}
				if count == 1 {
					responseHeaders = firstHeaders
				}
				err = writeFrame(1, 4, stream, responseHeaders)
				if count == 1 {
					held = stream
					if err == nil {
						err = writeFrame(0, 0, stream, firstData)
					}
				} else if count == 2 && !cancelled {
					waiting = stream
				} else if err == nil {
					err = writeFrame(0, 1, stream, []byte("hello"))
				}
				if count == 3 && err == nil {
					peerDone <- nil
					<-time.After(100 * time.Millisecond)
					return
				}
			case 3:
				if stream == held && len(data) == 4 {
					reset <- binary.BigEndian.Uint32(data)
					cancelled = true
					if waiting != 0 {
						err = writeFrame(0, 1, waiting, []byte("hello"))
					}
				}
			}
			if err != nil {
				peerDone <- err
				return
			}
		}
	}()
	client, err := New(Config{Profile: profile, Protocol: "h2", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstRequest := Request{Method: "GET", URL: "http://" + listener.Addr().String() + "/held"}
	var transfer *TransferControl
	if cause == http2CancelDecodedLimit {
		firstRequest.ContentDecoding = AdvertisedDecoding(0)
		firstRequest.Headers = []Header{{Name: "accept-encoding", Value: []byte("gzip")}}
	} else if cause == http2CancelTransferLimit {
		transfer = newTransfer(t, TransferLimits{DownloadBytes: uint64Pointer(0)})
	} else if cause == http2CancelTransferPacing || cause == http2CancelTransferTotal {
		transfer = newTransfer(t, TransferLimits{DownloadBytesPerSecond: uint64Pointer(1)})
	}
	if cause == http2CancelTransferTotal {
		firstRequest.Timeouts = Timeouts{Total: LimitTimeout(2 * time.Second), ReadIdle: LimitTimeout(50 * time.Millisecond)}
	}
	firstRequest.TransferControl = transfer
	first, err := client.Do(ctx, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if cause == http2CancelContext {
		if n, err := first.Body.Read(buffer); n != 1 || err != nil {
			t.Fatalf("held read %d: %v", n, err)
		}
	}
	second, err := client.Do(context.Background(), Request{Method: "GET", URL: "http://" + listener.Addr().String() + "/live"})
	if err != nil {
		t.Fatal(err)
	}
	if cause == http2CancelDecodedLimit {
		if _, err := first.Body.Read(buffer); kind(err) != "response_body_limit" {
			t.Fatalf("decoded limit: %v", err)
		}
	} else if cause == http2CancelTransferLimit {
		if _, err := first.Body.Read(buffer); kind(err) != "transfer" {
			t.Fatalf("transfer limit: %v", err)
		}
	} else if cause == http2CancelTransferTotal {
		_, err := first.Body.Read(buffer)
		var failure *Error
		if !errors.As(err, &failure) || failure.Kind != "timeout" || failure.TimeoutPhase != "total" {
			t.Fatalf("paced read must preserve total deadline without a read-idle failure: %v", err)
		}
		if snapshot := transferSnapshot(t, transfer); snapshot.DownloadReservedBytes != uint64(len(firstData)) || snapshot.DownloadEncodedBytes != 0 {
			t.Fatalf("timed-out reservation changed: %+v", snapshot)
		}
	} else if cause == http2CancelTransferPacing {
		readDone := make(chan error, 1)
		go func() {
			_, err := first.Body.Read(buffer)
			readDone <- err
		}()
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for transferSnapshot(t, transfer).DownloadReservedBytes == 0 {
			select {
			case <-tick.C:
			case <-deadline.C:
				t.Fatal("no paced reservation")
			}
		}
		before := transferSnapshot(t, transfer)
		if before.DownloadEncodedBytes != 0 || before.DownloadReservedBytes != uint64(len(firstData)) {
			t.Fatalf("reservation already delivered: %+v", before)
		}
		cancel()
		select {
		case err := <-readDone:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("paced read: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("paced read did not cancel")
		}
		if after := transferSnapshot(t, transfer); after != before {
			t.Fatalf("cancelled reservation changed: before=%+v after=%+v", before, after)
		}
	} else {
		cancel()
	}
	select {
	case code := <-reset:
		if code != 8 {
			t.Fatalf("reset=%d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no stream CANCEL")
	}
	if data, err := second.Body.ReadAll(5); err != nil || string(data) != "hello" {
		t.Fatalf("independent body %q: %v", data, err)
	}
	third, err := client.Do(context.Background(), Request{Method: "GET", URL: "http://" + listener.Addr().String() + "/reuse"})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := third.Body.ReadAll(5); err != nil || string(data) != "hello" {
		t.Fatalf("reused body %q: %v", data, err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
	if accepted.Load() != 1 {
		t.Fatal("connection was replaced")
	}
}

func TestHTTP2CancellationInterruptsFlowBlockedUpload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered := make(chan struct{})
	reset := make(chan uint32, 1)
	finished := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(6 * time.Second))
		preface := make([]byte, 24)
		if _, err := io.ReadFull(connection, preface); err != nil {
			finished <- err
			return
		}
		write := func(kind, flags byte, stream uint32, data []byte) error {
			header := []byte{byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data)), kind, flags, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(header[5:], stream)
			if _, err := connection.Write(header); err != nil {
				return err
			}
			_, err := connection.Write(data)
			return err
		}
		// Initial stream send window zero: the upload cannot enter TCP buffers.
		if err := write(4, 0, 0, []byte{0, 4, 0, 0, 0, 0}); err != nil {
			finished <- err
			return
		}
		var upload uint32
		acknowledged, signalled := false, false
		received := 0
		for {
			header := make([]byte, 9)
			if _, err := io.ReadFull(connection, header); err != nil {
				finished <- err
				return
			}
			length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
			if length > 1024*1024 {
				finished <- fmt.Errorf("unbounded frame")
				return
			}
			data := make([]byte, length)
			if _, err := io.ReadFull(connection, data); err != nil {
				finished <- err
				return
			}
			stream := binary.BigEndian.Uint32(header[5:]) & 0x7fffffff
			switch header[3] {
			case 4:
				if header[4]&1 == 0 {
					err = write(4, 1, 0, nil)
				} else {
					acknowledged = true
				}
				if acknowledged && upload != 0 && !signalled {
					close(entered)
					signalled = true
				}
			case 6:
				if header[4]&1 == 0 {
					err = write(6, 1, 0, data)
				}
			case 1:
				if upload == 0 {
					upload = stream
					if acknowledged && !signalled {
						close(entered)
						signalled = true
					}
				} else {
					if err = write(1, 4, stream, []byte{0x88}); err == nil {
						err = write(0, 1, stream, []byte("ok"))
					}
					finished <- err
					return
				}
			case 0:
				if stream == upload {
					received += len(data)
				}
				// The default window permits at most 65535 bytes before SETTINGS.
				if received > 65535 {
					finished <- fmt.Errorf("upload bypassed flow control")
					return
				}
			case 3:
				if stream == upload && len(data) == 4 {
					reset <- binary.BigEndian.Uint32(data)
				}
			}
			if err != nil {
				finished <- err
				return
			}
		}
	}()
	client, err := New(Config{Profile: profile, Protocol: "h2", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.Do(ctx, Request{Method: "PUT", URL: "http://" + listener.Addr().String(), Body: make([]byte, maxUpload)})
		done <- err
	}()
	select {
	case <-entered:
	case err := <-finished:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("upload not observed")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("upload cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upload cancellation hung")
	}
	select {
	case code := <-reset:
		if code != 8 {
			t.Fatalf("reset=%d", code)
		}
	case err := <-finished:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("no blocked upload CANCEL")
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: "http://" + listener.Addr().String() + "/control"})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := response.Body.ReadAll(2); err != nil || string(data) != "ok" {
		t.Fatalf("control body %q: %v", data, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
