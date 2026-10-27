package phantom

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var benchmarkPayloads = [...]struct {
	name string
	size int
}{
	{"small", 256},
	{"64KiB", 64 * 1024},
	{"1MiB", 1024 * 1024},
}

// BenchmarkClient exercises completed requests, including the caller's body read.
// Run on a quiet host with a matching native library and retain the source SHA.
func BenchmarkClient(b *testing.B) {
	for _, payload := range benchmarkPayloads {
		b.Run(payload.name, func(b *testing.B) {
			read := benchmarkClientRead(b, payload.size)
			for b.Loop() {
				if err := read(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkClientParallel uses at most 32 active workers sharing one client.
// Completed requests include the caller's body read and the in-process peer.
func BenchmarkClientParallel(b *testing.B) {
	for _, payload := range benchmarkPayloads {
		b.Run(payload.name, func(b *testing.B) {
			read := benchmarkClientRead(b, payload.size)
			workers := make(chan struct{}, 32)
			b.RunParallel(func(pb *testing.PB) {
				workers <- struct{}{}
				defer func() { <-workers }()
				for pb.Next() {
					if err := read(); err != nil {
						b.Error(err)
						return
					}
				}
			})
			b.StopTimer()
		})
	}
}

func benchmarkClientRead(b *testing.B, size int) func() error {
	b.Helper()
	payload := make([]byte, size)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	b.Cleanup(server.Close)
	client, err := New(Config{Profile: profile, Protocol: "h1", Timeout: 30 * time.Second})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := client.Close(); err != nil {
			b.Error(err)
		}
	})
	request := Request{Method: "GET", URL: server.URL}
	read := func() error {
		response, err := client.Do(context.Background(), request)
		if err != nil {
			return err
		}
		n, err := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || n != int64(size) {
			return fmt.Errorf("completed body: bytes=%d read=%v close=%v", n, err, closeErr)
		}
		return nil
	}
	if err := read(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(size))
	b.ResetTimer()
	return read
}
