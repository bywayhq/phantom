package phantom

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// BenchmarkClient exercises completed requests, including the caller's body read.
// Run on a quiet host with a matching native library and retain the source SHA.
func BenchmarkClient(b *testing.B) {
	for _, size := range []int{256, 64 * 1024, 1024 * 1024} {
		name := map[int]string{256: "small", 64 * 1024: "64KiB", 1024 * 1024: "1MiB"}[size]
		b.Run(name, func(b *testing.B) {
			payload := make([]byte, size)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(payload)
			}))
			defer server.Close()
			client, err := New(Config{Profile: profile, Protocol: "h1", Timeout: 30 * time.Second})
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			request := Request{Method: "GET", URL: server.URL}
			read := func() {
				response, err := client.Do(context.Background(), request)
				if err != nil {
					b.Fatal(err)
				}
				n, err := io.Copy(io.Discard, response.Body)
				closeErr := response.Body.Close()
				if err != nil || closeErr != nil || n != int64(size) {
					b.Fatalf("completed body: bytes=%d read=%v close=%v", n, err, closeErr)
				}
			}
			read()
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				read()
			}
		})
	}
}
