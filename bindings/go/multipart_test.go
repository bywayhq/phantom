package phantom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMultipartReaderCustodyOnInvalidRequestsAndReuse(t *testing.T) {
	client := &Client{}
	source := &ownedUpload{Reader: strings.NewReader("private")}
	part := MultipartReader("file", source)
	request := Request{Multipart: &StreamingMultipart{Boundary: "bound", MaximumBytes: 1024, Parts: []MultipartPart{part}}}
	if _, err := client.Do(nil, request); kind(err) != "invalid_context" {
		t.Fatal(err)
	}
	if source.closes.Load() != 1 || source.bytes.Load() != 0 {
		t.Fatal("invalid request lost reader custody")
	}
	if _, err := client.Do(nil, request); kind(err) != "invalid_context" {
		t.Fatal(err)
	}
	if source.closes.Load() != 1 {
		t.Fatal("reused part was closed twice")
	}
	if _, err := PrepareMultipart([]MultipartPart{MultipartReader("file", nil)}, "bound", 1024); kind(err) != "invalid_prepared_body" {
		t.Fatalf("prepared reader: %v", err)
	}
	duplicate := &ownedUpload{Reader: strings.NewReader("private")}
	owner := multipartUpload(&StreamingMultipart{Parts: []MultipartPart{MultipartReader("a", duplicate), MultipartReader("b", duplicate)}})
	if !owner.multipart.invalid {
		t.Fatal("duplicate reader accepted")
	}
	_ = owner.close()
	if duplicate.closes.Load() != 1 || duplicate.bytes.Load() != 0 {
		t.Fatal("duplicate reader custody")
	}
	oversize := &ownedUpload{Reader: strings.NewReader("private")}
	parts := make([]MultipartPart, 1025)
	parts[0], parts[1024] = MultipartReader("a", oversize), MultipartReader("b", oversize)
	_ = multipartUpload(&StreamingMultipart{Parts: parts}).close()
	if oversize.closes.Load() != 1 || oversize.bytes.Load() != 0 {
		t.Fatal("oversized request duplicated reader Close")
	}
	// A failed competing request must not close the reader owned by the first.
	active := &ownedUpload{Reader: strings.NewReader("a")}
	shared := &StreamingMultipart{Parts: []MultipartPart{MultipartReader("a", active)}}
	first, second := multipartUpload(shared), multipartUpload(shared)
	if !second.multipart.invalid {
		t.Fatal("reader part reused concurrently")
	}
	_ = second.close()
	if active.closes.Load() != 0 {
		t.Fatal("second request closed first request's reader")
	}
	_ = first.close()
	if active.closes.Load() != 1 {
		t.Fatal("first request lost custody")
	}
}

func TestStreamingMultipartUsesCoreEncodingAndUnknownLength(t *testing.T) {
	expected := "--fixture\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\nfirst\r\nsecond\r\n" +
		"--fixture\r\nContent-Disposition: form-data; name=\"tag\"; filename=\"a%22.bin\"\r\nContent-Type: application/x-custom\r\n\r\na\x00b\r\n" +
		"--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"stream.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nstreamed\r\n--fixture--\r\n"
	observed := make(chan error, 1)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, int64(len(expected)+1)))
		if err == nil && (string(data) != expected || r.ContentLength != -1 || len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked" || r.Header.Get("Content-Type") != "multipart/form-data; boundary=fixture") {
			err = fmt.Errorf("wire encoding/length mismatch: %d bytes, length=%d", len(data), r.ContentLength)
		}
		observed <- err
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "ok")
	}))
	defer peer.Close()
	source := &ownedUpload{Reader: strings.NewReader("streamed")}
	form := &StreamingMultipart{Boundary: "fixture", MaximumBytes: uint64(len(expected)), Parts: []MultipartPart{
		MultipartText("tag", "first\nsecond"), MultipartBytes("tag", []byte{'a', 0, 'b'}).WithFilename("a\".bin").WithContentType("application/x-custom"), MultipartReader("file", source).WithFilename("stream.bin"),
	}}
	contentType, err := form.ContentType()
	if err != nil {
		t.Fatal(err)
	}
	client := newClient(t)
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Multipart: form, Headers: []Header{{Name: "Content-Type", Value: []byte(contentType)}}})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := response.Body.ReadAll(2); err != nil || string(data) != "ok" {
		t.Fatalf("response %q: %v", data, err)
	}
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	waitUploadClosed(t, &source.closes)
}

func TestStreamingMultipartOwnsAnOpenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("file bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	observed := make(chan error, 1)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reader, err := r.MultipartReader()
		if err == nil {
			var part *multipart.Part
			part, err = reader.NextPart()
			if err == nil {
				var data []byte
				data, err = io.ReadAll(part)
				if err == nil && (part.FormName() != "file" || part.FileName() != "input.bin" || string(data) != "file bytes") {
					err = errors.New("file part mismatch")
				}
			}
			if err == nil {
				_, err = reader.NextPart()
				if errors.Is(err, io.EOF) {
					err = nil
				} else if err == nil {
					err = errors.New("extra part")
				}
			}
		}
		observed <- err
		w.Header().Set("Content-Length", "0")
	}))
	defer peer.Close()
	client := newClient(t)
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Headers: []Header{{Name: "Content-Type", Value: []byte("multipart/form-data; boundary=file")}}, Multipart: &StreamingMultipart{Boundary: "file", MaximumBytes: 1024, Parts: []MultipartPart{MultipartReader("file", file).WithFilename("input.bin")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = response.Body.ReadAll(0); err != nil {
		t.Fatal(err)
	}
	if err = <-observed; err != nil {
		t.Fatal(err)
	}
	if _, err = file.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("file custody: %v", err)
	}
}

type orderedMultipartReader struct {
	index     int
	previous  *orderedMultipartReader
	data      *strings.Reader
	closes    atomic.Int32
	reads     atomic.Int32
	violation *atomic.Bool
}

func (r *orderedMultipartReader) Read(output []byte) (int, error) {
	r.reads.Add(1)
	if r.previous != nil && r.previous.closes.Load() != 1 {
		r.violation.Store(true)
	}
	return r.data.Read(output)
}
func (r *orderedMultipartReader) Close() error { r.closes.Add(1); return nil }

func TestStreamingMultipartMoreThan64PartsActivatesOneReaderAtATime(t *testing.T) {
	var violation atomic.Bool
	parts := make([]MultipartPart, 0, 70)
	sources := make([]*orderedMultipartReader, 0, 70)
	var expected strings.Builder
	for index := 0; index < 70; index++ {
		source := &orderedMultipartReader{index: index, data: strings.NewReader(fmt.Sprint(index)), violation: &violation}
		if index != 0 {
			source.previous = sources[index-1]
		}
		sources = append(sources, source)
		parts = append(parts, MultipartReader("tag", source))
		fmt.Fprintf(&expected, "--many\r\nContent-Disposition: form-data; name=\"tag\"\r\nContent-Type: application/octet-stream\r\n\r\n%d\r\n", index)
	}
	expected.WriteString("--many--\r\n")
	received := make(chan error, 1)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, int64(expected.Len()+1)))
		if err == nil && string(data) != expected.String() {
			err = errors.New("multipart order differs")
		}
		received <- err
		w.Header().Set("Content-Length", "0")
	}))
	defer peer.Close()
	client := newClient(t)
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Headers: []Header{{Name: "Content-Type", Value: []byte("multipart/form-data; boundary=many")}}, Multipart: &StreamingMultipart{Boundary: "many", MaximumBytes: uint64(expected.Len()), Parts: parts}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = response.Body.ReadAll(0); err != nil {
		t.Fatal(err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		waitUploadClosed(t, &source.closes)
		if source.reads.Load() == 0 {
			t.Fatal("missing part")
		}
	}
	if violation.Load() {
		t.Fatal("next reader started before previous Close")
	}
}
