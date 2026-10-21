package phantom

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type h3PendingUpload struct {
	reads   atomic.Int32
	closes  atomic.Int32
	pending chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (source *h3PendingUpload) Read(output []byte) (int, error) {
	if len(output) == 0 {
		return 0, nil
	}
	if source.reads.Add(1) == 1 {
		if len(output) < 1024 {
			return 0, io.ErrShortBuffer
		}
		for index := range output[:1024] {
			output[index] = 'U'
		}
		return 1024, nil
	}
	source.once.Do(func() { close(source.pending) })
	<-source.closed
	return 0, io.ErrClosedPipe
}

func (source *h3PendingUpload) Close() error {
	if source.closes.Add(1) == 1 {
		close(source.closed)
	}
	return nil
}

func TestHTTP3UploadCancellation(t *testing.T) {
	python, script := os.Getenv("PHANTOM_H3_PEER_PYTHON"), os.Getenv("PHANTOM_H3_PEER_SCRIPT")
	if python == "" || script == "" {
		t.Fatal("independent HTTP/3 peer paths are required")
	}
	directory := t.TempDir()
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	command := exec.CommandContext(ctx, python, script, "--directory", directory)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	events := make(chan string, 8)
	exited := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 1024), 1024)
		for scanner.Scan() {
			events <- scanner.Text()
		}
		close(events)
		exited <- errors.Join(scanner.Err(), command.Wait())
	}()
	peerExited := false
	defer func() {
		_ = input.Close()
		if !peerExited {
			select {
			case err := <-exited:
				if err != nil {
					t.Errorf("HTTP/3 peer failed: %v: %s", err, stderr.String())
				}
			case <-time.After(8 * time.Second):
				_ = command.Process.Kill()
				<-exited
				t.Error("HTTP/3 peer did not settle")
			}
		}
	}()
	await := func(expected string) {
		t.Helper()
		select {
		case line, ok := <-events:
			var value struct {
				Event string `json:"event"`
			}
			if !ok || json.Unmarshal([]byte(line), &value) != nil || value.Event != expected {
				t.Fatalf("peer event %q, expected %s", line, expected)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("missing peer event %s", expected)
		}
	}
	read := func(name string, result any) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || len(data) > 65536 {
			t.Fatalf("peer receipt %s: %v", name, err)
		}
		if err := json.Unmarshal(data, result); err != nil {
			t.Fatal(err)
		}
	}
	await("ready")
	var ready struct {
		URL     string `json:"url"`
		RootDER []byte `json:"root_der"`
	}
	read("ready.json", &ready)
	// The generated CA is trust material; pins identify the actual leaf SPKI.
	certificatePEM, err := os.ReadFile(filepath.Join(directory, "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("missing peer leaf certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	client, err := New(Config{Profile: profile, Protocol: "h3", AdditionalRootsDER: [][]byte{ready.RootDER}, ServerSPKIPins: [][32]byte{{1}, pin}, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("client shutdown: %v", err)
		}
	}()
	request := func(path string) *Response {
		t.Helper()
		response, err := client.Do(ctx, Request{Method: "GET", URL: ready.URL + path})
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	checkBody := func(response *Response, expected string) {
		t.Helper()
		defer response.Body.Close()
		data, err := response.Body.ReadAll(len(expected))
		if err != nil || string(data) != expected || response.Protocol != "h3" {
			t.Fatalf("body %q: %v", data, err)
		}
	}
	checkBody(request("/warm"), "ok")
	source := &h3PendingUpload{pending: make(chan struct{}), closed: make(chan struct{})}
	selectedContext, cancel := context.WithCancel(ctx)
	defer cancel()
	selected, err := client.Do(selectedContext, Request{Method: "POST", URL: ready.URL + "/upload", Upload: source})
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Body.Close()
	prefix := make([]byte, 1)
	if _, err := io.ReadFull(selected.Body, prefix); err != nil || prefix[0] != 'a' {
		t.Fatalf("selected head prefix: %v", err)
	}
	select {
	case <-source.pending:
	case <-time.After(5 * time.Second):
		t.Fatal("producer was not pending")
	}
	healthy := request("/healthy")
	defer healthy.Body.Close()
	await("live")
	cancel()
	if _, err := selected.Body.Read(prefix); !errors.Is(err, context.Canceled) {
		t.Fatalf("selected body cancellation: %v", err)
	}
	select {
	case <-source.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("producer did not close")
	}
	await("cancelled")
	checkBody(healthy, "healthy")
	if source.reads.Load() != 2 || source.closes.Load() != 1 {
		t.Fatalf("producer reads=%d closes=%d", source.reads.Load(), source.closes.Load())
	}
	checkBody(request("/reuse"), "ok")
	await("complete")
	var result struct {
		Protocol      string         `json:"protocol"`
		Connections   int            `json:"connections"`
		Streams       map[string]int `json:"streams"`
		UploadBytes   int            `json:"upload_bytes"`
		Cancellations map[string]int `json:"cancellations"`
		Released      bool           `json:"healthy_released"`
	}
	read("result.json", &result)
	streams := make(map[int]bool)
	for _, stream := range result.Streams {
		streams[stream] = true
	}
	if result.Protocol != "h3" || result.Connections != 1 || len(streams) != 4 || result.UploadBytes != 1024 ||
		len(result.Cancellations) != 2 || result.Cancellations["reset_stream"] != 0x10c || result.Cancellations["stop_sending"] != 0x10c || !result.Released {
		t.Fatalf("unexpected HTTP/3 receipt: %+v", result)
	}
	if _, err := io.WriteString(input, "stop\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		peerExited = true
		if err != nil {
			t.Fatalf("HTTP/3 peer failed: %v: %s", err, stderr.String())
		}
	case <-time.After(8 * time.Second):
		t.Fatal("HTTP/3 peer did not settle")
	}
}
