package phantom

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestHTTP3ResponseHeadersRetainRawQPACKMarkers(t *testing.T) {
	directory := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Getenv("PHANTOM_H3_PEER_PYTHON"), os.Getenv("PHANTOM_HEADER_H3_PEER_SCRIPT"), "--directory", directory)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	settled := false
	defer func() {
		_ = input.Close()
		if !settled {
			_ = command.Process.Kill()
			<-exited
		}
	}()
	readyLine := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 1024), 1024)
		if !scanner.Scan() {
			readyLine <- fmt.Errorf("missing peer ready: %v", scanner.Err())
			return
		}
		var value struct {
			Event string `json:"event"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &value); err != nil {
			readyLine <- err
			return
		}
		if value.Event != "ready" {
			readyLine <- fmt.Errorf("unexpected peer event")
			return
		}
		readyLine <- nil
	}()
	select {
	case err := <-readyLine:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("missing peer ready")
	}
	data, err := os.ReadFile(filepath.Join(directory, "ready.json"))
	if err != nil || len(data) > 65536 {
		t.Fatalf("peer receipt: %v", err)
	}
	var ready struct {
		URL     string `json:"url"`
		RootDER []byte `json:"root_der"`
	}
	if err := json.Unmarshal(data, &ready); err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{Profile: "chrome/154.0.8037.97/windows-11-26200/r1", Protocol: "h3", Timeout: 10 * time.Second, AdditionalRootsDER: [][]byte{ready.RootDER}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	}()
	expected := []Header{{Name: "x-a", Value: []byte("first")}, {Name: "x-b", Value: []byte{0x80, 'B'}, Sensitive: true}, {Name: "x-a", Value: []byte("last")}}
	for _, target := range []string{"/one", "/two"} {
		response, err := client.Do(ctx, Request{Method: "GET", URL: ready.URL + target})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(response.Headers, expected) {
			_ = response.Body.Close()
			t.Fatalf("response headers: %#v", response.Headers)
		}
		body, err := response.Body.ReadAll(2)
		if err != nil || string(body) != "ok" {
			t.Fatalf("body %q: %v", body, err)
		}
		if !reflect.DeepEqual(response.Headers, expected) {
			t.Fatal("head metadata changed after completion")
		}
	}
	if _, err := input.Write([]byte("stop\n")); err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		settled = true
		if err != nil {
			t.Fatalf("peer failed: %v: %s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("peer did not settle")
	}
}
