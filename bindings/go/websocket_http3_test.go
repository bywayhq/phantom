package phantom

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTP3WebSocketFramesCancellationAndRejectedBody(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "messages and cancellation"
		if reject {
			name = "rejected body"
		}
		t.Run(name, func(t *testing.T) { checkHTTP3WebSocket(t, reject) })
	}
}

func checkHTTP3WebSocket(t *testing.T, reject bool) {
	python, script := os.Getenv("PHANTOM_H3_PEER_PYTHON"), os.Getenv("PHANTOM_WEBSOCKET_H3_PEER_SCRIPT")
	if python == "" || script == "" {
		t.Fatal("independent HTTP/3 WebSocket peer paths are required")
	}
	directory := t.TempDir()
	ctx, stop := context.WithTimeout(context.Background(), 35*time.Second)
	defer stop()
	command := exec.CommandContext(ctx, python, script, "--directory", directory)
	if reject {
		command.Args = append(command.Args, "--reject")
	}
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
	settled := false
	defer func() {
		_ = input.Close()
		if !settled {
			stop()
			select {
			case err := <-exited:
				if err != nil {
					t.Logf("peer cleanup: %v %s", err, stderr.String())
				}
			case <-time.After(5 * time.Second):
				t.Error("HTTP/3 WebSocket peer did not settle")
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
				t.Fatalf("peer event %q; expected %s", line, expected)
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
	base, err := NewCatalogProfile("chrome-154-windows", "")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	document, err := base.Describe()
	if err != nil {
		t.Fatal(err)
	}
	// Chrome leaves HTTP/3 WebSockets disabled. This local profile deliberately
	// enables the complete pseudo-header sequence required by the peer.
	profileFields := document["profile"].(map[string]any)
	http3 := profileFields["http3"].(map[string]any)
	http3["request"].(map[string]any)["extended_connect_pseudo_header_order"] = []string{"Method", "Protocol", "Scheme", "Authority", "Path"}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := ImportProfileJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Close()
	client, err := New(Config{ProfileSettings: selected, Protocol: "h3", AdditionalRootsDER: [][]byte{ready.RootDER}, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := func(path string) *Response {
		t.Helper()
		response, err := client.Do(ctx, Request{Method: "GET", URL: ready.URL + path})
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	body := func(response *Response, expected string) {
		t.Helper()
		defer response.Body.Close()
		data, err := response.Body.ReadAll(len(expected))
		if err != nil || string(data) != expected || response.Protocol != "h3" {
			t.Fatalf("body %q: %v", data, err)
		}
	}
	body(request("/warm"), "ok")
	url := strings.Replace(ready.URL, "https:", "wss:", 1)
	if reject {
		_, err := client.WebSocket(ctx, url+"/reject", WebSocketOptions{Protocol: "h3"})
		var rejected *WebSocketHandshakeError
		if !errors.As(err, &rejected) || rejected.Response.Status != 403 || rejected.Response.Protocol != "h3" {
			t.Fatalf("rejection: %v", err)
		}
		defer rejected.Response.Body.Close()
		await("rejected")
		closing, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		if err := client.Shutdown(closing); !errors.Is(err, context.DeadlineExceeded) {
			cancel()
			t.Fatalf("shutdown: %v", err)
		}
		cancel()
		prefix := make([]byte, 2)
		if n, err := rejected.Response.Body.Read(prefix); err != nil || n != 2 || string(prefix) != "de" {
			t.Fatalf("rejection prefix %q: %v", prefix, err)
		}
		if _, err := input.Write([]byte("release\n")); err != nil {
			t.Fatal(err)
		}
		await("complete")
		body(rejected.Response, "nied")
	} else {
		socket, err := client.WebSocket(ctx, url+"/echo", WebSocketOptions{Protocol: "h3", Headers: []Header{{Name: "sec-websocket-protocol", Value: []byte("chat")}}})
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Abort()
		if head := socket.Handshake(); head.Status != 200 || head.Protocol != "h3" || head.SelectedProtocol != "chat" {
			t.Fatalf("handshake %+v", head)
		}
		for _, message := range []struct {
			kind MessageType
			data []byte
		}{{TextMessage, []byte("hello")}, {BinaryMessage, []byte{0, 255}}} {
			if err := socket.Write(ctx, message.kind, message.data); err != nil {
				t.Fatal(err)
			}
			kind, data, err := socket.Read(ctx)
			if err != nil || kind != message.kind || !bytes.Equal(data, message.data) {
				t.Fatalf("echo %d %q %v", kind, data, err)
			}
		}
		if err := socket.Close(ctx, &WebSocketCloseFrame{1000, "done"}); err != nil {
			t.Fatal(err)
		}
		_, _, err = socket.Read(ctx)
		var closed *WebSocketCloseError
		if !errors.As(err, &closed) || closed.Frame == nil || closed.Frame.Code != 1000 {
			t.Fatalf("close: %v", err)
		}
		socket, err = client.WebSocket(ctx, url+"/cancel", WebSocketOptions{Protocol: "h3"})
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Abort()
		reading, cancel := context.WithCancel(ctx)
		defer cancel()
		pending := make(chan error, 1)
		go func() { _, _, err := socket.Read(reading); pending <- err }()
		awaitWebSocketOperation(t)
		healthy := request("/healthy")
		defer healthy.Body.Close()
		await("live")
		cancel()
		select {
		case err := <-pending:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		await("cancelled")
		body(healthy, "healthy")
		body(request("/reuse"), "ok")
		await("complete")
	}
	var result struct {
		Connections     int            `json:"connections"`
		Streams         map[string]int `json:"streams"`
		Frames          int            `json:"frames"`
		Cancellations   map[string]int `json:"cancellations"`
		HealthyReleased bool           `json:"healthy_released"`
		Rejected        bool           `json:"rejected"`
	}
	read("result.json", &result)
	expectedStreams := 5
	if reject {
		expectedStreams = 2
	}
	if result.Connections != 1 || result.Rejected != reject || len(result.Streams) != expectedStreams {
		t.Fatalf("connection/stream ownership: %+v", result)
	}
	seen := make(map[int]bool)
	for _, id := range result.Streams {
		seen[id] = true
	}
	if len(seen) != expectedStreams {
		t.Fatal("request stream identity reused")
	}
	if !reject && (result.Frames != 3 || !result.HealthyReleased || result.Cancellations["reset_stream"] != 0x10c || result.Cancellations["stop_sending"] != 0x10c) {
		t.Fatalf("selected-stream cancellation: %+v", result)
	}
	if _, err := input.Write([]byte("stop\n")); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	select {
	case err := <-exited:
		settled = true
		if err != nil {
			t.Fatalf("peer: %v %s", err, stderr.String())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if stderr.Len() != 0 {
		t.Fatalf("peer stderr: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(directory, "error.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("peer error receipt: %v", err)
	}
	if err := client.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
