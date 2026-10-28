package phantom

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTP3EventSourceReconnectCancellationAndRejection(t *testing.T) {
	for _, reject := range []string{"", "initial", "reconnect"} {
		name := reject
		if name == "" {
			name = "reconnect and sibling"
		}
		t.Run(name, func(t *testing.T) { checkHTTP3EventSource(t, reject) })
	}
}

func checkHTTP3EventSource(t *testing.T, reject string) {
	python, script := os.Getenv("PHANTOM_H3_PEER_PYTHON"), os.Getenv("PHANTOM_EVENTS_H3_PEER_SCRIPT")
	if python == "" || script == "" {
		t.Fatal("independent HTTP/3 EventSource peer paths are required")
	}
	directory := t.TempDir()
	ctx, stop := context.WithTimeout(context.Background(), 35*time.Second)
	defer stop()
	command := exec.CommandContext(ctx, python, script, "--directory", directory)
	if reject != "" {
		command.Args = append(command.Args, "--reject", reject)
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
				t.Error("HTTP/3 EventSource peer did not settle")
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
				t.Fatalf("peer event %q, want %s", line, expected)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("missing peer event %s", expected)
		}
	}
	receipt := func(name string, target any) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || len(data) > 65536 || json.Unmarshal(data, target) != nil {
			t.Fatalf("peer receipt %s: %v", name, err)
		}
	}
	await("ready")
	var ready struct {
		URL     string `json:"url"`
		RootDER []byte `json:"root_der"`
	}
	receipt("ready.json", &ready)
	client, err := New(Config{Profile: profile, Protocol: "h3", Context: "raw", Timeout: 10 * time.Second, AdditionalRootsDER: [][]byte{ready.RootDER}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	initial, minRetry := time.Duration(0), 200*time.Millisecond
	maximum := uint64(3)
	source, err := client.EventSource(ctx, ready.URL+"/events", EventSourceOptions{Protocol: "h3", InitialRetry: &initial, MinRetry: &minRetry, MaxReconnects: &maximum})
	if reject == "initial" {
		if kind(err) != "sse_unexpected_status" {
			t.Fatalf("initial rejection: %v", err)
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if source.Status != 200 || source.Protocol != "h3" {
			t.Fatalf("initial metadata: %d %s", source.Status, source.Protocol)
		}
		first, err := source.Next(ctx)
		if err != nil || first.Data != "first" || first.ID != "7" {
			t.Fatalf("first: %+v %v", first, err)
		}
		if reject == "reconnect" {
			_, err = source.Next(ctx)
			if kind(err) != "sse_unexpected_status" || strings.Contains(err.Error(), "private") {
				t.Fatalf("reconnect rejection: %v", err)
			}
			if _, err := source.Next(ctx); !errors.Is(err, io.EOF) {
				t.Fatalf("terminal reread: %v", err)
			}
			if source.Reconnects() != 1 {
				t.Fatalf("reconnect count: %d", source.Reconnects())
			}
		} else {
			healthy, err := client.Do(ctx, Request{Method: "GET", URL: ready.URL + "/healthy"})
			if err != nil {
				t.Fatal(err)
			}
			defer healthy.Body.Close()
			await("live")
			next, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
			_, err = source.Next(next)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) || source.Closed() {
				t.Fatalf("cancel backoff: %v closed=%v", err, source.Closed())
			}
			second, err := source.Next(ctx)
			if err != nil || second.Data != "second" || second.ID != "9" {
				t.Fatalf("resumed: %+v %v", second, err)
			}
			if _, err := source.Next(ctx); !errors.Is(err, io.EOF) {
				t.Fatalf("204: %v", err)
			}
			if !source.Closed() || source.LastEventID() != "9" || source.Reconnects() != 2 {
				t.Fatalf("terminal state: %s %d %v", source.LastEventID(), source.Reconnects(), source.Closed())
			}
			if body, err := healthy.Body.ReadAll(7); err != nil || string(body) != "healthy" {
				t.Fatalf("sibling: %q %v", body, err)
			}
		}
	}
	if reject != "" {
		await("rejected")
	}
	reused, err := client.Do(ctx, Request{Method: "GET", URL: ready.URL + "/reuse"})
	if err != nil {
		t.Fatal(err)
	}
	defer reused.Body.Close()
	if body, err := reused.Body.ReadAll(2); err != nil || string(body) != "ok" {
		t.Fatalf("reuse: %q %v", body, err)
	}
	await("complete")
	var result struct {
		Connections     int  `json:"connections"`
		HealthyReleased bool `json:"healthy_released"`
		Requests        []struct {
			Path    string     `json:"path"`
			Stream  int        `json:"stream"`
			Headers [][]string `json:"headers"`
		} `json:"requests"`
	}
	receipt("result.json", &result)
	paths := []string{"/events", "/healthy", "/events", "/events", "/reuse"}
	ids := []string{"", "7", "9"}
	if reject == "initial" {
		paths = []string{"/events", "/reuse"}
		ids = []string{""}
	} else if reject == "reconnect" {
		paths = []string{"/events", "/events", "/reuse"}
		ids = []string{"", "7"}
	}
	if result.Connections != 1 || len(result.Requests) != len(paths) || result.HealthyReleased != (reject == "") {
		t.Fatalf("peer summary: %+v", result)
	}
	seen := make(map[int]bool)
	index := 0
	for i, request := range result.Requests {
		if request.Path != paths[i] || seen[request.Stream] {
			t.Fatalf("request order/isolation: %+v", result.Requests)
		}
		seen[request.Stream] = true
		if request.Path == "/events" {
			var values []string
			for _, header := range request.Headers {
				if len(header) == 2 && header[0] == "last-event-id" {
					values = append(values, header[1])
				}
			}
			expected := ids[index]
			index++
			if (expected == "" && len(values) != 0) || (expected != "" && (len(values) != 1 || values[0] != expected)) {
				t.Fatalf("committed IDs: %v, want %q", values, expected)
			}
		}
	}
	if _, err := io.WriteString(input, "stop\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		settled = true
		if err != nil || stderr.Len() != 0 {
			t.Fatalf("peer exit: %v %s", err, stderr.String())
		}
	case <-time.After(8 * time.Second):
		t.Fatal("peer did not exit")
	}
	if _, err := os.Stat(filepath.Join(directory, "error.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("peer failure receipt: %v", err)
	}
}
