package phantom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionSnapshotRetainsStateAndRestoresIndependentPoolsAndConfiguration(t *testing.T) {
	type observation struct{ Connection, Cookie, Target, Mode string }
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(observation{r.RemoteAddr, r.Header.Get("Cookie"), r.RequestURI, r.Header.Get("Sec-Fetch-Mode")}); err != nil {
			t.Errorf("peer response: %v", err)
		}
	}))
	defer peer.Close()
	config := Config{Profile: profile, Protocol: "h1", Context: "fetch", BaseURL: peer.URL + "/base/", Timeout: 5 * time.Second}
	source, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	receiving, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer receiving.Close()
	observe := func(client *Client, path string) observation {
		t.Helper()
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: path})
		if err != nil {
			t.Fatal(err)
		}
		data, err := response.Body.ReadAll(2048)
		if err != nil {
			t.Fatal(err)
		}
		var result observation
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		if result.Target != "/base/"+path || result.Mode != "cors" || response.Protocol != "h1" {
			t.Fatalf("retained configuration: %+v", result)
		}
		return result
	}
	if err := source.SetCookie(peer.URL, "checkpoint=original; Path=/"); err != nil {
		t.Fatal(err)
	}
	if err := receiving.SetCookie(peer.URL, "receiver=untouched; Path=/"); err != nil {
		t.Fatal(err)
	}
	first := observe(source, "source")
	key := [32]byte{42}
	snapshot, err := source.ExportSession(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(snapshot, []byte("checkpoint=original")) || key[0] != 42 {
		t.Fatal("plaintext checkpoint or caller key changed")
	}
	if err := source.SetCookie(peer.URL, "checkpoint=changed; Path=/"); err != nil {
		t.Fatal(err)
	}
	child, err := receiving.RestoreSession(context.Background(), snapshot, key, []SessionRoute{
		{}, {Proxy: "http://127.0.0.1:80"},
		{Proxy: "socks5h://127.0.0.1:81", ProxyCredentials: &ProxyCredentials{Username: "user", Password: "password"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	second := observe(child, "child")
	third := observe(child, "reuse")
	if second.Cookie != "checkpoint=original" || second.Connection == first.Connection || third.Connection != second.Connection {
		t.Fatalf("independent pools/state: %+v %+v %+v", first, second, third)
	}
	if value, err := receiving.CookiesForURL(peer.URL); err != nil || value != "receiver=untouched" {
		t.Fatalf("receiver changed: %q %v", value, err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if got := observe(source, "after-child-close"); got.Cookie != "checkpoint=changed" || got.Connection != first.Connection {
		t.Fatalf("source changed: %+v", got)
	}
	child, err = receiving.RestoreSession(context.Background(), snapshot, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if got := observe(child, "after-source-close"); got.Cookie != "checkpoint=original" {
		t.Fatalf("source close changed child: %+v", got)
	}
}

func TestSessionSnapshotTypedErrorsBoundsAndUnsupportedSettings(t *testing.T) {
	key := [32]byte{17}
	source, err := New(Config{Profile: profile, Protocol: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := source.SetCookie("https://origin.example/", "sensitive=secret; Secure; Path=/"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := source.ExportSession(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(snapshot)
	corrupt[len(corrupt)-1] ^= 1
	version := bytes.Clone(snapshot)
	version[8], version[9] = 0, 255
	for _, test := range []struct {
		input []byte
		key   [32]byte
		kind  string
	}{
		{snapshot, [32]byte{18}, "authentication"},
		{corrupt, key, "authentication"},
		{version, key, "incompatible"},
		{[]byte("short"), key, "invalid_snapshot"},
		{make([]byte, maxSessionSnapshot), key, "invalid_snapshot"},
		{make([]byte, maxSessionSnapshot+1), key, "too_large"},
	} {
		child, err := source.RestoreSession(context.Background(), test.input, test.key, nil)
		if child != nil {
			_ = child.Close()
			t.Fatal("failed restore published a client")
		}
		var checkpoint *SessionSnapshotError
		var native *Error
		if !errors.As(err, &checkpoint) || !errors.As(err, &native) || checkpoint.Kind != test.kind || strings.Contains(fmt.Sprintf("%+v", err), "secret") {
			t.Fatalf("checkpoint error: %v; want %s", err, test.kind)
		}
	}
	if value, err := source.CookiesForURL("https://origin.example/"); err != nil || value != "sensitive=secret" {
		t.Fatalf("source changed: %q %v", value, err)
	}
	for _, test := range []struct {
		config Config
		kind   string
	}{
		{Config{Profile: profile, Protocol: "h1", DisableCookies: true}, "disabled"},
		{Config{Profile: profile, Protocol: "h1", Proxy: "http://127.0.0.1:80"}, "incompatible"},
	} {
		receiving, err := New(test.config)
		if err != nil {
			t.Fatal(err)
		}
		child, err := receiving.RestoreSession(context.Background(), snapshot, key, nil)
		_ = receiving.Close()
		if child != nil {
			_ = child.Close()
			t.Fatal("incompatible restore published a client")
		}
		var checkpoint *SessionSnapshotError
		if !errors.As(err, &checkpoint) || checkpoint.Kind != test.kind {
			t.Fatalf("restore: %v; want %s", err, test.kind)
		}
	}
	authenticated, err := New(Config{Profile: profile, Protocol: "h1", Proxy: "http://127.0.0.1:80", ProxyCredentials: &ProxyCredentials{Username: "secret", Password: "password"}})
	if err != nil {
		t.Fatal(err)
	}
	defer authenticated.Close()
	_, err = authenticated.ExportSession(context.Background(), key)
	var checkpoint *SessionSnapshotError
	if !errors.As(err, &checkpoint) || checkpoint.Kind != "unsupported" {
		t.Fatalf("unsupported export: %v", err)
	}
	if _, err := source.RestoreSession(context.Background(), snapshot, key, []SessionRoute{{Proxy: "ftp://127.0.0.1:80"}}); kind(err) != "invalid_proxy_scheme" {
		t.Fatalf("invalid route: %v", err)
	}
	if _, err := source.RestoreSession(context.Background(), snapshot, key, make([]SessionRoute, 257)); kind(err) != "input_limit" {
		t.Fatalf("route count: %v", err)
	}
	child, err := source.RestoreSession(context.Background(), snapshot, key, make([]SessionRoute, 256))
	if err != nil {
		t.Fatalf("allowed route count: %v", err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionSnapshotContextPriorityAndRedaction(t *testing.T) {
	var missing *Client
	key := [32]byte{42}
	if _, err := missing.ExportSession(nil, key); kind(err) != "invalid_context" {
		t.Fatalf("nil context: %v", err)
	}
	if _, err := missing.RestoreSession(nil, nil, key, nil); kind(err) != "invalid_context" {
		t.Fatalf("nil restore context: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := missing.ExportSession(ctx, key); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel priority: %v", err)
	}
	if _, err := missing.RestoreSession(ctx, nil, key, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("restore cancel priority: %v", err)
	}
	if _, err := missing.RestoreSession(context.Background(), nil, key, nil); kind(err) != "client_closed" {
		t.Fatalf("nil receiver: %v", err)
	}
	route := SessionRoute{Proxy: "http://secret.invalid", ProxyCredentials: &ProxyCredentials{Username: "secret-user", Password: "secret-password"}}
	if text := fmt.Sprintf("%+v %#v", route, route); strings.Contains(text, "secret") {
		t.Fatal("route formatting leaked credentials")
	}
	err := snapshotError("authentication")
	var native *Error
	if !errors.As(err, &native) || native.Kind != "session_snapshot_authentication" {
		t.Fatal("native error identity lost")
	}
}

func TestSessionSnapshotCancellationReleasesPreparedCiphertextAndUnpublishedClient(t *testing.T) {
	source := newClient(t)
	key := [32]byte{42}
	value, err := sessionCall(context.Background(), map[string]any{"kind": "export", "client": source.id.Load()}, key[:], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var prepared struct {
		Operation uint64 `json:"operation"`
		Length    int    `json:"length"`
	}
	if err := json.Unmarshal(value, &prepared); err != nil || prepared.Operation == 0 || prepared.Length <= 0 {
		t.Fatalf("prepared export: %s %v", value, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if output, err := copySession(ctx, value); output != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ciphertext handoff: %d %v", len(output), err)
	}
	if _, err := sessionCall(context.Background(), map[string]any{"kind": "copy", "operation": prepared.Operation}, nil, nil, make([]byte, prepared.Length)); kind(err) != "invalid_handle" {
		t.Fatalf("cancelled export retained native operation: %v", err)
	}

	snapshot, err := source.ExportSession(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	value, err = sessionCall(context.Background(), map[string]any{"kind": "restore", "client": source.id.Load(), "receiving_routes": []SessionRoute{}}, key[:], snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	var restored struct {
		ID uint64 `json:"id"`
	}
	if err := json.Unmarshal(value, &restored); err != nil || restored.ID == 0 {
		t.Fatalf("prepared restore: %s %v", value, err)
	}
	if child, err := acceptSession(ctx, value); child != nil || !errors.Is(err, context.Canceled) {
		if child != nil {
			_ = child.Close()
		}
		t.Fatalf("cancelled owner handoff: %v", err)
	}
	if _, err := dispatch(map[string]any{"kind": "cookie_get", "client": restored.ID, "url": "https://origin.example/"}, nil); kind(err) != "invalid_handle" {
		t.Fatalf("cancelled restore retained native client: %v", err)
	}
	if err := source.SetCookie("https://origin.example/", "still=live; Secure; Path=/"); err != nil {
		t.Fatalf("cancellation changed source: %v", err)
	}
}
