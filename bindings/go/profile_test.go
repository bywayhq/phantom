package phantom

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func catalogProfile(t *testing.T, context string) *Profile {
	t.Helper()
	p, err := NewCatalogProfile(profile, context)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestProfileRoundTripPrecisionIndependentEditsAndRedaction(t *testing.T) {
	exact := catalogProfile(t, "navigation")
	if exact.CatalogID() != profile {
		t.Fatal("lost exact identity")
	}
	description, err := exact.Describe()
	if err != nil {
		t.Fatal(err)
	}
	settings := description["profile"].(map[string]any)
	ttl := settings["dns_cache"].(map[string]any)["ttl"].(map[string]any)
	ttl["seconds"] = json.Number("9007199254740993")
	settings["tls"].(map[string]any)["session_ticket_order"] = "OldestFirst"
	document, err := json.Marshal(description)
	if err != nil {
		t.Fatal(err)
	}
	custom, err := ImportProfileJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	defer custom.Close()
	clear(document)
	if custom.CatalogID() != "" {
		t.Fatal("import invented catalog evidence")
	}
	exported, err := custom.ExportJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(exported, []byte("9007199254740993")) {
		t.Fatal("u64 precision lost")
	}
	second, err := ImportProfileJSON(exported)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	clear(exported)
	got, err := second.Describe()
	if err != nil {
		t.Fatal(err)
	}
	gotTTL := got["profile"].(map[string]any)["dns_cache"].(map[string]any)["ttl"].(map[string]any)["seconds"]
	if gotTTL != json.Number("9007199254740993") {
		t.Fatalf("precision: %v", gotTTL)
	}
	original, err := exact.Describe()
	if err != nil {
		t.Fatal(err)
	}
	if original["profile"].(map[string]any)["tls"].(map[string]any)["session_ticket_order"] == "OldestFirst" {
		t.Fatal("editing mutated source")
	}
	settings["tls"].(map[string]any)["session_ticket_order"] = "private-secret-value"
	document, err = json.Marshal(description)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ImportProfileJSON(document)
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != "profile_import_unsupported_setting" || failure.Field != "tls.session_ticket_order" {
		t.Fatalf("category/field: %v", err)
	}
	if strings.Contains(fmt.Sprint(err), "private-secret-value") || strings.Contains(fmt.Sprintf("%#v", custom), "OldestFirst") {
		t.Fatal("diagnostic exposed settings")
	}
}

func TestProfileOwnersExceedHTTPQuotaAndCloseDoesNotAffectClients(t *testing.T) {
	var owners []*Profile
	defer func() {
		for _, owner := range owners {
			_ = owner.Close()
		}
	}()
	for range 80 {
		owner, err := NewCatalogProfile(profile, "")
		if err != nil {
			t.Fatal(err)
		}
		owners = append(owners, owner)
	}
	client, err := New(Config{ProfileSettings: owners[0], Protocol: "h1", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := owners[0].Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := owners[0].ExportJSON(); kind(err) != "profile_closed" {
		t.Fatalf("closed export: %v", err)
	}
	if _, err := New(Config{ProfileSettings: owners[0], Protocol: "h1"}); kind(err) != "profile_closed" {
		t.Fatalf("closed client: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	data, err := response.Body.ReadAll(2)
	if err != nil || string(data) != "ok" {
		t.Fatalf("retained settings: %q %v", data, err)
	}
}

func TestProfileContextSelectionUsesImportedTemplateAndRetainsOrdering(t *testing.T) {
	exact := catalogProfile(t, "navigation")
	description, err := exact.Describe()
	if err != nil {
		t.Fatal(err)
	}
	settings := description["profile"].(map[string]any)
	template := settings["request_template"].(map[string]any)
	fields := template["http1_fields"].([]any)
	template["http1_fields"] = append([]any{
		map[string]any{"variant": "Literal", "name": "X-Custom-First", "value": "first"},
		map[string]any{"variant": "Literal", "name": "X-Custom-Second", "value": "second"},
	}, fields...)
	document, err := json.Marshal(description)
	if err != nil {
		t.Fatal(err)
	}
	custom, err := ImportProfileJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	defer custom.Close()
	for _, config := range []Config{
		{Profile: profile, ProfileSettings: custom, Protocol: "h1"},
		{Protocol: "h1"},
	} {
		if _, err := New(config); kind(err) != "invalid_profile_selection" {
			t.Fatalf("selection: %v", err)
		}
	}
	if _, err := New(Config{ProfileSettings: custom, Protocol: "h1", Context: "navigation"}); kind(err) != "context_unavailable" {
		t.Fatalf("borrowed catalog: %v", err)
	}
	if _, err := New(Config{ProfileSettings: custom, Protocol: "h1", Context: "unknown"}); kind(err) != "invalid_context" {
		t.Fatalf("unknown context: %v", err)
	}
	for _, selected := range []string{"raw", "profile"} {
		t.Run(selected, func(t *testing.T) {
			client, err := New(Config{ProfileSettings: custom, Protocol: "h1", Context: selected, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			type observation struct {
				head string
				err  error
			}
			done := make(chan observation, 1)
			go func() {
				head, err := func() (string, error) {
					connection, err := listener.AcceptTCP()
					if err != nil {
						return "", err
					}
					defer connection.Close()
					if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						return "", err
					}
					reader := bufio.NewReader(io.LimitReader(connection, 32*1024))
					var head strings.Builder
					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							return "", err
						}
						head.WriteString(line)
						if line == "\r\n" {
							break
						}
					}
					_, err = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
					return head.String(), err
				}()
				done <- observation{head, err}
			}()
			joined := false
			defer func() {
				if !joined {
					_ = listener.Close()
					if observed := <-done; observed.err != nil {
						t.Logf("settled peer: %v", observed.err)
					}
				}
			}()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: "http://" + listener.Addr().String(), Headers: []Header{{Name: "User-Agent", Value: []byte("Phantom-Test Chrome/154.0.0.0")}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := response.Body.ReadAll(2); err != nil {
				t.Fatal(err)
			}
			observed := <-done
			joined = true
			if observed.err != nil {
				t.Fatal(observed.err)
			}
			if selected == "profile" {
				if !strings.Contains(observed.head, "\r\nX-Custom-First: first\r\nX-Custom-Second: second\r\n") {
					t.Fatalf("template order: %q", observed.head)
				}
			} else if strings.Contains(observed.head, "X-Custom-") {
				t.Fatalf("raw context used template: %q", observed.head)
			}
		})
	}
}

func TestProfileFullDocumentLimitAndCloseRaces(t *testing.T) {
	exact := catalogProfile(t, "")
	document, err := exact.ExportJSON()
	if err != nil {
		t.Fatal(err)
	}
	// Whitespace is legal JSON input; prove the channel is not the 8 MiB upload path.
	large := make([]byte, maxProfileDocument)
	copy(large, document)
	for index := len(document); index < len(large); index++ {
		large[index] = ' '
	}
	owner, err := ImportProfileJSON(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportProfileJSON(append(large, ' ')); kind(err) != "input_limit" {
		t.Fatalf("document bound: %v", err)
	}
	for range 8 {
		owner, err := NewCatalogProfile(profile, "")
		if err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		workers.Go(func() {
			if err := owner.Close(); err != nil {
				t.Error(err)
			}
		})
		workers.Go(func() {
			if _, err := owner.ExportJSON(); err != nil && kind(err) != "profile_closed" {
				t.Error(err)
			}
		})
		workers.Go(func() {
			client, err := New(Config{ProfileSettings: owner, Protocol: "h1"})
			if err != nil {
				if kind(err) != "profile_closed" {
					t.Error(err)
				}
				return
			}
			if err := client.Close(); err != nil {
				t.Error(err)
			}
		})
		workers.Wait()
	}
}
