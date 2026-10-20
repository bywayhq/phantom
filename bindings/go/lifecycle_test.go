package phantom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConnectionMaintenanceRetainsActiveBodyAndRefreshesLaterUse(t *testing.T) {
	heldAddress := make(chan string, 1)
	release := make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/held" {
			heldAddress <- r.RemoteAddr
			w.Header().Set("Content-Length", "2")
			_, _ = io.WriteString(w, "a")
			w.(http.Flusher).Flush()
			select {
			case <-release:
				_, _ = io.WriteString(w, "b")
			case <-r.Context().Done():
			}
			return
		}
		_, _ = io.WriteString(w, r.RemoteAddr)
	}))
	defer peer.Close()
	client := newClient(t)
	// Close the client before httptest waits for any abandoned peer handler.
	defer client.Close()
	address := func() string {
		t.Helper()
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL})
		if err != nil {
			t.Fatal(err)
		}
		data, err := response.Body.ReadAll(128)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	first := address()
	held, err := client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/held"})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Body.Close()
	if got := <-heldAddress; got != first {
		t.Fatalf("ordinary reuse %q != %q", got, first)
	}
	data := make([]byte, 1)
	if n, err := held.Body.Read(data); n != 1 || err != nil || string(data) != "a" {
		t.Fatalf("held body did not start: %d %v", n, err)
	}
	second := address()
	if second == first {
		t.Fatal("active H1 body used as an idle connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.CloseIdleConnections(ctx); err != nil {
		t.Fatal(err)
	}
	third := address()
	if third == second || third == first {
		t.Fatal("idle connection remained selected")
	}
	if err := client.RefreshConnections(ctx); err != nil {
		t.Fatal(err)
	}
	if fourth := address(); fourth == third || fourth == first || fourth == second {
		t.Fatal("refresh did not select a fresh connection")
	}
	close(release)
	if data, err := held.Body.ReadAll(1); err != nil || string(data) != "b" {
		t.Fatalf("maintenance interrupted active body %q: %v", data, err)
	}
	for _, clear := range []func() error{client.ClearDNSCache, client.ClearClientHints, client.ClearAltSvc, client.ClearAltSvcRacingHistory} {
		if err := clear(); err != nil {
			t.Fatal(err)
		}
	}
	if count, err := client.ClearSessionTickets(); err != nil || count != 0 {
		t.Fatalf("plaintext tickets %d: %v", count, err)
	}
	if err := client.SetCookie(peer.URL, "keep=yes; Path=/"); err != nil {
		t.Fatal(err)
	}
	if err := client.RefreshConnections(ctx); err != nil {
		t.Fatal(err)
	}
	if cookies, err := client.CookiesForURL(peer.URL); err != nil || cookies != "keep=yes" {
		t.Fatalf("refresh discarded cookies %q: %v", cookies, err)
	}
}

func TestMaintenanceContextAndClosedClientErrors(t *testing.T) {
	client := newClient(t)
	defer client.Close()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, maintain := range []func(context.Context) error{client.CloseIdleConnections, client.RefreshConnections} {
		if kind(maintain(nil)) != "invalid_context" {
			t.Fatal("nil context accepted")
		}
		if err := maintain(cancelled); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled context: %v", err)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.RefreshConnections(context.Background()); kind(err) != "client_closed" {
		t.Fatalf("closed maintenance: %v", err)
	}
	if err := client.ClearDNSCache(); kind(err) != "client_closed" {
		t.Fatalf("closed clear: %v", err)
	}
}
