package phantom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestForkSharesSelectedCookiesWithIndependentReusablePoolsAndShutdown(t *testing.T) {
	type observation struct{ Connection, Cookie, Target string }
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/learn") {
			w.Header().Set("Set-Cookie", "seen=learned; Path=/")
		}
		_ = json.NewEncoder(w).Encode(observation{r.RemoteAddr, r.Header.Get("Cookie"), r.RequestURI})
	}))
	defer peer.Close()
	source, err := New(Config{Profile: profile, Protocol: "h1", BaseURL: peer.URL + "/api/", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	observe := func(client *Client, target string) observation {
		t.Helper()
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: target})
		if err != nil {
			t.Fatal(err)
		}
		if response.Protocol != "h1" || response.Status != 200 {
			t.Fatalf("head: %s %d", response.Protocol, response.Status)
		}
		data, err := response.Body.ReadAll(1024)
		if err != nil {
			t.Fatal(err)
		}
		var got observation
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if got.Target != "/api/"+target {
			t.Fatalf("base URL: %s", got.Target)
		}
		return got
	}
	learned := observe(source, "learn")
	shared, err := source.Fork(SessionSharing{Cookies: true, DNS: true, ClientHints: true, Discovery: true, Tickets: true})
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	isolated, err := source.Fork(SessionSharing{})
	if err != nil {
		t.Fatal(err)
	}
	defer isolated.Close()
	first := observe(shared, "shared-first")
	second := observe(shared, "shared-second")
	original := observe(source, "source")
	empty := observe(isolated, "isolated")
	if first.Cookie != "seen=learned" || second.Cookie != first.Cookie || original.Cookie != first.Cookie || empty.Cookie != "" {
		t.Fatalf("cookie selection: %q %q %q %q", first.Cookie, second.Cookie, original.Cookie, empty.Cookie)
	}
	if learned.Connection != original.Connection || first.Connection != second.Connection || first.Connection == original.Connection || empty.Connection == first.Connection || empty.Connection == original.Connection {
		t.Fatalf("pool identities: %q %q %q %q %q", learned.Connection, original.Connection, first.Connection, second.Connection, empty.Connection)
	}
	if err := shared.ClearCookies(); err != nil {
		t.Fatal(err)
	}
	if value, err := source.CookiesForURL(peer.URL); err != nil || value != "" {
		t.Fatalf("shared clear: %q %v", value, err)
	}
	if err := source.SetCookie(peer.URL, "later=yes; Path=/"); err != nil {
		t.Fatal(err)
	}
	if got := observe(shared, "later"); got.Cookie != "later=yes" {
		t.Fatalf("live update: %q", got.Cookie)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Fork(SessionSharing{}); kind(err) != "client_closed" {
		t.Fatalf("released source: %v", err)
	}
	if got := observe(shared, "after-source-close"); got.Cookie != "later=yes" {
		t.Fatalf("remaining fork: %q", got.Cookie)
	}
	if err := shared.Close(); err != nil {
		t.Fatal(err)
	}
	if got := observe(isolated, "after-shared-close"); got.Cookie != "" {
		t.Fatalf("isolated state changed: %q", got.Cookie)
	}
}

func TestForkPreservesTrustTemplateAndClientTimeouts(t *testing.T) {
	peer := tlsPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/head" {
			<-r.Context().Done()
			return
		}
		if r.RequestURI != "/api/a%2Fb?x=1" || r.Header.Get("Sec-Fetch-Mode") != "navigate" || r.Header.Get("User-Agent") != "Phantom-Test Chrome/154.0.0.0" {
			t.Errorf("preserved settings: %s %v", r.RequestURI, r.Header)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	settings := catalogProfile(t, "navigation")
	source, err := New(Config{ProfileSettings: settings, Protocol: "h1", Context: "profile", BaseURL: peer.URL + "/api/", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeouts: Timeouts{ResponseHead: LimitTimeout(0), Total: LimitTimeout(5 * time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := settings.Close(); err != nil {
		t.Fatal(err)
	}
	fork, err := source.Fork(SessionSharing{})
	if err != nil {
		t.Fatal(err)
	}
	defer fork.Close()
	headers := []Header{{Name: "User-Agent", Value: []byte("Phantom-Test Chrome/154.0.0.0")}}
	_, err = fork.Do(context.Background(), Request{Method: "GET", URL: "head", Headers: headers})
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != "timeout" || failure.TimeoutPhase != "response_head" {
		t.Fatalf("inherited zero head: %v", err)
	}
	response, err := fork.Do(context.Background(), Request{Method: "GET", URL: "a%2Fb?x=1", Headers: headers, Timeouts: Timeouts{ResponseHead: Timeout{Mode: TimeoutDisabled}}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := response.Body.ReadAll(2)
	if err != nil || string(data) != "ok" || response.Protocol != "h1" {
		t.Fatalf("fork response: %q %v", data, err)
	}
}

func TestForkDoesNotEnableDisabledCookiesAndCloseRaceReclaimsOwners(t *testing.T) {
	disabled, err := New(Config{Profile: profile, Protocol: "h1", DisableCookies: true})
	if err != nil {
		t.Fatal(err)
	}
	defer disabled.Close()
	fork, err := disabled.Fork(SessionSharing{Cookies: true})
	if err != nil {
		t.Fatal(err)
	}
	defer fork.Close()
	if err := fork.SetCookie("http://example.test/", "disabled=yes"); kind(err) != "cookies_disabled" {
		t.Fatalf("enabled disabled state: %v", err)
	}
	for range 8 {
		source, err := New(Config{Profile: profile, Protocol: "h1"})
		if err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		workers.Go(func() {
			if err := source.Close(); err != nil {
				t.Error(err)
			}
		})
		workers.Go(func() {
			owner, err := source.Fork(SessionSharing{})
			if err != nil {
				if kind(err) != "client_closed" {
					t.Error(err)
				}
				return
			}
			if err := owner.Close(); err != nil {
				t.Error(err)
			}
		})
		workers.Wait()
		if _, err := source.Fork(SessionSharing{}); kind(err) != "client_closed" {
			t.Fatalf("released source after race: %v", err)
		}
	}
}
