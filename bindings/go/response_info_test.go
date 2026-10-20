package phantom

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
)

func TestResponseInfoKeepsDefaultRedirectPolicyAndActualURL(t *testing.T) {
	var lock sync.Mutex
	var targets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		targets = append(targets, r.RequestURI)
		lock.Unlock()
		if r.URL.Path == "/original" {
			w.Header().Set("Location", "/final%2Fpath?x=1")
			w.WriteHeader(http.StatusFound)
		}
		_, _ = io.WriteString(w, "body")
	}))
	defer server.Close()
	client := newClient(t)
	for index, target := range []string{"/original?x=a%20b", "/final%2Fpath?x=1"} {
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + target})
		if err != nil {
			t.Fatal(err)
		}
		wantStatus := http.StatusOK
		if index == 0 {
			wantStatus = http.StatusFound
		}
		if response.Status != wantStatus || response.Protocol != "h1" || response.EffectiveURL != server.URL+target || response.RedirectsFollowed != 0 || response.ConnectionSetupRetries != 0 {
			t.Fatalf("response metadata: %+v", response)
		}
		body, err := response.Body.ReadAll(4)
		if err != nil || string(body) != "body" {
			t.Fatalf("body: %q %v", body, err)
		}
	}
	lock.Lock()
	defer lock.Unlock()
	if !reflect.DeepEqual(targets, []string{"/original?x=a%20b", "/final%2Fpath?x=1"}) {
		t.Fatalf("origin traffic: %v", targets)
	}
}
