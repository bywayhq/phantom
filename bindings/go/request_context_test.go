package phantom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequestContextFlagsFollowTheTypedABI(t *testing.T) {
	for code, name := range []string{"", "raw", "navigation", "fetch", "fetchNoStore", "fetchUpload", "script", "stylesheet", "image", "font"} {
		flags, err := requestContextFlags(name)
		if err != nil || flags != uint64(code)<<5 {
			t.Fatalf("context %q: flags=%d, error=%v", name, flags, err)
		}
	}
	for _, name := range []string{"profile", "inherit", "Fetch", "fetch_no_store", "unknown"} {
		if _, err := requestContextFlags(name); kind(err) != "invalid_context" {
			t.Fatalf("invalid context %q: %v", name, err)
		}
	}
}

func TestUnknownRequestContextClosesUploadBeforeNativeAdmission(t *testing.T) {
	client := &Client{}
	client.id.Store(1)
	for _, multipart := range []bool{false, true} {
		source := &ownedUpload{Reader: strings.NewReader("unread")}
		request := Request{Method: "POST", URL: "http://127.0.0.1/", Context: "unknown", Upload: source}
		if multipart {
			request.Upload = nil
			request.Multipart = &StreamingMultipart{Boundary: "bound", MaximumBytes: 1024, Parts: []MultipartPart{MultipartReader("file", source)}}
		}
		_, err := client.Do(context.Background(), request)
		if kind(err) != "invalid_context" || source.closes.Load() != 1 || source.bytes.Load() != 0 {
			t.Fatalf("invalid context consumed upload: error=%v, closes=%d, bytes=%d", err, source.closes.Load(), source.bytes.Load())
		}
	}
}

type contextObservation struct {
	Mode, Destination, Cache, Address string
}

func contextResponse(response *Response, err error) (contextObservation, error) {
	if err != nil {
		return contextObservation{}, err
	}
	data, err := response.Body.ReadAll(4096)
	if err != nil {
		return contextObservation{}, err
	}
	var observed contextObservation
	err = json.Unmarshal(data, &observed)
	return observed, err
}

func TestRequestContextsReuseOneConnectionWithoutChangingTheDefault(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(contextObservation{r.Header.Get("Sec-Fetch-Mode"), r.Header.Get("Sec-Fetch-Dest"), r.Header.Get("Cache-Control"), r.RemoteAddr}); err != nil {
			t.Errorf("write observation: %v", err)
		}
	}))
	defer peer.Close()
	client, err := New(Config{Profile: "chrome-154-windows", Protocol: "h1", Context: "navigation", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	address := ""
	for _, test := range []struct {
		context, mode, destination, cache string
	}{
		{"", "navigate", "document", ""},
		{"fetch", "cors", "empty", ""},
		{"raw", "", "", ""},
		{"", "navigate", "document", ""},
		{"fetchNoStore", "cors", "empty", "no-cache"},
		{"navigation", "navigate", "document", ""},
	} {
		observed, err := contextResponse(client.Do(context.Background(), Request{Method: "GET", URL: peer.URL, Context: test.context}))
		if err != nil {
			t.Fatalf("context %q: %v", test.context, err)
		}
		if observed.Mode != test.mode || observed.Destination != test.destination || observed.Cache != test.cache {
			t.Fatalf("context %q: %+v", test.context, observed)
		}
		if address == "" {
			address = observed.Address
		} else if observed.Address != address {
			t.Fatalf("context %q opened another connection: %s != %s", test.context, observed.Address, address)
		}
	}
}

func TestConcurrentRequestContextsStayIndependentOnHTTP2(t *testing.T) {
	const count = 12
	var arrived atomic.Int32
	release := make(chan struct{})
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/warm" {
			if arrived.Add(1) == count {
				close(release)
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		if err := json.NewEncoder(w).Encode(contextObservation{r.Header.Get("Sec-Fetch-Mode"), r.Header.Get("Sec-Fetch-Dest"), r.Header.Get("Cache-Control"), r.RemoteAddr}); err != nil {
			t.Errorf("write observation: %v", err)
		}
	}))
	peer.EnableHTTP2 = true
	peer.StartTLS()
	defer peer.Close()
	client, err := New(Config{Profile: "chrome-154-windows", Protocol: "h2", Context: "navigation", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	warm, err := contextResponse(client.Do(context.Background(), Request{Method: "GET", URL: peer.URL + "/warm"}))
	if err != nil {
		t.Fatal(err)
	}
	var requests sync.WaitGroup
	for index := range count {
		requests.Go(func() {
			selected, mode, destination := "fetch", "cors", "empty"
			if index%2 == 0 {
				selected, mode, destination = "navigation", "navigate", "document"
			}
			observed, err := contextResponse(client.Do(context.Background(), Request{Method: "GET", URL: fmt.Sprintf("%s/%d", peer.URL, index), Context: selected}))
			if err != nil {
				t.Errorf("context %s: %v", selected, err)
				return
			}
			if observed.Mode != mode || observed.Destination != destination || observed.Address != warm.Address {
				t.Errorf("context %s contaminated or opened another connection: %+v", selected, observed)
			}
		})
	}
	requests.Wait()
}

func TestResourceContextsUseTheSelectedCatalogProfile(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(contextObservation{r.Header.Get("Sec-Fetch-Mode"), r.Header.Get("Sec-Fetch-Dest"), "", r.RemoteAddr}); err != nil {
			t.Errorf("write observation: %v", err)
		}
	}))
	defer peer.Close()
	client, err := New(Config{Profile: "chrome-156-windows", Protocol: "h1", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, name := range []string{"script", "stylesheet", "image", "font"} {
		observed, err := contextResponse(client.Do(context.Background(), Request{Method: "GET", URL: peer.URL, Context: name, Headers: []Header{{Name: "Referer", Value: []byte(peer.URL + "/page")}, {Name: "Origin", Value: []byte(peer.URL)}}}))
		if err != nil {
			t.Fatalf("context %s: %v", name, err)
		}
		destination := name
		if name == "stylesheet" {
			destination = "style"
		}
		if observed.Destination != destination {
			t.Fatalf("context %s destination: %q", name, observed.Destination)
		}
	}
}

func TestUnavailableRequestContextsNeverReachTheOrigin(t *testing.T) {
	var hits atomic.Uint64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "unexpected")
	}))
	defer peer.Close()
	client := newClient(t)
	for _, name := range []string{"script", "stylesheet", "image", "font"} {
		source := &ownedUpload{Reader: strings.NewReader("unread")}
		_, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Context: name, Upload: source})
		if kind(err) != "request_template" || source.closes.Load() != 1 || source.bytes.Load() != 0 {
			t.Fatalf("context %s: error=%v, closes=%d, bytes=%d", name, err, source.closes.Load(), source.bytes.Load())
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("unavailable contexts sent %d requests", hits.Load())
	}
}

func TestImportedProfileContextKeepsItsDefaultAndRejectsCatalogSelection(t *testing.T) {
	owner := catalogProfile(t, "navigation")
	document, err := owner.ExportJSON()
	if err != nil {
		t.Fatal(err)
	}
	custom, err := ImportProfileJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	defer custom.Close()
	client, err := New(Config{ProfileSettings: custom, Protocol: "h1", Context: "profile", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var hits atomic.Uint64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if err := json.NewEncoder(w).Encode(contextObservation{Mode: r.Header.Get("Sec-Fetch-Mode")}); err != nil {
			t.Errorf("write observation: %v", err)
		}
	}))
	defer peer.Close()
	for _, name := range []string{"", "raw", ""} {
		observed, err := contextResponse(client.Do(context.Background(), Request{Method: "GET", URL: peer.URL, Context: name}))
		if err != nil {
			t.Fatal(err)
		}
		mode := "navigate"
		if name == "raw" {
			mode = ""
		}
		if observed.Mode != mode {
			t.Fatalf("context %q changed default: %+v", name, observed)
		}
	}
	_, err = client.Do(context.Background(), Request{Method: "GET", URL: peer.URL, Context: "fetch"})
	if kind(err) != "request_template" || hits.Load() != 3 {
		t.Fatalf("imported settings invented catalog context: error=%v, sends=%d", err, hits.Load())
	}
}
