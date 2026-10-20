package phantom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInvalidCollectionLimitClosesBodyAndAllowsRepeatedClose(t *testing.T) {
	disconnected := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(disconnected)
	}))
	defer server.Close()
	client := newClient(t)
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if data, err := response.Body.ReadAll(-1); data != nil || kind(err) != "invalid_body_limit" {
		t.Fatalf("invalid collection: %q, %v", data, err)
	}
	if _, err := response.Body.Read(make([]byte, 1)); kind(err) != "body_closed" {
		t.Fatalf("invalid collection left body readable: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("repeated close: %v", err)
	}
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("invalid collection did not close the native response")
	}
}
