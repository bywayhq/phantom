package phantom

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTLSSetupTimeoutClosesBlockedUploadReader(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	client, err := New(Config{Profile: profile, Protocol: "h2", Timeouts: Timeouts{Connect: LimitTimeout(250 * time.Millisecond), Total: LimitTimeout(5 * time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	source := newGatedUpload()
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: "https://" + listener.Addr().String(), Upload: source})
	if response != nil {
		_ = response.Body.Close()
	}
	select {
	case <-source.started:
	default:
		t.Fatal("source Read did not overlap TLS setup")
	}
	select {
	case connection := <-accepted:
		_ = connection.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("TLS peer never accepted connection")
	}
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != "timeout" || failure.TimeoutPhase != "connect" {
		t.Fatalf("TLS setup deadline: %v", err)
	}
	waitUploadClosed(t, &source.closes)
}

func TestEarlyHTTP2ReadIdleTimeoutClosesBlockedUploadReader(t *testing.T) {
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "head")
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	peer.EnableHTTP2 = true
	peer.StartTLS()
	defer peer.Close()
	client, err := New(Config{Profile: profile, Protocol: "h2", AdditionalRootsDER: [][]byte{peer.Certificate().Raw}, Timeouts: Timeouts{ReadIdle: LimitTimeout(250 * time.Millisecond), Total: LimitTimeout(5 * time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	source := newGatedUpload()
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: peer.URL, Upload: source})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, err = response.Body.ReadAll(16)
	select {
	case <-source.started:
	default:
		t.Fatal("source Read did not overlap response body wait")
	}
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != "timeout" || failure.TimeoutPhase != "read_idle" {
		t.Fatalf("response idle deadline: %v", err)
	}
	waitUploadClosed(t, &source.closes)
}
