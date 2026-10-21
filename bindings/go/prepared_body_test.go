package phantom

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPreparedFormPreservesOrderAndCanBeReused(t *testing.T) {
	body, err := PrepareForm([]FormField{{"q", "a +"}, {"q", ""}, {"", "é"}}, 128)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	expected := "q=a+%2B&q=&=%C3%A9"
	if body.Len() != uint64(len(expected)) || body.ContentType() != "application/x-www-form-urlencoded;charset=UTF-8" {
		t.Fatalf("incorrect encoded metadata: %d %q", body.Len(), body.ContentType())
	}
	checkPreparedRequests(t, body, expected)
}

func TestPreparedMultipartKeepsDuplicateFieldsAndCopiesByteInputs(t *testing.T) {
	data := []byte("a\x00b")
	body, err := PrepareMultipart([]MultipartPart{
		MultipartText("tag", "first\nsecond"),
		MultipartBytes("tag", data).WithFilename("a\".bin").WithContentType("application/x-custom"),
	}, "fixture", 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	data[0] = 'z'
	expected := "--fixture\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\nfirst\r\nsecond\r\n" +
		"--fixture\r\nContent-Disposition: form-data; name=\"tag\"; filename=\"a%22.bin\"\r\n" +
		"Content-Type: application/x-custom\r\n\r\na\x00b\r\n--fixture--\r\n"
	if body.Len() != uint64(len(expected)) || body.ContentType() != "multipart/form-data; boundary=fixture" {
		t.Fatalf("incorrect multipart metadata: %d %q", body.Len(), body.ContentType())
	}
	checkPreparedRequests(t, body, expected)
}

func TestPreparedBodySurvivesOwnerCloseAndRedirectReplay(t *testing.T) {
	body, err := PrepareForm([]FormField{{"a", "b"}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	type observation struct {
		target, method, body string
		err                  error
	}
	received := make(chan observation, 2)
	peer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		data, err := io.ReadAll(io.LimitReader(request.Body, 32))
		if request.URL.Path == "/start" && err == nil {
			err = body.Close()
		}
		received <- observation{request.URL.Path, request.Method, string(data), err}
		writer.Header().Set("Content-Length", "0")
		if request.URL.Path == "/start" {
			writer.Header().Set("Location", "/done")
			writer.WriteHeader(http.StatusTemporaryRedirect)
		}
	}))
	defer peer.Close()
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	response, err := client.Do(ctx, Request{Method: "POST", URL: peer.URL + "/start", PreparedBody: body,
		Headers:        []Header{{Name: "Content-Type", Value: []byte(body.ContentType())}},
		RedirectPolicy: &RedirectPolicy{MaximumHops: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := response.Body.ReadAll(0); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/start", "/done"} {
		select {
		case actual := <-received:
			if actual.target != target || actual.method != "POST" || actual.body != "a=b" || actual.err != nil {
				t.Fatalf("redirect request: %+v", actual)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func checkPreparedRequests(t *testing.T, body *PreparedBody, expected string) {
	t.Helper()
	type observation struct{ body, contentType string }
	received := make(chan observation, 2)
	peer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		data, err := io.ReadAll(io.LimitReader(request.Body, 2048))
		if err != nil {
			t.Error(err)
		}
		received <- observation{string(data), request.Header.Get("Content-Type")}
		writer.Header().Set("Content-Length", "0")
	}))
	defer peer.Close()
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for range 2 {
		response, err := client.Do(ctx, Request{Method: "POST", URL: peer.URL, PreparedBody: body,
			Headers: []Header{{Name: "Content-Type", Value: []byte(body.ContentType())}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := response.Body.ReadAll(0); err != nil {
			t.Fatal(err)
		}
		select {
		case actual := <-received:
			if actual.body != expected || actual.contentType != body.ContentType() {
				t.Fatalf("unexpected request body/type: %q %q", actual.body, actual.contentType)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func TestPreparedBodyRejectsMetadataCollisionAndEncodedOverflow(t *testing.T) {
	for _, test := range []struct {
		prepare func() (*PreparedBody, error)
		kind    string
	}{
		{func() (*PreparedBody, error) { return PrepareForm([]FormField{{"a", " "}}, 2) }, "prepared_body_too_large"},
		{func() (*PreparedBody, error) { return PrepareMultipart(nil, "bad boundary", 1024) }, "prepared_body_invalid_boundary"},
		{func() (*PreparedBody, error) {
			return PrepareMultipart([]MultipartPart{MultipartText("a", "--b")}, "b", 1024)
		}, "prepared_body_boundary_collision"},
		{func() (*PreparedBody, error) {
			return PrepareMultipart([]MultipartPart{MultipartBytes("a", nil).WithContentType("text/plain;bad")}, "b", 1024)
		}, "prepared_body_invalid_content_type"},
		{func() (*PreparedBody, error) {
			return PrepareMultipart([]MultipartPart{MultipartText("a\x00", "secret")}, "b", 1024)
		}, "prepared_body_invalid_name"},
		{func() (*PreparedBody, error) { return PrepareMultipart(make([]MultipartPart, 1025), "b", 1024) }, "prepared_body_too_many_parts"},
	} {
		body, err := test.prepare()
		var failure *Error
		if body != nil || !errors.As(err, &failure) || failure.Kind != test.kind || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unexpected preparation result: %v %v", body, err)
		}
	}
	body, err := PrepareForm(nil, 0)
	if err != nil || body.Len() != 0 {
		t.Fatalf("empty form: %v %v", body, err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedCapacityIsReleasedByClose(t *testing.T) {
	owners := make([]*PreparedBody, 0, 64)
	t.Cleanup(func() {
		for _, owner := range owners {
			if err := owner.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	for range 64 {
		body, err := PrepareForm(nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		owners = append(owners, body)
	}
	if body, err := PrepareForm(nil, 0); body != nil || kind(err) != "capacity" {
		t.Fatalf("prepared capacity: %v %v", body, err)
	}
	if err := owners[0].Close(); err != nil {
		t.Fatal(err)
	}
	body, err := PrepareForm(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	owners = append(owners, body)
}

func TestPreparedCloseCanRaceWithRequestAttachment(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		data, err := io.ReadAll(io.LimitReader(request.Body, 32))
		if err != nil || string(data) != "a=b" {
			t.Errorf("attached body: %q %v", data, err)
		}
		writer.Header().Set("Content-Length", "0")
	}))
	defer peer.Close()
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for range 8 {
		body, err := PrepareForm([]FormField{{"a", "b"}}, 10)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		done := make(chan error, 2)
		go func() {
			<-start
			response, err := client.Do(ctx, Request{Method: "POST", URL: peer.URL, PreparedBody: body,
				Headers: []Header{{Name: "Content-Type", Value: []byte(body.ContentType())}}})
			if err == nil {
				_, err = response.Body.ReadAll(0)
			}
			done <- err
		}()
		go func() { <-start; done <- body.Close() }()
		close(start)
		for range 2 {
			select {
			case err := <-done:
				if err != nil && kind(err) != "invalid_handle" {
					t.Fatalf("attachment/close race: %v", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
}

func TestPreparedContentTypeAndBodyConflictsDoNotSpendAttemptBudget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	url := "http://" + listener.Addr().String()
	body, err := PrepareForm([]FormField{{"a", "b"}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	budget, err := NewAttemptBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	client := newClient(t)
	for _, request := range []Request{
		{},
		{Headers: []Header{{Name: "Content-Type", Value: []byte("application/json")}}},
		{Body: []byte{}},
	} {
		request.Method, request.URL = "POST", url
		request.PreparedBody, request.Budget = body, budget
		if response, err := client.Do(context.Background(), request); err == nil || response != nil {
			t.Fatalf("invalid request accepted: %v %v", response, err)
		}
		remaining, err := budget.Remaining()
		if err != nil || remaining != 1 {
			t.Fatalf("invalid request spent budget: %d %v", remaining, err)
		}
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(context.Background(), Request{Method: "POST", URL: url, PreparedBody: body})
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != "invalid_handle" {
		t.Fatalf("closed prepared owner: %v", err)
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if connection != nil {
		connection.Close()
		t.Fatal("invalid prepared request connected to the peer")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("checking no-I/O boundary: %v", err)
	}
}
