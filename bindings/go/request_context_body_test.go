package phantom

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchUploadContextWorksForEachBodySource(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Fetch-Mode") != "cors" || r.Header.Get("Sec-Fetch-Dest") != "empty" {
			t.Errorf("upload context: %v", r.Header)
		}
		if r.URL.Path == "/multipart" {
			if err := r.ParseMultipartForm(1024); err != nil {
				t.Errorf("parse multipart: %v", err)
				return
			}
			if r.MultipartForm != nil {
				defer r.MultipartForm.RemoveAll()
			}
			if r.FormValue("message") != "payload" {
				t.Errorf("multipart payload: %v", r.Form)
			}
		} else {
			data, err := io.ReadAll(io.LimitReader(r.Body, 1024))
			if err != nil || string(data) != "message=payload" {
				t.Errorf("upload payload: %q, %v", data, err)
			}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer peer.Close()
	client := newClient(t)
	prepared, err := PrepareForm([]FormField{{Name: "message", Value: "payload"}}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	source := &ownedUpload{Reader: strings.NewReader("message=payload")}
	multipart := &StreamingMultipart{Boundary: "context-bound", MaximumBytes: 1024, Parts: []MultipartPart{MultipartText("message", "payload")}}
	multipartType, err := multipart.ContentType()
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []Request{
		{URL: peer.URL + "/bytes", Body: []byte("message=payload")},
		{URL: peer.URL + "/stream", Upload: source},
		{URL: peer.URL + "/prepared", PreparedBody: prepared},
		{URL: peer.URL + "/multipart", Multipart: multipart},
	} {
		request.Method = "POST"
		request.Context = "fetchUpload"
		contentType := "application/x-www-form-urlencoded"
		if request.Multipart != nil {
			contentType = multipartType
		}
		request.Headers = []Header{{Name: "Origin", Value: []byte(peer.URL)}, {Name: "Referer", Value: []byte(peer.URL + "/page")}, {Name: "Content-Type", Value: []byte(contentType)}}
		response, err := client.Do(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if data, err := response.Body.ReadAll(2); err != nil || string(data) != "ok" {
			t.Fatalf("response: %q, %v", data, err)
		}
	}
	waitUploadClosed(t, &source.closes)
}
