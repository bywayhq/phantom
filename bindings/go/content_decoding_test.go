package phantom

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestContentDecodingWirePreservesInclusiveZeroAndFullUint64(t *testing.T) {
	for _, maximum := range []uint64{0, math.MaxUint64} {
		wire, err := contentDecodingWire(AdvertisedDecoding(maximum))
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(wire)
		want := `{"mode":"advertised","maximum_decoded_bytes":` + strconv.FormatUint(maximum, 10) + `}`
		if err != nil || string(data) != want {
			t.Fatalf("encoding %s: %v; want %s", data, err, want)
		}
	}
	for _, value := range []ContentDecoding{{Mode: "unknown"}, {MaximumDecodedBytes: 1}} {
		if _, err := contentDecodingWire(value); kind(err) != "invalid_content_decoding" {
			t.Fatalf("invalid mode accepted: %v", err)
		}
	}
}

func TestAdvertisedContentDecodingUsesCoreStreamAndRetainsWireFields(t *testing.T) {
	plain := []byte("decoded response")
	encoded := gzipBytes(t, plain)
	var count atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if values := r.Header.Values("Accept-Encoding"); !reflect.DeepEqual(values, []string{"gzip", "br;q=0"}) {
			t.Errorf("caller fields changed: %v", values)
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
		_, _ = w.Write(encoded)
	}))
	defer server.Close()
	client, err := New(Config{Profile: profile, Protocol: "h1", DisableCookies: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, test := range []struct {
		name    string
		policy  ContentDecoding
		want    []byte
		failure string
	}{
		{"default", ContentDecoding{}, encoded, ""},
		{"exact", AdvertisedDecoding(uint64(len(plain))), plain, ""},
		{"overflow", AdvertisedDecoding(uint64(len(plain) - 1)), nil, "response_body_limit"},
		{"zero", AdvertisedDecoding(0), nil, "response_body_limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL,
				Headers: []Header{{Name: "Accept-Encoding", Value: []byte("gzip")}, {Name: "Accept-Encoding", Value: []byte("br;q=0")}}, ContentDecoding: test.policy})
			if err != nil {
				t.Fatal(err)
			}
			if response.Status != 200 || string(header(response, "Content-Encoding")) != "gzip" || string(header(response, "Content-Length")) != strconv.Itoa(len(encoded)) {
				t.Fatalf("wire metadata changed: %#v", response.Headers)
			}
			if test.policy.Mode == DecodingAdvertised && !reflect.DeepEqual(response.DecodedContentCodings, []string{"gzip"}) {
				t.Fatalf("coding chain: %v", response.DecodedContentCodings)
			}
			if test.policy.Mode == DecodingNone && len(response.DecodedContentCodings) != 0 {
				t.Fatalf("default coding chain: %v", response.DecodedContentCodings)
			}
			var prefix []byte
			if test.name == "exact" {
				prefix = make([]byte, 3)
				if _, err := io.ReadFull(response.Body, prefix); err != nil {
					t.Fatal(err)
				}
			}
			data, err := response.Body.ReadAll(1024)
			if (test.failure == "" && err != nil) || kind(err) != test.failure || (err == nil && !bytes.Equal(append(prefix, data...), test.want)) {
				t.Fatalf("body %q: %v", data, err)
			}
		})
	}
	if count.Load() != 4 {
		t.Fatalf("request count=%d", count.Load())
	}
}

func header(response *Response, name string) []byte {
	for _, field := range response.Headers {
		if http.CanonicalHeaderKey(field.Name) == name {
			return field.Value
		}
	}
	return nil
}

func TestContentDecodingRejectsMalformedAndUnadvertisedDataOnBodyRead(t *testing.T) {
	for _, test := range []struct {
		name, advertised, coding string
		data                     []byte
	}{
		{"malformed", "gzip", "gzip", []byte("not gzip")},
		{"unadvertised", "br", "gzip", gzipBytes(t, []byte("ok"))},
		{"unknown", "gzip", "unknown", []byte("data")},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", test.coding)
				_, _ = w.Write(test.data)
			}))
			defer server.Close()
			client, err := New(Config{Profile: profile, Protocol: "h1"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL,
				Headers: []Header{{Name: "Accept-Encoding", Value: []byte(test.advertised)}}, ContentDecoding: AdvertisedDecoding(1024)})
			if err != nil || response.Status != 200 {
				t.Fatalf("head: %v", err)
			}
			if _, err := response.Body.ReadAll(1024); kind(err) != "content_decoding" {
				t.Fatalf("body: %v", err)
			}
		})
	}
	var count atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1) }))
	defer server.Close()
	client, err := New(Config{Profile: profile, Protocol: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Do(context.Background(), Request{Method: "GET", URL: server.URL,
		Headers: []Header{{Name: "Accept-Encoding", Value: []byte("gzip;q=broken")}}, ContentDecoding: AdvertisedDecoding(1024)})
	if kind(err) != "invalid_header" || count.Load() != 0 {
		t.Fatalf("malformed advertisement sent: %v, count=%d", err, count.Load())
	}
}

func TestAdvertisedDecodingZeroAcceptsEmptyAndBodylessResponses(t *testing.T) {
	encoded := gzipBytes(t, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		if r.URL.Path == "/bodyless" {
			w.WriteHeader(204)
			return
		}
		_, _ = w.Write(encoded)
	}))
	defer server.Close()
	client, err := New(Config{Profile: profile, Protocol: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, path := range []string{"/empty", "/bodyless"} {
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + path, Headers: []Header{{Name: "Accept-Encoding", Value: []byte("gzip")}}, ContentDecoding: AdvertisedDecoding(0)})
		if err != nil {
			t.Fatal(err)
		}
		data, err := response.Body.ReadAll(0)
		if err != nil || len(data) != 0 {
			t.Fatalf("%s: %q, %v", path, data, err)
		}
	}
}
