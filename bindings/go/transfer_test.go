package phantom

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

func newTransfer(t *testing.T, limits TransferLimits) *TransferControl {
	t.Helper()
	control, err := NewTransferControl(limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := control.Close(); err != nil {
			t.Error(err)
		}
	})
	return control
}

func transferSnapshot(t *testing.T, control *TransferControl) TransferSnapshot {
	t.Helper()
	snapshot, err := control.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestTransferLimitsAndSnapshotKeepExactUint64AndRejectMissingCounters(t *testing.T) {
	maximum := uint64(math.MaxUint64)
	encoded, err := json.Marshal(TransferLimits{UploadBytes: &maximum, DownloadBytes: uint64Pointer(0)})
	if err != nil || string(encoded) != `{"upload_bytes":18446744073709551615,"download_bytes":0}` {
		t.Fatalf("wire=%s, error=%v", encoded, err)
	}
	for _, data := range []string{
		`{}`, `null`, `{"upload_reserved_bytes":0}`,
		`{"upload_reserved_bytes":0,"upload_body_bytes":0,"download_reserved_bytes":0,"download_encoded_bytes":0,"download_decoded_bytes":-1}`,
	} {
		if _, err := decodeTransferSnapshot([]byte(data)); kind(err) != "native_abi" {
			t.Fatalf("invalid snapshot %s: %v", data, err)
		}
	}
	data := `{"upload_reserved_bytes":18446744073709551615,"upload_body_bytes":0,"download_reserved_bytes":0,"download_encoded_bytes":0,"download_decoded_bytes":0}`
	snapshot, err := decodeTransferSnapshot([]byte(data))
	if err != nil || snapshot.UploadReservedBytes != maximum {
		t.Fatalf("snapshot=%+v, error=%v", snapshot, err)
	}
	for _, limits := range []TransferLimits{
		{UploadBytesPerSecond: uint64Pointer(0)}, {DownloadBytesPerSecond: uint64Pointer(0)},
	} {
		if owner, err := NewTransferControl(limits); owner != nil || kind(err) != "invalid_transfer_limits" {
			t.Fatalf("zero rate owner=%v, error=%v", owner, err)
		}
	}
	owner := newTransfer(t, TransferLimits{UploadBytes: uint64Pointer(0), DownloadBytes: &maximum})
	if snapshot := transferSnapshot(t, owner); snapshot != (TransferSnapshot{}) {
		t.Fatalf("fresh snapshot=%+v", snapshot)
	}
}

func TestSharedTransferUploadCapCannotBeOverspentAndIndependentControlsStaySeparate(t *testing.T) {
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err == nil && bytes.Equal(data, []byte("data")) {
			received.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := newClient(t)
	other := newClient(t)
	control := newTransfer(t, TransferLimits{UploadBytes: uint64Pointer(20)})
	var successes atomic.Int64
	var pending sync.WaitGroup
	for index := range 16 {
		selected := client
		if index%2 == 1 {
			selected = other
		}
		pending.Add(1)
		go func() {
			defer pending.Done()
			response, err := selected.Do(context.Background(), Request{
				Method: "POST", URL: server.URL, Body: []byte("data"), TransferControl: control,
			})
			if err != nil {
				if kind(err) != "transfer" {
					t.Errorf("request error: %v", err)
				}
				return
			}
			if _, err := response.Body.ReadAll(1); err != nil {
				t.Error(err)
				return
			}
			successes.Add(1)
		}()
	}
	pending.Wait()
	if successes.Load() != 5 || received.Load() != 5 {
		t.Fatalf("completed=%d, peer bodies=%d", successes.Load(), received.Load())
	}
	if snapshot := transferSnapshot(t, control); snapshot.UploadReservedBytes != 20 || snapshot.UploadBodyBytes != 20 {
		t.Fatalf("shared counters=%+v", snapshot)
	}
	independent := newTransfer(t, TransferLimits{})
	response, err := client.Do(context.Background(), Request{Method: "POST", URL: server.URL, Body: []byte("data"), TransferControl: independent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := response.Body.ReadAll(1); err != nil {
		t.Fatal(err)
	}
	if snapshot := transferSnapshot(t, independent); snapshot.UploadBodyBytes != 4 {
		t.Fatalf("independent counters=%+v", snapshot)
	}
}

func TestTransferUploadCountersChargeRedirectResends(t *testing.T) {
	var bodies atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil || string(data) != "data" {
			t.Errorf("request body=%q: %v", data, err)
			return
		}
		bodies.Add(1)
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/end")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := newClient(t)
	control := newTransfer(t, TransferLimits{UploadBytes: uint64Pointer(8)})
	response, err := client.Do(context.Background(), Request{
		Method: "POST", URL: server.URL + "/start", Body: []byte("data"), TransferControl: control,
		RedirectPolicy: &RedirectPolicy{MaximumHops: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := response.Body.ReadAll(1); err != nil {
		t.Fatal(err)
	}
	if snapshot := transferSnapshot(t, control); snapshot.UploadBodyBytes != 8 || snapshot.UploadReservedBytes != 8 || bodies.Load() != 2 {
		t.Fatalf("peer bodies=%d, counters=%+v", bodies.Load(), snapshot)
	}
}

func TestTransferCountersDistinguishEncodedAndBufferedDecodedBytes(t *testing.T) {
	plain := bytes.Repeat([]byte("data"), 128)
	encoded := gzipBytes(t, plain)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
		if _, err := w.Write(encoded); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := newClient(t)
	control := newTransfer(t, TransferLimits{})
	response, err := client.Do(context.Background(), Request{
		Method: "GET", URL: server.URL, TransferControl: control,
		Headers:         []Header{{Name: "Accept-Encoding", Value: []byte("gzip")}},
		ContentDecoding: AdvertisedDecoding(uint64(len(plain))),
	})
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 1)
	if n, err := response.Body.Read(first); n != 1 || err != nil {
		t.Fatalf("first read=%d: %v", n, err)
	}
	if snapshot := transferSnapshot(t, control); snapshot.DownloadDecodedBytes <= 1 || snapshot.DownloadDecodedBytes > uint64(len(plain)) {
		t.Fatalf("core frame counter should lead buffered application cursor: %+v", snapshot)
	}
	rest, err := response.Body.ReadAll(len(plain))
	if err != nil || !bytes.Equal(append(first, rest...), plain) {
		t.Fatalf("decoded body mismatch: %v", err)
	}
	snapshot := transferSnapshot(t, control)
	if snapshot.DownloadEncodedBytes != uint64(len(encoded)) || snapshot.DownloadDecodedBytes != uint64(len(plain)) {
		t.Fatalf("encoded=%d decoded=%d: %+v", len(encoded), len(plain), snapshot)
	}
}

func TestClosingTransferOwnerDoesNotCancelAttachedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.WriteString(w, "still attached"); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := newClient(t)
	control := newTransfer(t, TransferLimits{})
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL, TransferControl: control})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := response.Body.ReadAll(100); err != nil || string(data) != "still attached" {
		t.Fatalf("retained response=%q: %v", data, err)
	}
	if _, err := control.Snapshot(); kind(err) != "invalid_handle" {
		t.Fatalf("released snapshot: %v", err)
	}
	budget, err := NewAttemptBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	if _, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL, TransferControl: control, Budget: budget}); kind(err) != "invalid_handle" {
		t.Fatalf("released request: %v", err)
	}
	if remaining, err := budget.Remaining(); err != nil || remaining != 1 {
		t.Fatalf("invalid handle spent allowance=%d: %v", remaining, err)
	}
}
