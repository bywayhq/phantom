package phantom

import (
	"encoding/json"
	"runtime"
	"sync/atomic"
)

// TransferLimits sets shared body-byte caps and rates. Nil fields are unlimited.
// Byte caps may be zero; rates must be positive and are measured in bytes/second.
// Download caps and rates apply to encoded response bodies before decompression.
type TransferLimits struct {
	UploadBytes            *uint64 `json:"upload_bytes,omitempty"`
	DownloadBytes          *uint64 `json:"download_bytes,omitempty"`
	UploadBytesPerSecond   *uint64 `json:"upload_bytes_per_second,omitempty"`
	DownloadBytesPerSecond *uint64 `json:"download_bytes_per_second,omitempty"`
}

// TransferSnapshot reports one coherent snapshot of shared body-byte counters.
// Reservations include cancelled paced chunks. Uploads include resends and
// multipart framing; encoded downloads precede decompression. Decoded bytes
// count core frames delivered to the binding, including its unread buffer.
// Headers, protocol framing and transport overhead are excluded.
type TransferSnapshot struct {
	UploadReservedBytes   uint64 `json:"upload_reserved_bytes"`
	UploadBodyBytes       uint64 `json:"upload_body_bytes"`
	DownloadReservedBytes uint64 `json:"download_reserved_bytes"`
	DownloadEncodedBytes  uint64 `json:"download_encoded_bytes"`
	DownloadDecodedBytes  uint64 `json:"download_decoded_bytes"`
}

// TransferControl shares immutable limits, pacing and counters across requests.
// It is safe for concurrent use. Do not copy it after first use.
type TransferControl struct{ id atomic.Uint64 }

// NewTransferControl creates a shared policy. The zero limits value counts bytes
// without limiting them. Pacing has no initial burst; cancellation retains its
// reservation and leaves a gap in the shared schedule. Close the returned owner.
func NewTransferControl(limits TransferLimits) (*TransferControl, error) {
	if (limits.UploadBytesPerSecond != nil && *limits.UploadBytesPerSecond == 0) ||
		(limits.DownloadBytesPerSecond != nil && *limits.DownloadBytesPerSecond == 0) {
		return nil, &Error{Kind: "invalid_transfer_limits"}
	}
	value, err := dispatch(map[string]any{"kind": "new_transfer", "limits": limits}, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(value, &result) != nil || result.ID == 0 {
		return nil, &Error{Kind: "native_abi"}
	}
	owner := &TransferControl{}
	owner.id.Store(result.ID)
	runtime.SetFinalizer(owner, func(control *TransferControl) {
		// Finalizers cannot report release errors; callers can observe them through Close.
		_ = control.Close()
	})
	return owner, nil
}

// Snapshot returns the current counters. A released or zero-value owner returns
// an invalid_handle error. Counters describe body processing, not socket bytes.
func (c *TransferControl) Snapshot() (TransferSnapshot, error) {
	if c == nil || c.id.Load() == 0 {
		return TransferSnapshot{}, &Error{Kind: "invalid_handle"}
	}
	value, err := dispatch(map[string]any{"kind": "transfer_snapshot", "transfer": c.id.Load()}, nil)
	runtime.KeepAlive(c)
	if err != nil {
		return TransferSnapshot{}, err
	}
	return decodeTransferSnapshot(value)
}

func decodeTransferSnapshot(value json.RawMessage) (TransferSnapshot, error) {
	var wire struct {
		UploadReservedBytes   *uint64 `json:"upload_reserved_bytes"`
		UploadBodyBytes       *uint64 `json:"upload_body_bytes"`
		DownloadReservedBytes *uint64 `json:"download_reserved_bytes"`
		DownloadEncodedBytes  *uint64 `json:"download_encoded_bytes"`
		DownloadDecodedBytes  *uint64 `json:"download_decoded_bytes"`
	}
	if json.Unmarshal(value, &wire) != nil || wire.UploadReservedBytes == nil ||
		wire.UploadBodyBytes == nil || wire.DownloadReservedBytes == nil ||
		wire.DownloadEncodedBytes == nil || wire.DownloadDecodedBytes == nil {
		return TransferSnapshot{}, &Error{Kind: "native_abi"}
	}
	return TransferSnapshot{
		UploadReservedBytes: *wire.UploadReservedBytes, UploadBodyBytes: *wire.UploadBodyBytes,
		DownloadReservedBytes: *wire.DownloadReservedBytes, DownloadEncodedBytes: *wire.DownloadEncodedBytes,
		DownloadDecodedBytes: *wire.DownloadDecodedBytes,
	}, nil
}

// Close releases this handle without cancelling requests already attached to it.
// Repeated calls, including on a nil owner, do nothing.
func (c *TransferControl) Close() error {
	if c == nil {
		return nil
	}
	id := c.id.Swap(0)
	if id == 0 {
		return nil
	}
	runtime.SetFinalizer(c, nil)
	return control("release_transfer", "transfer", id)
}
