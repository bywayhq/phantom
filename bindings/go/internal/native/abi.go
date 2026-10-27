// Package native owns the process-lifetime library and its synchronous ABI.
package native

import (
	"bytes"
	"unsafe"
)

// ABI 2 records borrow the caller's storage for one synchronous call. Their
// layout matches native/src/ffi/hot.rs; they never own or retain Go pointers.
type Span struct {
	Pointer unsafe.Pointer
	Length  uint64
}
type Field struct {
	Name, Value Span
	Sensitive   uint64
}
type Timeout struct{ Mode, Nanoseconds uint64 }
type Retry struct {
	Flags                  uint64
	ConnectionMaximum      uint64
	ConnectionDelay        uint64
	ConnectionMaximumDelay uint64
	Statuses               unsafe.Pointer
	StatusCount            uint64
	StatusMaximum          uint64
	StatusDelay            uint64
	StatusMaximumDelay     uint64
	RetryAfter             uint64
	Unprocessed            uint64
	Maximum                uint64
}
type Request struct {
	Client                uint64
	Method, URL           Span
	Headers               unsafe.Pointer
	HeaderCount           uint64
	Trailers              unsafe.Pointer
	TrailerCount          uint64
	Flags                 uint64
	ExpectContinue        uint64
	Budget                uint64
	Transfer              uint64
	Diagnostics           uint64
	PreparedBody          uint64
	Upload                uint64
	Timeouts              [5]Timeout
	DecodedMaximum        uint64
	RedirectMaximum       uint64
	CredentialHeaders     unsafe.Pointer
	CredentialHeaderCount uint64
	RedirectHistory       uint64
	Retry                 *Retry
}
type ErrorRecord struct{ Kind, Protocol, TimeoutPhase [64]byte }
type Reply struct {
	Operation uint64
	Error     ErrorRecord
}
type Slice struct{ Offset, Length uint64 }
type OutputField struct {
	Name, Value Slice
	Sensitive   uint64
}
type Hop struct {
	From, To, Method, NextMethod Slice
	Status                       uint64
}
type Event struct {
	Operation      uint64
	Kind           uint64
	Body           uint64
	Status         uint64
	Protocol       uint64
	Redirects      uint64
	SetupRetries   uint64
	HistoryPresent uint64
	HistoryOmitted uint64
	Part           uint64
	TrailerState   uint64
	FieldCount     uint64
	HopCount       uint64
	CodingCount    uint64
	ArenaLength    uint64
	DataLength     uint64
	EffectiveURL   Slice
	Error          ErrorRecord
}

func (value ErrorRecord) Err() error {
	if value.Kind[0] == 0 {
		return nil
	}
	text := func(value []byte) string {
		if index := bytes.IndexByte(value, 0); index >= 0 {
			value = value[:index]
		}
		return string(value)
	}
	return &Failure{Kind: text(value.Kind[:]), Protocol: text(value.Protocol[:]), TimeoutPhase: text(value.TimeoutPhase[:])}
}

// BorrowedString creates a span whose owner must remain live through the call.
func BorrowedString(value string) Span {
	return Span{unsafe.Pointer(unsafe.StringData(value)), uint64(len(value))}
}

// BorrowedBytes creates a span whose owner must remain live through the call.
func BorrowedBytes(value []byte) Span {
	return Span{unsafe.Pointer(unsafe.SliceData(value)), uint64(len(value))}
}
