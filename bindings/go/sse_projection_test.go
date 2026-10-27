package phantom

import (
	"testing"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

func TestSSETransferRejectsInvalidLengthsFlagsAndUTF8(t *testing.T) {
	for _, test := range []struct {
		value  native.SSEEvent
		output []byte
	}{
		{native.SSEEvent{DataLength: ^uint64(0), TypeLength: 1}, nil},
		{native.SSEEvent{DataLength: native.MaxSSEResult, TypeLength: 1}, nil},
		{native.SSEEvent{Flags: 8}, nil},
		{native.SSEEvent{Flags: 1, TypeLength: 1}, []byte("x")},
		{native.SSEEvent{TypeLength: 1}, []byte{255}},
		{native.SSEEvent{DataLength: 1, TypeLength: 1}, []byte("a")},
		{native.SSEEvent{}, nil},
	} {
		if _, err := decodeSSEEvent(test.value, test.output); kind(err) != "native_abi" {
			t.Fatalf("invalid event accepted: %+v, %v", test.value, err)
		}
	}
}

func TestSSETransferOwnsStringsAndPreservesLargeRetryValues(t *testing.T) {
	data := []byte("valuepricecommitted")
	result, err := decodeSSEEvent(native.SSEEvent{DataLength: 5, TypeLength: 5, IDLength: 9, RetryMilliseconds: ^uint64(0), Flags: 2}, data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	if result.event != (SSEEvent{Data: "value", Type: "price", ID: "committed"}) || !result.hasRetry || result.retry != ^uint64(0) {
		t.Fatalf("event copy: %+v", result)
	}
}
