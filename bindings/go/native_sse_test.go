package phantom

import "testing"

func TestSSETransferRejectsInvalidLengthsFlagsAndUTF8(t *testing.T) {
	for _, test := range []struct {
		value  nativeSSEEvent
		output []byte
	}{
		{nativeSSEEvent{DataLength: ^uint64(0), TypeLength: 1}, nil},
		{nativeSSEEvent{DataLength: maxSSEResult, TypeLength: 1}, nil},
		{nativeSSEEvent{Flags: 8}, nil},
		{nativeSSEEvent{Flags: 1, TypeLength: 1}, []byte("x")},
		{nativeSSEEvent{TypeLength: 1}, []byte{255}},
		{nativeSSEEvent{DataLength: 1, TypeLength: 1}, []byte("a")},
		{nativeSSEEvent{}, nil},
	} {
		if _, err := decodeSSEEvent(test.value, test.output); kind(err) != "native_abi" {
			t.Fatalf("invalid event accepted: %+v, %v", test.value, err)
		}
	}
}

func TestSSETransferOwnsStringsAndPreservesLargeRetryValues(t *testing.T) {
	data := []byte("valuepricecommitted")
	result, err := decodeSSEEvent(nativeSSEEvent{DataLength: 5, TypeLength: 5, IDLength: 9, RetryMilliseconds: ^uint64(0), Flags: 2}, data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	if result.event != (SSEEvent{Data: "value", Type: "price", ID: "committed"}) || !result.hasRetry || result.retry != ^uint64(0) {
		t.Fatalf("event copy: %+v", result)
	}
}
