package phantom

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"unsafe"
)

func TestNativeLayoutMatchesThe64BitCABI(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("typed ABI is limited to 64-bit hosts")
	}
	for _, test := range []struct {
		name      string
		got, want uintptr
	}{
		{"span", unsafe.Sizeof(nativeSpan{}), 16},
		{"request field", unsafe.Sizeof(nativeField{}), 40},
		{"timeout", unsafe.Sizeof(nativeTimeout{}), 16},
		{"retry", unsafe.Sizeof(nativeRetry{}), 96},
		{"request", unsafe.Sizeof(nativeRequest{}), 256},
		{"reply", unsafe.Sizeof(nativeReply{}), 200},
		{"completion field", unsafe.Sizeof(nativeOutputField{}), 40},
		{"hop", unsafe.Sizeof(nativeHop{}), 72},
		{"event", unsafe.Sizeof(nativeEvent{}), 336},
	} {
		if test.got != test.want {
			t.Errorf("%s size=%d, want%d", test.name, test.got, test.want)
		}
	}
}

func TestTypedCompletionPreservesOrderedBinaryFieldsAndEmptyHistory(t *testing.T) {
	arena := []byte("https://example.test/\x58\xff\x58secondgzipgzipgzipgzipgzip")
	urlLength := uint64(len("https://example.test/"))
	fields := []nativeOutputField{
		{Name: nativeSlice{urlLength, 1}, Value: nativeSlice{urlLength + 1, 1}, Sensitive: 1},
		{Name: nativeSlice{urlLength + 2, 1}, Value: nativeSlice{urlLength + 3, 6}},
	}
	start := urlLength + 9
	for range 5 {
		fields = append(fields, nativeOutputField{Name: nativeSlice{start, 4}})
		start += 4
	}
	event := nativeEvent{Operation: 7, Kind: 5, Body: 11, Status: 200, Protocol: 2, HistoryPresent: 1, FieldCount: 2, CodingCount: 5, ArenaLength: uint64(len(arena)), EffectiveURL: nativeSlice{0, urlLength}}
	result, err := eventCompletion(event, fields, nil, arena, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := []Header{{Name: "X", Value: []byte{255}, Sensitive: true}, {Name: "X", Value: []byte("second")}}
	if !reflect.DeepEqual(result.head.Headers, expected) {
		t.Fatalf("ordered fields: %+v", result.head.Headers)
	}
	if result.head.RedirectHistory == nil || len(result.head.RedirectHistory.Entries) != 0 {
		t.Fatal("enabled empty history lost")
	}
	if len(result.head.DecodedContentCodings) != 5 {
		t.Fatalf("coding chain truncated: %v", result.head.DecodedContentCodings)
	}
	arena[urlLength+1] = 0
	if result.head.Headers[0].Value[0] != 255 {
		t.Fatal("response retained pump scratch storage")
	}
}

func TestTypedCompletionRejectsOutOfBoundsAndUnknownStates(t *testing.T) {
	for _, test := range []struct {
		name   string
		event  nativeEvent
		fields []nativeOutputField
		arena  []byte
	}{
		{name: "missing operation", event: nativeEvent{Kind: 1}},
		{name: "unknown kind", event: nativeEvent{Operation: 1, Kind: 99}},
		{name: "arena length", event: nativeEvent{Operation: 1, Kind: 1, ArenaLength: 1}},
		{name: "field count", event: nativeEvent{Operation: 1, Kind: 1, FieldCount: 1}},
		{name: "trailer state", event: nativeEvent{Operation: 1, Kind: 3, TrailerState: 99}},
		{name: "field span overflow", event: nativeEvent{Operation: 1, Kind: 3, TrailerState: 1, FieldCount: 1}, fields: []nativeOutputField{{Name: nativeSlice{math.MaxUint64, 1}}}},
		{name: "sensitive flag", event: nativeEvent{Operation: 1, Kind: 3, TrailerState: 1, FieldCount: 1}, fields: []nativeOutputField{{Sensitive: 2}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := eventCompletion(test.event, test.fields, nil, test.arena, nil)
			var native *Error
			if !errors.As(err, &native) || native.Kind != "native_abi" {
				t.Fatalf("malformed completion accepted: %v", err)
			}
		})
	}
}

func TestTypedCompletionPreservesFailureDetails(t *testing.T) {
	event := nativeEvent{Operation: 7}
	copy(event.Error.Kind[:], "timeout")
	copy(event.Error.Protocol[:], "h2")
	copy(event.Error.TimeoutPhase[:], "response_head")
	result, err := eventCompletion(event, nil, nil, nil, nil)
	if err != nil || result.Error == nil || result.Error.Kind != "timeout" || result.Error.Protocol != "h2" || result.Error.TimeoutPhase != "response_head" {
		t.Fatalf("failure details: %+v %v", result.Error, err)
	}
}
