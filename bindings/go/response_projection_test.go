package phantom

import (
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

func TestTypedCompletionPreservesOrderedBinaryFieldsAndEmptyHistory(t *testing.T) {
	arena := []byte("https://example.test/\x58\xff\x58secondgzipgzipgzipgzipgzip")
	urlLength := uint64(len("https://example.test/"))
	fields := []native.OutputField{
		{Name: native.Slice{Offset: urlLength, Length: 1}, Value: native.Slice{Offset: urlLength + 1, Length: 1}, Sensitive: 1},
		{Name: native.Slice{Offset: urlLength + 2, Length: 1}, Value: native.Slice{Offset: urlLength + 3, Length: 6}},
	}
	start := urlLength + 9
	for range 5 {
		fields = append(fields, native.OutputField{Name: native.Slice{Offset: start, Length: 4}})
		start += 4
	}
	event := native.Event{Operation: 7, Kind: 5, Body: 11, Status: 200, Protocol: 2, HistoryPresent: 1, FieldCount: 2, CodingCount: 5, ArenaLength: uint64(len(arena)), EffectiveURL: native.Slice{Offset: 0, Length: urlLength}}
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
		event  native.Event
		fields []native.OutputField
		arena  []byte
	}{
		{name: "missing operation", event: native.Event{Kind: 1}},
		{name: "unknown kind", event: native.Event{Operation: 1, Kind: 99}},
		{name: "arena length", event: native.Event{Operation: 1, Kind: 1, ArenaLength: 1}},
		{name: "field count", event: native.Event{Operation: 1, Kind: 1, FieldCount: 1}},
		{name: "trailer state", event: native.Event{Operation: 1, Kind: 3, TrailerState: 99}},
		{name: "field span overflow", event: native.Event{Operation: 1, Kind: 3, TrailerState: 1, FieldCount: 1}, fields: []native.OutputField{{Name: native.Slice{Offset: math.MaxUint64, Length: 1}}}},
		{name: "sensitive flag", event: native.Event{Operation: 1, Kind: 3, TrailerState: 1, FieldCount: 1}, fields: []native.OutputField{{Sensitive: 2}}},
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
	event := native.Event{Operation: 7}
	copy(event.Error.Kind[:], "timeout")
	copy(event.Error.Protocol[:], "h2")
	copy(event.Error.TimeoutPhase[:], "response_head")
	result, err := eventCompletion(event, nil, nil, nil, nil)
	if err != nil || result.Error == nil || result.Error.Kind != "timeout" || result.Error.Protocol != "h2" || result.Error.TimeoutPhase != "response_head" {
		t.Fatalf("failure details: %+v %v", result.Error, err)
	}
}
