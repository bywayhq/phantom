package phantom

import (
	"unicode/utf8"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

type receivedSSE struct {
	event         SSEEvent
	retry         uint64
	hasRetry, eof bool
	err           error
}

func readSSEEvent(operation uint64) (receivedSSE, error) {
	if err := ensureNativeIdentity(); err != nil {
		return receivedSSE{}, err
	}
	value, output, err := native.ReadSSEEvent(operation)
	if err != nil {
		return receivedSSE{}, nativeBoundaryError(err)
	}
	return decodeSSEEvent(value, output)
}

func decodeSSEEvent(value native.SSEEvent, output []byte) (receivedSSE, error) {
	length, err := native.SSEResultLength(value)
	if err != nil || length != len(output) || !utf8.Valid(output) {
		return receivedSSE{}, &Error{Kind: "native_abi"}
	}
	dataEnd, typeEnd := int(value.DataLength), int(value.DataLength+value.TypeLength)
	result := receivedSSE{
		event: SSEEvent{Data: string(output[:dataEnd]), Type: string(output[dataEnd:typeEnd]), ID: string(output[typeEnd:])},
		retry: value.RetryMilliseconds, hasRetry: value.Flags&2 != 0, eof: value.Flags&1 != 0,
		err: nativeRecordError(value.Error),
	}
	if failure, ok := result.err.(*Error); ok {
		failure.cause = nativeRecordError(value.Cause)
	} else if value.Cause.Kind[0] != 0 {
		return receivedSSE{}, &Error{Kind: "native_abi"}
	}
	return result, nil
}
