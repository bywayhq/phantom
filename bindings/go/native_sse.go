package phantom

import "unicode/utf8"

// SSE ABI 1 uses separate symbols and result descriptors. Ordinary ABI 2
// request/completion descriptors are unchanged; events stay operation-owned
// until the completion callback finishes its synchronous copy and acknowledges.
type nativeSSEEvent struct {
	DataLength, TypeLength, IDLength uint64
	RetryMilliseconds, Flags         uint64
	Error, Cause                     nativeError
}

type receivedSSE struct {
	event         SSEEvent
	retry         uint64
	hasRetry, eof bool
	err           error
}

const maxSSEResult = 3*(1024*1024+8*1024*1024) + 7

func readSSEEvent(operation uint64) (receivedSSE, error) {
	var probe nativeSSEEvent
	if err := nativeSSEResult(operation, &probe, nil); err != nil {
		return receivedSSE{}, err
	}
	length, err := sseResultLength(probe)
	if err != nil {
		return receivedSSE{}, err
	}
	output := make([]byte, length)
	value := probe
	if length != 0 {
		if err := nativeSSEResult(operation, &value, output); err != nil {
			return receivedSSE{}, err
		}
		if value != probe {
			return receivedSSE{}, &Error{Kind: "native_abi"}
		}
	}
	return decodeSSEEvent(value, output)
}

func sseResultLength(value nativeSSEEvent) (int, error) {
	if value.Flags & ^uint64(3) != 0 || value.DataLength > maxSSEResult ||
		value.TypeLength > maxSSEResult-value.DataLength || value.IDLength > maxSSEResult-value.DataLength-value.TypeLength ||
		(value.Flags&1 != 0 && (value.DataLength != 0 || value.TypeLength != 0)) ||
		(value.Flags&1 == 0 && value.TypeLength == 0 && value.Error.Kind[0] == 0) {
		return 0, &Error{Kind: "native_abi"}
	}
	return int(value.DataLength + value.TypeLength + value.IDLength), nil
}

func decodeSSEEvent(value nativeSSEEvent, output []byte) (receivedSSE, error) {
	length, err := sseResultLength(value)
	if err != nil || length != len(output) || !utf8.Valid(output) {
		return receivedSSE{}, &Error{Kind: "native_abi"}
	}
	dataEnd, typeEnd := int(value.DataLength), int(value.DataLength+value.TypeLength)
	result := receivedSSE{
		event: SSEEvent{Data: string(output[:dataEnd]), Type: string(output[dataEnd:typeEnd]), ID: string(output[typeEnd:])},
		retry: value.RetryMilliseconds, hasRetry: value.Flags&2 != 0, eof: value.Flags&1 != 0,
		err: value.Error.err(),
	}
	if failure, ok := result.err.(*Error); ok {
		failure.cause = value.Cause.err()
	} else if value.Cause.Kind[0] != 0 {
		return receivedSSE{}, &Error{Kind: "native_abi"}
	}
	return result, nil
}
