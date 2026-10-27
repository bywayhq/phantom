package native

// SSE ABI 1 uses separate symbols and result descriptors. Ordinary ABI 2
// request/completion descriptors are unchanged; events stay operation-owned
// until the completion callback finishes its synchronous copy and acknowledges.
type SSEEvent struct {
	DataLength, TypeLength, IDLength uint64
	RetryMilliseconds, Flags         uint64
	Error, Cause                     ErrorRecord
}

const MaxSSEResult = 3*(1024*1024+8*1024*1024) + 7

// ReadSSEEvent copies one operation-owned result before its acknowledgement.
func ReadSSEEvent(operation uint64) (SSEEvent, []byte, error) {
	var probe SSEEvent
	if err := SSEResult(operation, &probe, nil); err != nil {
		return SSEEvent{}, nil, err
	}
	length, err := SSEResultLength(probe)
	if err != nil {
		return SSEEvent{}, nil, err
	}
	output := make([]byte, length)
	value := probe
	if length != 0 {
		if err := SSEResult(operation, &value, output); err != nil {
			return SSEEvent{}, nil, err
		}
		if value != probe {
			return SSEEvent{}, nil, &Failure{Kind: "native_abi"}
		}
	}
	return value, output, nil
}

func SSEResultLength(value SSEEvent) (int, error) {
	if value.Flags & ^uint64(3) != 0 || value.DataLength > MaxSSEResult ||
		value.TypeLength > MaxSSEResult-value.DataLength || value.IDLength > MaxSSEResult-value.DataLength-value.TypeLength ||
		(value.Flags&1 != 0 && (value.DataLength != 0 || value.TypeLength != 0)) ||
		(value.Flags&1 == 0 && value.TypeLength == 0 && value.Error.Kind[0] == 0) {
		return 0, &Failure{Kind: "native_abi"}
	}
	return int(value.DataLength + value.TypeLength + value.IDLength), nil
}
