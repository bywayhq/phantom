package native

import "unsafe"

// EventSource ABI 1 is independent of HTTP, SSE and WebSocket descriptors.
type EventSourceHeader struct {
	Kind  uint64
	Field Field
}
type EventSourceOpening struct {
	Client                                                    uint64
	URL                                                       Span
	Protocol                                                  uint64
	Headers                                                   unsafe.Pointer
	HeaderCount, HeadersPresent                               uint64
	Line, Event, Flags, Idle, InitialRetry, MinRetry, Maximum uint64
	Timeouts                                                  [5]Timeout
	Proxy, Username, Password                                 Span
}
type EventSourceResult struct {
	Event                                 SSEEvent
	RetryMilliseconds, Reconnects, Closed uint64
}

func ReadEventSourceResult(operation uint64) (EventSourceResult, []byte, error) {
	var probe EventSourceResult
	if err := EventSourceCopy(operation, &probe, nil); err != nil {
		return EventSourceResult{}, nil, err
	}
	length, err := SSEResultLength(probe.Event)
	if err != nil {
		return EventSourceResult{}, nil, err
	}
	if probe.Closed > 1 || (probe.Event.Flags&2 != 0 && probe.RetryMilliseconds != probe.Event.RetryMilliseconds) {
		return EventSourceResult{}, nil, &Failure{Kind: "native_abi"}
	}
	data := make([]byte, length)
	if length != 0 {
		value := probe
		if err := EventSourceCopy(operation, &value, data); err != nil {
			return EventSourceResult{}, nil, err
		}
		if value != probe {
			return EventSourceResult{}, nil, &Failure{Kind: "native_abi"}
		}
	}
	return probe, data, nil
}
