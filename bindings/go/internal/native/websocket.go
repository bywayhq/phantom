package native

import "unsafe"

// WebSocket ABI 1 is optional and does not reinterpret HTTP or SSE descriptors.
type WebSocketTemplateField struct {
	Kind  uint64
	Field Field
}
type WebSocketDeflateParameter struct{ Kind, Bits uint64 }
type WebSocketDeflate struct {
	Parameters                  unsafe.Pointer
	Count, Flags, Window, Level uint64
}
type WebSocketOpening struct {
	Client                         uint64
	URL                            Span
	Protocol                       uint64
	Headers                        unsafe.Pointer
	HeaderCount                    uint64
	Template                       unsafe.Pointer
	TemplateCount, TemplatePresent uint64
	Frame, Message, Fragments      uint64
	Timeout                        Timeout
	Retries, RetryDelay            uint64
	Deflate                        *WebSocketDeflate
}
type WebSocketResult struct {
	Kind, Length, Code                      uint64
	Compression, ServerWindow, ClientWindow uint64
	Error                                   ErrorRecord
}

const MaxWebSocketMessage = 64 * 1024 * 1024

func WebSocketResultLength(value WebSocketResult) (int, error) {
	if value.Error.Kind[0] != 0 {
		return 0, value.Error.Err()
	}
	if value.Kind < 1 || value.Kind > 7 || value.Length > MaxWebSocketMessage ||
		value.Compression & ^uint64(7) != 0 || value.Code > 65535 ||
		(value.Kind != 6 && value.Code != 0) ||
		((value.Kind == 4 || value.Kind == 5) && value.Length > 125) ||
		(value.Kind == 6 && (value.Length > 123 || (value.Code == 0 && value.Length != 0))) ||
		(value.Kind == 7 && value.Length != 0) ||
		(value.Kind != 1 && (value.Compression != 0 || value.ServerWindow != 0 || value.ClientWindow != 0)) ||
		(value.Compression == 0 && (value.ServerWindow != 0 || value.ClientWindow != 0)) ||
		(value.Compression != 0 && (value.Compression&1 == 0 || value.ServerWindow < 8 || value.ServerWindow > 15 || value.ClientWindow < 8 || value.ClientWindow > 15)) {
		return 0, &Failure{Kind: "native_abi"}
	}
	return int(value.Length), nil
}

func ReadWebSocketResult(operation uint64) (WebSocketResult, []byte, error) {
	var probe WebSocketResult
	if err := WebSocketCopy(operation, &probe, nil); err != nil {
		return WebSocketResult{}, nil, err
	}
	length, err := WebSocketResultLength(probe)
	if err != nil {
		return WebSocketResult{}, nil, err
	}
	data := make([]byte, length)
	if length != 0 {
		value := probe
		if err := WebSocketCopy(operation, &value, data); err != nil {
			return WebSocketResult{}, nil, err
		}
		if value != probe {
			return WebSocketResult{}, nil, &Failure{Kind: "native_abi"}
		}
	}
	return probe, data, nil
}
