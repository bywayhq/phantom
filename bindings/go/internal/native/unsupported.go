//go:build (!windows && !linux && !darwin) || (!amd64 && !arm64) || (windows && !amd64)

package native

func Dispatch([]byte, []byte, []byte) (int, error) {
	return 0, &Failure{Kind: "unsupported_platform"}
}

func Profile([]byte, []byte, []byte, []byte) (int, error) {
	return 0, &Failure{Kind: "unsupported_platform"}
}

func Session([]byte, []byte, []byte, []byte, []byte) (int, error) {
	return 0, &Failure{Kind: "unsupported_platform"}
}

func Submit(*Request, []byte, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}

func Operation(uint64, uint64, uint64, []byte, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}

func WaitEvent(*Event, []OutputField, []Hop, []byte, []byte) error {
	return &Failure{Kind: "unsupported_platform"}
}

func LoadSSE() error { return &Failure{Kind: "unsupported_platform"} }
func SSESubmit(*Request, []byte, uint64, uint64, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}

func SSENext(uint64, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}

func SSEResult(uint64, *SSEEvent, []byte) error {
	return &Failure{Kind: "unsupported_platform"}
}

func LoadWebSocket() error                          { return &Failure{Kind: "unsupported_platform"} }
func WebSocketOpen(*WebSocketOpening, *Reply) error { return &Failure{Kind: "unsupported_platform"} }
func WebSocketOperation(uint64, uint64, uint64, uint64, []byte, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func WebSocketCopy(uint64, *WebSocketResult, []byte) error {
	return &Failure{Kind: "unsupported_platform"}
}
