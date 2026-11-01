//go:build (!windows && !linux && !darwin) || (!amd64 && !arm64) || (windows && !amd64)

package native

func LoadRedirectHooks() error { return &Failure{Kind: "unsupported_platform"} }
func RedirectHookRequest(*Request, []byte, uint64, *CallbackSSELimits, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func RedirectHookCopy(uint64, uint64, *RedirectInvocation, []byte) error {
	return &Failure{Kind: "unsupported_platform"}
}
func RedirectHookReply(uint64, uint64, uint64, uint64, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}

func LoadStateTransfer() error                         { return &Failure{Kind: "unsupported_platform"} }
func SubmitStateTransfer(*StateTransfer, *Reply) error { return &Failure{Kind: "unsupported_platform"} }
func StateTransferCopy(uint64, *StateResult, []StateCookie, []StateAlternative, []byte) error {
	return &Failure{Kind: "unsupported_platform"}
}

func LoadSSEHeaderHooks() error { return &Failure{Kind: "unsupported_platform"} }
func SSEHeaderHookRequest(*Request, []byte, uint64, uint64, uint64, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func LoadHeaderHooks() error { return &Failure{Kind: "unsupported_platform"} }
func HeaderHookRequest(*Request, []byte, uint64, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func HeaderHookCopy(uint64, uint64, *HeaderInvocation, []OutputField, []byte) error {
	return &Failure{Kind: "unsupported_platform"}
}
func HeaderHookReply(uint64, uint64, uint64, []HeaderEdit, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func HeaderHookCancel(uint64, *Reply) error { return &Failure{Kind: "unsupported_platform"} }

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
func LoadWebSocketRoute() error                     { return &Failure{Kind: "unsupported_platform"} }
func WebSocketOpenWithRoute(*WebSocketOpening, *WebSocketRoute, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func WebSocketOperation(uint64, uint64, uint64, uint64, []byte, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func WebSocketCopy(uint64, *WebSocketResult, []byte) error {
	return &Failure{Kind: "unsupported_platform"}
}

func LoadEventSource() error { return &Failure{Kind: "unsupported_platform"} }
func EventSourceOpen(*EventSourceOpening, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func EventSourceOperation(uint64, uint64, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func EventSourceCopy(uint64, *EventSourceResult, []byte) error {
	return &Failure{Kind: "unsupported_platform"}
}
