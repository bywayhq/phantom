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

func LoadEventSourceHooks() error { return &Failure{Kind: "unsupported_platform"} }
func EventSourceHooksOpen(*EventSourceOpening, uint64, *EventSourceHooksReply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func EventSourceHooksOperation(uint64, uint64, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}
func EventSourceHooksFailure(uint64, *uint64, *Reply) error {
	return &Failure{Kind: "unsupported_platform"}
}

func EventSourceHooksActive(uint64, uint64, *Reply) error {
	return &Failure{Kind: "native_unavailable"}
}

func LoadLogicalHooks() error { return &Failure{Kind: "unsupported_platform"} }
func LogicalHookRequest(*Request, []byte, *LogicalHookOptions, *Reply) error {
	return LoadLogicalHooks()
}
func LogicalHookCopy(uint64, uint64, *LogicalInvocation, []OutputField, []byte) error {
	return LoadLogicalHooks()
}
func LogicalHookReply(uint64, uint64, uint64, *Reply) error { return LoadLogicalHooks() }
func LogicalHookSourceOpen(*EventSourceOpening, uint64, uint64, *EventSourceHooksReply) error {
	return LoadLogicalHooks()
}
