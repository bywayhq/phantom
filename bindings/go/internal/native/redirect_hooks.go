package native

type RedirectInvocation struct {
	From, To, Method, NextMethod Slice
	Status, Hop, ArenaLength     uint64
	Error                        ErrorRecord
}

// CallbackSSELimits is present only for a single-response SSE opening.
type CallbackSSELimits struct{ Line, Event uint64 }
