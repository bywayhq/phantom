package native

// EventSourceHooksReply extends only the independently negotiated source-hook opening.
type EventSourceHooksReply struct {
	Operation, Owner uint64
	Error            ErrorRecord
}
