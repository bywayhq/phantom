package native

// LogicalInvocation contains only offsets into the call's bounded output arena.
type LogicalInvocation struct {
	Phase, CauseOperation                                    uint64
	Method, URI                                              Slice
	Status, Protocol                                         uint64
	EffectiveURI                                             Slice
	Redirects, Retries, FieldCount, CodingCount, ArenaLength uint64
	Failure, Error                                           ErrorRecord
}

type LogicalHookOptions struct {
	Headers, Redirect, Phases uint64
	Limits                    *CallbackSSELimits
}
