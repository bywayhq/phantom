package native

// HeaderInvocation uses offsets into the copy call's caller-owned arena.
type HeaderInvocation struct {
	Index                   uint64
	Method, URI             Slice
	FieldCount, ArenaLength uint64
	Error                   ErrorRecord
}

type HeaderEdit struct {
	Kind  uint64
	Field Field
}
