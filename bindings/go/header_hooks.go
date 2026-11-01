package phantom

import (
	"context"
	"runtime"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

// HeaderHook edits caller headers before a logical Do or Events request is sent.
// Client hooks run first, then request hooks. Redirects and retries reuse the
// result. Functions run on the calling goroutine and must honor ctx cancellation.
// Hooks on different requests may run concurrently.
type HeaderHook func(ctx context.Context, headers *HeaderHookContext) error

// HeaderHookContext exposes the initial resolved request and ordered caller
// headers, including prepared-body fields and earlier hook edits. Generated
// cookies and template literals are added afterward. It never exposes the body.
// Use it only during the callback; mutation after return fails.
type HeaderHookContext struct {
	method, url string
	headers     []Header
	edits       []headerEdit
	active      bool
}

type headerEdit struct {
	kind   uint64
	header Header
}

// Method returns the initial request method.
func (h *HeaderHookContext) Method() string { return h.method }

// URL returns the resolved initial URL. It may contain credentials or query secrets.
func (h *HeaderHookContext) URL() string { return h.url }

// Headers returns an owned ordered copy, preserving duplicate names and sensitivity.
func (h *HeaderHookContext) Headers() []Header { return copyHookHeaders(h.headers) }
func (HeaderHookContext) String() string       { return "phantom.HeaderHookContext{[redacted]}" }
func (h HeaderHookContext) GoString() string   { return h.String() }

// Append adds a field at the end. Names and values are validated by Rust before I/O.
// The hook may record at most 256 edits and 64 KiB of names and values.
func (h *HeaderHookContext) Append(header Header) error { return h.edit(1, header) }

// Set replaces the first matching field and removes later duplicates, ignoring ASCII case.
// A new name is appended. Template expansion still owns final spelling and position.
func (h *HeaderHookContext) Set(header Header) error { return h.edit(2, header) }

// Remove removes all caller fields with this name, ignoring ASCII case.
// A removed override may reveal a template literal afterward.
func (h *HeaderHookContext) Remove(name string) error { return h.edit(3, Header{Name: name}) }

func copyHookHeaders(headers []Header) []Header {
	result := make([]Header, len(headers))
	for i, header := range headers {
		result[i] = Header{Name: header.Name, Value: append([]byte(nil), header.Value...), Sensitive: header.Sensitive}
	}
	return result
}

func sameHookHeaderName(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range len(left) {
		a, b := left[i], right[i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

func (h *HeaderHookContext) edit(kind uint64, header Header) error {
	if !h.active {
		return &Error{Kind: "header_hook_closed"}
	}
	remaining := 64 * 1024
	consume := func(header Header) bool {
		if len(header.Name) > remaining || len(header.Value) > remaining-len(header.Name) {
			return false
		}
		remaining -= len(header.Name) + len(header.Value)
		return true
	}
	if len(h.edits) >= 256 || !consume(header) {
		return &Error{Kind: "input_limit"}
	}
	for _, edit := range h.edits {
		if !consume(edit.header) {
			return &Error{Kind: "input_limit"}
		}
	}
	header.Value = append([]byte(nil), header.Value...)
	h.edits = append(h.edits, headerEdit{kind, header})
	switch kind {
	case 1:
		h.headers = append(h.headers, header)
	case 2, 3:
		found := false
		output := h.headers[:0]
		for _, old := range h.headers {
			if sameHookHeaderName(old.Name, header.Name) {
				if !found && kind == 2 {
					output = append(output, header)
				}
				found = true
			} else {
				output = append(output, old)
			}
		}
		if !found && kind == 2 {
			output = append(output, header)
		}
		h.headers = output
	}
	return nil
}

type headerCall struct {
	ticket, index uint64
	context       HeaderHookContext
}

type requestHooks struct {
	hooks       []HeaderHook
	ctx         context.Context
	cancel      context.CancelFunc
	next        uint64
	failure     error
	failureKind string
	redirect    RedirectCallback
	redirectHop uint64
}

func snapshotHeaderHooks(client, request []HeaderHook) ([]HeaderHook, error) {
	if len(client) == 0 && len(request) == 0 {
		return nil, nil
	}
	if len(client) > 256 || len(request) > 256-len(client) {
		return nil, &Error{Kind: "invalid_header_hooks"}
	}
	hooks := append(append(make([]HeaderHook, 0, len(client)+len(request)), client...), request...)
	for _, hook := range hooks {
		if hook == nil {
			return nil, &Error{Kind: "invalid_header_hooks"}
		}
	}
	return hooks, nil
}

func newRequestHooks(ctx context.Context, client, request []HeaderHook, redirect RedirectCallback) (*requestHooks, error) {
	hooks, err := snapshotHeaderHooks(client, request)
	if err != nil || (len(hooks) == 0 && redirect == nil) {
		return nil, err
	}
	derived, cancel := context.WithCancel(ctx)
	return &requestHooks{hooks: hooks, ctx: derived, cancel: cancel, redirect: redirect}, nil
}

func readHeaderCall(event native.Event, fields []native.OutputField, arena []byte) (completion, error) {
	var invocation native.HeaderInvocation
	if event.Part == 0 || event.FieldCount != 0 || event.ArenaLength != 0 || event.DataLength != 0 {
		return completion{}, &Error{Kind: "native_abi"}
	}
	if err := native.HeaderHookCopy(event.Operation, event.Part, &invocation, fields, arena); err != nil {
		return completion{}, nativeBoundaryError(err)
	}
	if err := nativeRecordError(invocation.Error); err != nil {
		return completion{}, err
	}
	if invocation.FieldCount > uint64(len(fields)) || invocation.ArenaLength > uint64(len(arena)) {
		return completion{}, &Error{Kind: "native_abi"}
	}
	arena = arena[:invocation.ArenaLength]
	slice := func(value native.Slice) ([]byte, error) {
		if value.Offset > uint64(len(arena)) || value.Length > uint64(len(arena))-value.Offset {
			return nil, &Error{Kind: "native_abi"}
		}
		return arena[value.Offset : value.Offset+value.Length], nil
	}
	method, err := slice(invocation.Method)
	if err != nil {
		return completion{}, err
	}
	uri, err := slice(invocation.URI)
	if err != nil {
		return completion{}, err
	}
	call := &headerCall{ticket: event.Part, index: invocation.Index, context: HeaderHookContext{method: string(method), url: string(uri), active: true}}
	call.context.headers = make([]Header, invocation.FieldCount)
	for i := range call.context.headers {
		field := fields[i]
		name, err := slice(field.Name)
		if err != nil {
			return completion{}, err
		}
		value, err := slice(field.Value)
		if err != nil {
			return completion{}, err
		}
		if field.Sensitive > 1 {
			return completion{}, &Error{Kind: "native_abi"}
		}
		call.context.headers[i] = Header{Name: string(name), Value: append([]byte(nil), value...), Sensitive: field.Sensitive != 0}
	}
	return completion{Operation: event.Operation, kind: 6, header: call}, nil
}

func replyHeaderCall(operation, ticket, outcome uint64, edits []headerEdit) error {
	fields := make([]native.HeaderEdit, len(edits))
	for i, edit := range edits {
		fields[i] = native.HeaderEdit{Kind: edit.kind, Field: native.Field{Name: native.BorrowedString(edit.header.Name), Value: native.BorrowedBytes(edit.header.Value), Sensitive: boolean(edit.header.Sensitive)}}
	}
	var reply native.Reply
	err := native.HeaderHookReply(operation, ticket, outcome, fields, &reply)
	runtime.KeepAlive(edits)
	if err != nil {
		return nativeBoundaryError(err)
	}
	return nativeRecordError(reply.Error)
}

func cancelHeaderRequest(operation uint64) {
	var reply native.Reply
	// A terminal completion may already have released this request.
	_ = native.HeaderHookCancel(operation, &reply)
}

func (h *requestHooks) invoke(operation uint64, call *headerCall) error {
	if call == nil {
		return &Error{Kind: "native_abi"}
	}
	defer func() {
		call.context.active = false
		// Complete is single-use; discard also releases custody after a race or panic.
		_ = replyHeaderCall(operation, call.ticket, 2, nil)
	}()
	if h.ctx.Err() != nil {
		return nil
	}
	if call.index != h.next || call.index >= uint64(len(h.hooks)) {
		return &Error{Kind: "native_abi"}
	}
	h.next++
	err := h.hooks[call.index](h.ctx, &call.context)
	if h.ctx.Err() != nil {
		return nil
	}
	outcome := uint64(0)
	if err != nil {
		h.failure = err
		h.failureKind = "header_hook"
		outcome = 1
	}
	edits := call.context.edits
	if outcome != 0 {
		edits = nil
	}
	err = replyHeaderCall(operation, call.ticket, outcome, edits)
	if failure, ok := err.(*Error); ok && failure.Kind == "header_hook_closed" {
		return nil
	}
	if err != nil && h.ctx.Err() == nil {
		return err
	}
	return nil
}

func (h *requestHooks) wrap(err error) error {
	if h != nil && h.failure != nil {
		if failure, ok := err.(*Error); ok && failure.Kind == h.failureKind {
			copy := *failure
			copy.cause = h.failure
			return &copy
		}
	}
	return err
}
