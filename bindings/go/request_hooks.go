package phantom

import (
	"context"
	"strconv"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

// RequestHooks observes one logical send, including all retries and redirects.
// Client callbacks precede request callbacks. EventSource runs them for each
// fresh GET. Empty bundles make no callback bridge. Functions may run concurrently.
// Callbacks must honor ctx cancellation; Do and shutdown wait for their return.
// Metadata excludes bodies. Response failure does not trigger OnError; caller
// cancellation and dropped operations do not invoke OnError. Callback work shares
// the request's total deadline. Late failures remain available through errors.Is.
type RequestHooks struct {
	OnRequest  func(context.Context, RequestHookContext) error
	OnResponse func(context.Context, ResponseHookContext) error
	OnError    func(context.Context, RequestErrorHookContext) error
}

// RequestHookContext identifies the original request before redirects.
// URLs may contain secrets; formatting omits them.
type RequestHookContext struct{ method, url string }

// Method returns the original method.
func (c RequestHookContext) Method() string { return c.method }

// URL returns the resolved initial URL.
func (c RequestHookContext) URL() string      { return c.url }
func (RequestHookContext) String() string     { return "phantom.RequestHookContext{[redacted]}" }
func (c RequestHookContext) GoString() string { return c.String() }

// ResponseHookContext describes the final response head, including 4xx/5xx.
// Headers reflect content-decoding preparation, without original wire ordering.
// The callback cannot consume the body or alter the response.
type ResponseHookContext struct {
	request                RequestHookContext
	status                 int
	protocol, effectiveURL string
	headers                []Header
	redirects, retries     uint64
	codings                []string
}

// Request returns the original logical request.
func (c ResponseHookContext) Request() RequestHookContext { return c.request }

// Status returns the final HTTP status.
func (c ResponseHookContext) Status() int { return c.status }

// Protocol returns h1, h2 or h3.
func (c ResponseHookContext) Protocol() string { return c.protocol }

// EffectiveURL returns the final URL after redirects.
func (c ResponseHookContext) EffectiveURL() string { return c.effectiveURL }

// Headers returns an owned copy, preserving duplicates and sensitivity.
func (c ResponseHookContext) Headers() []Header { return copyHookHeaders(c.headers) }

// RedirectsFollowed returns the number of followed hops.
func (c ResponseHookContext) RedirectsFollowed() uint64 { return c.redirects }

// ConnectionSetupRetries returns connection-failure retries across redirect hops.
func (c ResponseHookContext) ConnectionSetupRetries() uint64 { return c.retries }

// DecodedContentCodings returns an owned copy of selected content decoders.
func (c ResponseHookContext) DecodedContentCodings() []string {
	return append([]string(nil), c.codings...)
}
func (c ResponseHookContext) String() string {
	return "phantom.ResponseHookContext{status:" + strconv.Itoa(c.status) + "}"
}
func (c ResponseHookContext) GoString() string { return c.String() }

// RequestErrorHookContext exposes the terminal error and its original Go cause.
// A failing OnError preserves this error as primary and joins the callback error.
type RequestErrorHookContext struct {
	request RequestHookContext
	err     error
}

// Request returns the original logical request.
func (c RequestErrorHookContext) Request() RequestHookContext { return c.request }

// Error returns the typed request error with any original callback cause.
func (c RequestErrorHookContext) Error() error     { return c.err }
func (RequestErrorHookContext) String() string     { return "phantom.RequestErrorHookContext{[redacted]}" }
func (c RequestErrorHookContext) GoString() string { return c.String() }

func (h RequestHooks) phases() uint64 {
	var result uint64
	if h.OnRequest != nil {
		result |= 1
	}
	if h.OnResponse != nil {
		result |= 2
	}
	if h.OnError != nil {
		result |= 4
	}
	return result
}
func snapshotRequestHooks(bundles ...RequestHooks) ([]RequestHooks, uint64) {
	var hooks []RequestHooks
	var phases uint64
	for _, bundle := range bundles {
		if mask := bundle.phases(); mask != 0 {
			hooks = append(hooks, bundle)
			phases |= mask
		}
	}
	return hooks, phases
}

type logicalCall struct {
	ticket, phase, causeOperation uint64
	request                       RequestHookContext
	response                      ResponseHookContext
	err                           error
}

func readLogicalCall(event native.Event, fields []native.OutputField, arena []byte) (completion, error) {
	if event.Part == 0 || event.FieldCount != 0 || event.ArenaLength != 0 || event.DataLength != 0 {
		return completion{}, &Error{Kind: "native_abi"}
	}
	var value native.LogicalInvocation
	if err := native.LogicalHookCopy(event.Operation, event.Part, &value, fields, arena); err != nil {
		return completion{}, nativeBoundaryError(err)
	}
	if err := nativeRecordError(value.Error); err != nil {
		return completion{}, err
	}
	return decodeLogicalCall(event.Operation, event.Part, value, fields, arena)
}
func decodeLogicalCall(operation, ticket uint64, value native.LogicalInvocation, fields []native.OutputField, arena []byte) (completion, error) {
	invalid := func() (completion, error) { return completion{}, &Error{Kind: "native_abi"} }
	if value.ArenaLength > uint64(len(arena)) || value.FieldCount > uint64(len(fields)) || value.CodingCount > uint64(len(fields))-value.FieldCount {
		return invalid()
	}
	arena = arena[:value.ArenaLength]
	bytes := func(span native.Slice) ([]byte, error) {
		if span.Offset > uint64(len(arena)) || span.Length > uint64(len(arena))-span.Offset {
			return nil, &Error{Kind: "native_abi"}
		}
		return arena[span.Offset : span.Offset+span.Length], nil
	}
	text := func(span native.Slice) (string, error) { data, err := bytes(span); return string(data), err }
	method, err := text(value.Method)
	if err != nil {
		return completion{}, err
	}
	url, err := text(value.URI)
	if err != nil {
		return completion{}, err
	}
	if method == "" || url == "" {
		return invalid()
	}
	call := &logicalCall{ticket: ticket, phase: value.Phase, causeOperation: value.CauseOperation, request: RequestHookContext{method, url}}
	switch value.Phase {
	case 1:
		if value.FieldCount != 0 || value.CodingCount != 0 || nativeRecordError(value.Failure) != nil {
			return invalid()
		}
	case 2:
		if value.Status < 100 || value.Status > 999 || nativeRecordError(value.Failure) != nil {
			return invalid()
		}
		protocol := ""
		switch value.Protocol {
		case 1:
			protocol = "h1"
		case 2:
			protocol = "h2"
		case 3:
			protocol = "h3"
		default:
			return invalid()
		}
		effective, err := text(value.EffectiveURI)
		if err != nil {
			return completion{}, err
		}
		if effective == "" {
			return invalid()
		}
		call.response = ResponseHookContext{request: call.request, status: int(value.Status), protocol: protocol, effectiveURL: effective, redirects: value.Redirects, retries: value.Retries, headers: make([]Header, value.FieldCount)}
		for i := range call.response.headers {
			field := fields[i]
			name, err := text(field.Name)
			if err != nil {
				return completion{}, err
			}
			value, err := bytes(field.Value)
			if err != nil {
				return completion{}, err
			}
			if field.Sensitive > 1 {
				return invalid()
			}
			call.response.headers[i] = Header{Name: name, Value: append([]byte(nil), value...), Sensitive: field.Sensitive != 0}
		}
		for _, field := range fields[value.FieldCount : value.FieldCount+value.CodingCount] {
			name, err := text(field.Name)
			if err != nil {
				return completion{}, err
			}
			call.response.codings = append(call.response.codings, name)
		}
	case 4:
		if value.FieldCount != 0 || value.CodingCount != 0 {
			return invalid()
		}
		call.err = nativeRecordError(value.Failure)
		if call.err == nil {
			return invalid()
		}
	default:
		return invalid()
	}
	return completion{Operation: operation, kind: 8, logical: call}, nil
}
func replyLogicalCall(operation, ticket, outcome uint64) error {
	var reply native.Reply
	if err := native.LogicalHookReply(operation, ticket, outcome, &reply); err != nil {
		return nativeBoundaryError(err)
	}
	return nativeRecordError(reply.Error)
}
func (h *requestHooks) invokeLogical(operation uint64, call *logicalCall) error {
	if call == nil || h.phases&call.phase == 0 {
		return &Error{Kind: "native_abi"}
	}
	// Return custody after a race, a rejected reply or a caller panic.
	defer func() { _ = replyLogicalCall(operation, call.ticket, 2) }()
	if h.ctx.Err() != nil {
		return nil
	}
	if h.source {
		var reply native.Reply
		if err := native.EventSourceHooksActive(operation, call.ticket, &reply); err != nil {
			return nativeBoundaryError(err)
		}
		if err := nativeRecordError(reply.Error); err != nil {
			return err
		}
		if reply.Operation == 0 {
			return nil
		}
		if reply.Operation != 1 {
			return &Error{Kind: "native_abi"}
		}
	}
	if h.sourceOwner != nil && call.phase == 4 && call.causeOperation != 0 {
		if prior := h.sourceOwner.causeFor(call.causeOperation); prior != nil {
			h.failure, h.failureKind = prior, "request_hook"
			h.priorOperation = call.causeOperation
		}
	}
	err := h.observeLogical(call)
	if err != nil {
		h.rememberFailure(err, "request_hook")
	}
	if h.ctx.Err() != nil {
		return nil
	}
	outcome := uint64(0)
	if err != nil {
		outcome = 1
	}
	err = replyLogicalCall(operation, call.ticket, outcome)
	if failure, ok := err.(*Error); ok && failure.Kind == "header_hook_closed" {
		return nil
	}
	if err != nil && h.ctx.Err() == nil {
		return err
	}
	return nil
}
func (h *requestHooks) observeLogical(call *logicalCall) error {
	for _, hooks := range h.logical {
		var err error
		switch call.phase {
		case 1:
			if hooks.OnRequest != nil {
				err = hooks.OnRequest(h.ctx, call.request)
			}
		case 2:
			if hooks.OnResponse != nil {
				err = hooks.OnResponse(h.ctx, call.response)
			}
		case 4:
			if hooks.OnError != nil {
				err = hooks.OnError(h.ctx, RequestErrorHookContext{call.request, h.wrap(call.err)})
			}
		default:
			return &Error{Kind: "native_abi"}
		}
		if err != nil {
			return err
		}
		if h.ctx.Err() != nil {
			return nil
		}
	}
	return nil
}
func (h *requestHooks) rememberFailure(err error, kind string) {
	if h.failure == nil {
		h.failure, h.failureKind = err, kind
	} else if h.secondary == nil {
		h.secondary = err
	}
	// Publish the actual Go failure before replying: the core can deliver its
	// terminal source result as soon as the reply is accepted.
	if h.sourceOwner != nil && err != h.ctx.Err() {
		h.sourceOwner.rememberInvocation(h.sourceOwner.operation.Load(), h)
	}
}
