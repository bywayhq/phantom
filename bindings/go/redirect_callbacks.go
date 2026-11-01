package phantom

import (
	"context"
	"strconv"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

// RedirectDecision selects whether to follow a proposed hop, return its unread
// response, or fail the request. The zero value is invalid.
type RedirectDecision uint64

const (
	// RedirectFollow selects the proposed next request.
	RedirectFollow RedirectDecision = iota + 1
	// RedirectStop returns the current response and its unread body.
	RedirectStop
	// RedirectReject fails with a redirect error.
	RedirectReject
)

// RedirectAttempt is a validated proposal. Hop starts at one. URLs may contain
// secrets; formatting omits them. Changing this value cannot change the hop.
// URL and method text together are limited to 256 KiB before callback execution.
type RedirectAttempt struct {
	FromURL, ToURL     string
	Method, NextMethod string
	Status             int
	Hop                uint64
}

func (a RedirectAttempt) String() string {
	return "RedirectAttempt{status:" + strconv.Itoa(a.Status) + ", hop:" + strconv.FormatUint(a.Hop, 10) + "}"
}
func (a RedirectAttempt) GoString() string { return a.String() }

// RedirectCallback runs once per proposed hop, after header hooks. A failure
// returns a redirect error retaining the original error through errors.Is/As.
// Callbacks may run concurrently across requests and must honor cancellation.
// Do and Shutdown wait for actual callback return; user code is not preempted.
// Cancellation and total deadlines remain primary, retaining late errors.
// Replay safety, credential stripping and attempt budgets remain enforced.
type RedirectCallback func(context.Context, RedirectAttempt) (RedirectDecision, error)

type redirectCall struct {
	ticket  uint64
	attempt RedirectAttempt
}

func readRedirectCall(event native.Event, arena []byte) (completion, error) {
	if event.Part == 0 || event.FieldCount != 0 || event.ArenaLength != 0 || event.DataLength != 0 {
		return completion{}, &Error{Kind: "native_abi"}
	}
	var invocation native.RedirectInvocation
	if err := native.RedirectHookCopy(event.Operation, event.Part, &invocation, arena); err != nil {
		return completion{}, nativeBoundaryError(err)
	}
	if err := nativeRecordError(invocation.Error); err != nil {
		return completion{}, err
	}
	if invocation.ArenaLength > uint64(len(arena)) || invocation.Status < 300 || invocation.Status > 399 || invocation.Hop == 0 {
		return completion{}, &Error{Kind: "native_abi"}
	}
	switch invocation.Status {
	case 301, 302, 303, 307, 308:
	default:
		return completion{}, &Error{Kind: "native_abi"}
	}
	arena = arena[:invocation.ArenaLength]
	text := func(span native.Slice) (string, error) {
		if span.Offset > uint64(len(arena)) || span.Length > uint64(len(arena))-span.Offset {
			return "", &Error{Kind: "native_abi"}
		}
		return string(arena[span.Offset : span.Offset+span.Length]), nil
	}
	from, err := text(invocation.From)
	if err != nil {
		return completion{}, err
	}
	to, err := text(invocation.To)
	if err != nil {
		return completion{}, err
	}
	method, err := text(invocation.Method)
	if err != nil {
		return completion{}, err
	}
	next, err := text(invocation.NextMethod)
	if err != nil {
		return completion{}, err
	}
	if from == "" || to == "" || method == "" || next == "" {
		return completion{}, &Error{Kind: "native_abi"}
	}
	return completion{Operation: event.Operation, kind: event.Kind, redirect: &redirectCall{event.Part, RedirectAttempt{from, to, method, next, int(invocation.Status), invocation.Hop}}}, nil
}

func replyRedirectCall(operation, ticket, outcome uint64, decision RedirectDecision) error {
	var reply native.Reply
	if err := native.RedirectHookReply(operation, ticket, outcome, uint64(decision), &reply); err != nil {
		return nativeBoundaryError(err)
	}
	return nativeRecordError(reply.Error)
}

func (h *requestHooks) invokeRedirect(operation uint64, call *redirectCall) error {
	if call == nil {
		return &Error{Kind: "native_abi"}
	}
	// A closed invocation still needs handback after a race, bad reply or panic.
	defer func() { _ = replyRedirectCall(operation, call.ticket, 2, 0) }()
	if h.redirect == nil || call.attempt.Hop != h.redirectHop+1 {
		return &Error{Kind: "native_abi"}
	}
	if h.ctx.Err() != nil {
		return nil
	}
	h.redirectHop = call.attempt.Hop
	decision, err := h.redirect(h.ctx, call.attempt)
	if err != nil {
		h.failure, h.failureKind = err, "redirect"
	}
	if h.ctx.Err() != nil {
		return nil
	}
	if err == nil && (decision < RedirectFollow || decision > RedirectReject) {
		err = &Error{Kind: "invalid_redirect_decision"}
	}
	outcome := uint64(0)
	if err != nil {
		h.failure, h.failureKind = err, "redirect"
		outcome, decision = 1, 0
	}
	err = replyRedirectCall(operation, call.ticket, outcome, decision)
	if failure, ok := err.(*Error); ok && failure.Kind == "header_hook_closed" {
		return nil
	}
	if err != nil && h.ctx.Err() == nil {
		return err
	}
	return nil
}
