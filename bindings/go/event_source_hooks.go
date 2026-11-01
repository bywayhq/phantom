package phantom

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

type sourceHookFailure struct {
	operation      uint64
	cause          error
	kind           string
	priorOperation uint64
	prior          *sourceHookFailure
	reported       bool
}
type eventSourceHooks struct {
	client        *Client
	context       context.Context
	handle        uint64
	hooks         []HeaderHook
	logical       []RequestHooks
	phases        uint64
	done          chan struct{}
	operation     atomic.Uint64
	mu            sync.Mutex
	last, cleanup *sourceHookFailure
}

func startEventSourceHooks(client *Client, handle uint64, hooks []HeaderHook, logical []RequestHooks, phases uint64, ctx context.Context) *eventSourceHooks {
	owner := &eventSourceHooks{client: client, context: context.WithoutCancel(ctx), handle: handle, done: make(chan struct{}), hooks: hooks, logical: logical, phases: phases}
	client.sourceMu.Lock()
	if client.sourceHooks == nil {
		client.sourceHooks = make(map[*eventSourceHooks]struct{})
	}
	client.sourceHooks[owner] = struct{}{}
	client.sourceMu.Unlock()
	go owner.run()
	return owner
}
func (owner *eventSourceHooks) remember(operation uint64, err error) {
	if err == nil {
		return
	}
	owner.mu.Lock()
	failure := &sourceHookFailure{operation: operation, cause: err, kind: "header_hook"}
	owner.last = failure
	if owner.cleanup == nil {
		owner.cleanup = failure
	}
	owner.mu.Unlock()
}
func (failure *sourceHookFailure) matches(operation uint64) bool {
	return failure != nil && (failure.operation == operation || (operation != 0 && failure.priorOperation == operation))
}
func (owner *eventSourceHooks) failureFor(operation uint64) *sourceHookFailure {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.last.matches(operation) {
		return owner.last
	}
	if owner.cleanup.matches(operation) {
		return owner.cleanup
	}
	return nil
}
func (owner *eventSourceHooks) causeFor(operation uint64) error {
	if failure := owner.failureFor(operation); failure != nil {
		return failure.cause
	}
	return nil
}

func (owner *eventSourceHooks) rememberInvocation(operation uint64, hooks *requestHooks) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	cause := hooks.failure
	if hooks.sourcePrior != nil && hooks.sourcePrior.reported {
		// The public timeout already exposed the primary cause while this
		// error callback was still cleaning up. Retain only its late failure.
		cause = hooks.secondary
	} else if hooks.secondary != nil {
		cause = errors.Join(cause, hooks.secondary)
	}
	failure := &sourceHookFailure{operation: operation, cause: cause, kind: hooks.failureKind, priorOperation: hooks.priorOperation, prior: hooks.sourcePrior}
	owner.last = failure
	if owner.cleanup == nil || owner.cleanup.matches(hooks.priorOperation) {
		owner.cleanup = failure
	}
}

func (owner *eventSourceHooks) run() {
	defer close(owner.done)
	defer func() {
		// Every callback's native operation was acknowledged before release.
		if _, err := eventSourceHooksOperation(3, owner.handle); err != nil {
			owner.remember(owner.operation.Load(), err)
		}
		owner.mu.Lock()
		clean := owner.cleanup == nil
		owner.mu.Unlock()
		if clean {
			owner.client.removeSourceHooks(owner)
		}
	}()
	next := uint64(0)
	for {
		ctx, cancel := context.WithCancel(owner.context)
		hooks := &requestHooks{hooks: owner.hooks, ctx: ctx, cancel: cancel, next: next, source: true, logical: owner.logical, phases: owner.phases, sourceOwner: owner}
		err := performSubmittedWithHooks(context.Background(), func() (uint64, error) {
			operation, err := eventSourceHooksOperation(1, owner.handle)
			owner.operation.Store(operation)
			return operation, err
		}, nil, func(completion) error { return nil }, hooks)
		cancel()
		next = 0
		if len(owner.hooks) != 0 {
			next = hooks.next % uint64(len(owner.hooks))
		}
		if err != nil {
			next = 0
			if kind(err) == "sse_closed" {
				return
			}
			if kind(err) != "header_hook" && kind(err) != "request_hook" && kind(err) != "source_header_cancelled" {
				owner.remember(owner.operation.Load(), err)
				owner.stop()
				return
			}
		}
		// A GET may time out after its host failure was delivered. The source
		// decides whether to reconnect; keep serving it until terminal close.
	}
}
func (owner *eventSourceHooks) stop() {
	if owner != nil {
		if _, err := eventSourceHooksOperation(2, owner.handle); err != nil {
			owner.remember(owner.operation.Load(), err)
		}
	}
}
func (owner *eventSourceHooks) wait(ctx context.Context) error {
	if owner == nil {
		return nil
	}
	if ctx == nil {
		return &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-owner.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	owner.mu.Lock()
	failure := owner.cleanup
	if failure != nil {
		failure.reported = true
		if failure.prior != nil {
			failure.prior.reported = true
		}
	}
	owner.cleanup = nil
	owner.mu.Unlock()
	owner.client.removeSourceHooks(owner)
	if failure == nil {
		return nil
	}
	return &Error{Kind: failure.kind, cause: failure.cause}
}
func (owner *eventSourceHooks) attach(err error, operation uint64) error {
	if owner == nil || err == nil || operation == 0 {
		return err
	}
	owner.mu.Lock()
	failure := owner.last
	if !failure.matches(operation) {
		owner.mu.Unlock()
		return err
	}
	failure.reported = true
	if failure.prior != nil {
		failure.prior.reported = true
	}
	if owner.cleanup.matches(operation) {
		owner.cleanup = nil
	}
	owner.mu.Unlock()
	var primary *Error
	if errors.As(err, &primary) {
		copy := *primary
		copy.cause = errors.Join(err, failure.cause)
		return &copy
	}
	return &Error{Kind: failure.kind, cause: errors.Join(err, failure.cause)}
}
func (client *Client) removeSourceHooks(owner *eventSourceHooks) {
	client.sourceMu.Lock()
	delete(client.sourceHooks, owner)
	client.sourceMu.Unlock()
}
func (client *Client) waitSourceHooks(ctx context.Context) error {
	client.sourceMu.Lock()
	owners := make([]*eventSourceHooks, 0, len(client.sourceHooks))
	for owner := range client.sourceHooks {
		owners = append(owners, owner)
	}
	client.sourceMu.Unlock()
	if len(owners) == 0 {
		return nil
	}
	if ctx == nil {
		return &Error{Kind: "invalid_context"}
	}
	var first error
	for _, owner := range owners {
		err := owner.wait(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if first == nil {
			first = err
		}
	}
	return first
}
func eventSourceHooksOperation(verb, handle uint64) (uint64, error) {
	var reply native.Reply
	if err := native.EventSourceHooksOperation(verb, handle, &reply); err != nil {
		return 0, nativeBoundaryError(err)
	}
	return reply.Operation, nativeRecordError(reply.Error)
}
func eventSourceHookFailure(operation uint64) (uint64, error) {
	var ticket uint64
	var reply native.Reply
	if err := native.EventSourceHooksFailure(operation, &ticket, &reply); err != nil {
		return 0, nativeBoundaryError(err)
	}
	return ticket, nativeRecordError(reply.Error)
}
