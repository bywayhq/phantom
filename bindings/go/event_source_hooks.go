package phantom

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

type sourceHookFailure struct {
	operation uint64
	cause     error
}
type eventSourceHooks struct {
	client        *Client
	context       context.Context
	handle        uint64
	hooks         []HeaderHook
	done          chan struct{}
	operation     atomic.Uint64
	mu            sync.Mutex
	last, cleanup *sourceHookFailure
}

func startEventSourceHooks(client *Client, handle uint64, hooks []HeaderHook, ctx context.Context) *eventSourceHooks {
	owner := &eventSourceHooks{client: client, context: context.WithoutCancel(ctx), handle: handle, done: make(chan struct{}), hooks: make([]HeaderHook, len(hooks))}
	for index, hook := range hooks {
		owner.hooks[index] = func(ctx context.Context, fields *HeaderHookContext) error {
			err := hook(ctx, fields)
			if err != ctx.Err() {
				owner.remember(owner.operation.Load(), err)
			}
			return err
		}
	}
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
	failure := &sourceHookFailure{operation, err}
	owner.last = failure
	if owner.cleanup == nil {
		owner.cleanup = failure
	}
	owner.mu.Unlock()
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
		hooks := &requestHooks{hooks: owner.hooks, ctx: ctx, cancel: cancel, next: next, source: true}
		err := performSubmittedWithHooks(context.Background(), func() (uint64, error) {
			operation, err := eventSourceHooksOperation(1, owner.handle)
			owner.operation.Store(operation)
			return operation, err
		}, nil, func(completion) error { return nil }, hooks)
		cancel()
		next = hooks.next % uint64(len(owner.hooks))
		if err != nil {
			next = 0
			if kind(err) == "sse_closed" {
				return
			}
			if kind(err) != "header_hook" && kind(err) != "source_header_cancelled" {
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
	owner.cleanup = nil
	owner.mu.Unlock()
	owner.client.removeSourceHooks(owner)
	if failure == nil {
		return nil
	}
	return &Error{Kind: "header_hook", cause: failure.cause}
}
func (owner *eventSourceHooks) attach(err error, operation uint64) error {
	if owner == nil || err == nil || operation == 0 {
		return err
	}
	owner.mu.Lock()
	failure := owner.last
	if failure == nil || failure.operation != operation {
		owner.mu.Unlock()
		return err
	}
	if owner.cleanup != nil && owner.cleanup.operation == operation {
		owner.cleanup = nil
	}
	owner.mu.Unlock()
	var primary *Error
	if errors.As(err, &primary) {
		copy := *primary
		copy.cause = errors.Join(err, failure.cause)
		return &copy
	}
	return &Error{Kind: "header_hook", cause: errors.Join(err, failure.cause)}
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
