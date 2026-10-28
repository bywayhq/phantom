package phantom

import (
	"context"
	"io"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

// EventSource pulls events from a reconnecting GET without a background reader
// or queue. Close it when finished. Initial response fields describe only the
// opening response; state getters describe the last completed Next call.
type EventSource struct {
	Status                                    int
	Protocol                                  string
	Headers                                   []Header
	EffectiveURL                              string
	RedirectsFollowed, ConnectionSetupRetries uint64
	DecodedContentCodings                     []string
	RedirectHistory                           *RedirectHistory
	client                                    *Client
	id                                        atomic.Uint64
	closed                                    atomic.Bool
	read                                      sync.Mutex
	state                                     sync.RWMutex
	lastID                                    string
	retry, reconnects                         uint64
}

// EventSource opens a reconnecting stream. ctx bounds opening only; Next uses
// its own context. HTTP 204 returns an already-closed source. Setup and retries
// use the existing Rust EventSource implementation and client policies.
func (c *Client) EventSource(ctx context.Context, url string, options EventSourceOptions) (*EventSource, error) {
	if ctx == nil {
		return nil, &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil || c.closing.Load() || c.id.Load() == 0 {
		return nil, &Error{Kind: "client_closed"}
	}
	opening, err := eventSourceOpeningValue(c.id.Load(), url, options)
	if err != nil {
		return nil, err
	}
	if err := ensureNativeIdentity(); err != nil {
		return nil, err
	}
	if err := nativeBoundaryError(native.LoadEventSource()); err != nil {
		return nil, err
	}
	var source *EventSource
	err = performSubmitted(ctx, func() (uint64, error) {
		var reply native.Reply
		err := nativeBoundaryError(native.EventSourceOpen(&opening.descriptor, &reply))
		runtime.KeepAlive(opening)
		runtime.KeepAlive(options)
		runtime.KeepAlive(url)
		if err != nil {
			return 0, err
		}
		return reply.Operation, nativeRecordError(reply.Error)
	}, nil, func(event completion) error {
		value, data, err := native.ReadEventSourceResult(event.Operation)
		if err != nil {
			return nativeBoundaryError(err)
		}
		result, err := decodeSSEEvent(value.Event, data)
		if err != nil {
			return err
		}
		if result.err != nil {
			return result.err
		}
		if event.head == nil {
			return &Error{Kind: "native_abi"}
		}
		head := event.head
		source = &EventSource{Status: head.Status, Protocol: head.Protocol, Headers: head.Headers, EffectiveURL: head.EffectiveURL, RedirectsFollowed: head.RedirectsFollowed, ConnectionSetupRetries: head.ConnectionSetupRetries, DecodedContentCodings: head.DecodedContentCodings, RedirectHistory: head.RedirectHistory, client: c, lastID: result.event.ID, retry: value.RetryMilliseconds, reconnects: value.Reconnects}
		source.closed.Store(value.Closed != 0)
		if value.Closed == 0 {
			source.id.Store(head.Body)
		}
		runtime.SetFinalizer(source, func(value *EventSource) { _ = value.Close() })
		return nil
	})
	runtime.KeepAlive(c)
	if err != nil {
		if source != nil {
			_ = source.Close()
		}
		return nil, err
	}
	return source, nil
}

// Next returns one event or io.EOF. Terminal errors are returned once, then EOF.
// Cancelling ctx preserves the source and waits for its native read lease to
// return before another Next can start. Competing Next calls fail immediately.
func (source *EventSource) Next(ctx context.Context) (SSEEvent, error) {
	if ctx == nil {
		return SSEEvent{}, &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return SSEEvent{}, err
	}
	if source == nil {
		return SSEEvent{}, &Error{Kind: "sse_closed"}
	}
	if !source.read.TryLock() {
		return SSEEvent{}, &Error{Kind: "concurrent_event_source_read"}
	}
	defer source.read.Unlock()
	if source.closed.Load() {
		return SSEEvent{}, io.EOF
	}
	var operation uint64
	var stop func() bool
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	var received receivedSSE
	var snapshot native.EventSourceResult
	admitted := false
	waitContext := ctx
	if ctx.Done() != nil {
		waitContext = context.WithoutCancel(ctx)
	}
	err := performSubmitted(waitContext, func() (uint64, error) {
		var err error
		operation, err = eventSourceOperation(1, source.id.Load())
		admitted = err == nil
		return operation, err
	}, func() {
		if ctx.Done() == nil {
			return
		}
		stop = context.AfterFunc(ctx, func() {
			// Completion may win the race and already be acknowledged. The cancel
			// result is irrelevant then; the registered completion owns handback.
			_, _ = eventSourceOperation(3, operation)
		})
	}, func(event completion) error {
		value, data, err := native.ReadEventSourceResult(event.Operation)
		if err != nil {
			return nativeBoundaryError(err)
		}
		received, err = decodeSSEEvent(value.Event, data)
		snapshot = value
		return err
	})
	runtime.KeepAlive(source)
	if err := ctx.Err(); err != nil {
		return SSEEvent{}, err
	}
	if err != nil {
		if admitted {
			_ = source.Close()
		}
		return SSEEvent{}, err
	}
	source.state.Lock()
	source.lastID = received.event.ID
	source.retry = snapshot.RetryMilliseconds
	source.reconnects = snapshot.Reconnects
	source.state.Unlock()
	if snapshot.Closed != 0 {
		source.closed.Store(true)
		source.id.Store(0)
	}
	if received.err != nil {
		return SSEEvent{}, received.err
	}
	if received.eof {
		return SSEEvent{}, io.EOF
	}
	return received.event, nil
}

// Close cancels a pending read, reconnect or backoff and releases this source.
// Graceful client shutdown waits for open sources; close them to finish it.
func (source *EventSource) Close() error {
	if source == nil {
		return nil
	}
	source.closed.Store(true)
	id := source.id.Swap(0)
	if id == 0 {
		return nil
	}
	_, err := eventSourceOperation(2, id)
	runtime.KeepAlive(source.client)
	return err
}

func eventSourceOperation(verb, handle uint64) (uint64, error) {
	var reply native.Reply
	if err := nativeBoundaryError(native.EventSourceOperation(verb, handle, &reply)); err != nil {
		return 0, err
	}
	return reply.Operation, nativeRecordError(reply.Error)
}

// LastEventID returns the ID committed by the last completed operation.
func (source *EventSource) LastEventID() string {
	if source == nil {
		return ""
	}
	source.state.RLock()
	defer source.state.RUnlock()
	return source.lastID
}

// RetryMilliseconds returns the effective reconnect delay, including its floor.
func (source *EventSource) RetryMilliseconds() uint64 {
	if source == nil {
		return 0
	}
	source.state.RLock()
	defer source.state.RUnlock()
	return source.retry
}

// Reconnects returns the attempt count from the last completed operation.
func (source *EventSource) Reconnects() uint64 {
	if source == nil {
		return 0
	}
	source.state.RLock()
	defer source.state.RUnlock()
	return source.reconnects
}

// Closed reports local close or the last observed terminal native state.
func (source *EventSource) Closed() bool { return source == nil || source.closed.Load() }
