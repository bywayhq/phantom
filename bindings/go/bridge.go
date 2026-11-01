package phantom

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"unsafe"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

const maxMetadata = 256 * 1024
const maxChunk = 64 * 1024
const maxUpload = 8 * 1024 * 1024

type reply struct {
	Value json.RawMessage `json:"value"`
	Error *Error          `json:"error"`
}
type completion struct {
	Operation uint64
	Error     *Error
	kind      uint64
	data      []byte
	head      *responseHead
	eof       bool
	trailers  ResponseTrailers
	part      uint64
	header    *headerCall
	redirect  *redirectCall
}

var scratch = sync.Pool{New: func() any { return make([]byte, maxMetadata) }}

func dispatch(command any, data []byte) (json.RawMessage, error) {
	input, err := json.Marshal(command)
	if err != nil || len(input) > 64*1024 || len(data) > maxUpload {
		return nil, &Error{Kind: "input_limit"}
	}
	if err := ensureNativeIdentity(); err != nil {
		return nil, err
	}
	output := scratch.Get().([]byte)
	defer scratch.Put(output)
	length, err := nativeDispatch(input, data, output)
	if err != nil {
		return nil, err
	}
	if length <= 0 || length > len(output) {
		return nil, &Error{Kind: "native_abi"}
	}
	var response reply
	if json.Unmarshal(output[:length], &response) != nil {
		return nil, &Error{Kind: "native_abi"}
	}
	if response.Error != nil {
		return nil, response.Error
	}
	return response.Value, nil
}

func control(kind string, idName string, id uint64) error {
	var code uint64
	switch kind {
	case "cancel":
		code = 5
	case "ack":
		code = 6
	case "close_body":
		code = 7
	case "close_upload":
		code = 8
	}
	if code != 0 {
		_, err := submitOperation(code, id, 0, nil)
		return err
	}
	_, err := dispatch(map[string]any{"kind": kind, idName: id}, nil)
	return err
}

var pump struct {
	once          sync.Once
	mu            sync.Mutex
	pending       map[uint64]chan completion
	headerCancels map[uint64]context.CancelFunc
	failure       error
}

func completionPump() {
	arena := make([]byte, maxMetadata)
	data := make([]byte, maxChunk)
	fields := make([]native.OutputField, maxMetadata/int(unsafe.Sizeof(native.OutputField{})))
	hops := make([]native.Hop, maxMetadata/int(unsafe.Sizeof(native.Hop{})))
	for {
		var native native.Event
		err := nativeWaitEvent(&native, fields, hops, arena, data)
		headerDelivered := err == nil && (native.Kind == 6 || native.Kind == 7)
		var event completion
		if err == nil {
			event, err = eventCompletion(native, fields, hops, arena, data)
		}
		if err != nil {
			if headerDelivered {
				// Projection failed before this invocation reached its calling goroutine.
				if native.Kind == 6 {
					_ = replyHeaderCall(native.Operation, native.Part, 2, nil)
				} else {
					_ = replyRedirectCall(native.Operation, native.Part, 2, 0)
				}
			}
			pump.mu.Lock()
			pump.failure = err
			pending := pump.pending
			pump.pending = make(map[uint64]chan completion)
			cancels := pump.headerCancels
			pump.headerCancels = nil
			pump.mu.Unlock()
			for id, channel := range pending {
				if cancel := cancels[id]; cancel != nil {
					cancel()
				}
				_ = control("cancel", "operation", id)
				channel <- completion{Error: &Error{Kind: "native_abi", cause: err}}
			}
			return
		}
		pump.mu.Lock()
		channel := pump.pending[event.Operation]
		var cancel context.CancelFunc
		if event.kind != 6 && event.kind != 7 {
			delete(pump.pending, event.Operation)
			cancel = pump.headerCancels[event.Operation]
			delete(pump.headerCancels, event.Operation)
		}
		pump.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if channel != nil {
			channel <- event
			if event.kind == 1 || event.kind == 4 {
				// Upload producers need acknowledgements and part demand to continue.
				runtime.Gosched()
			}
		} else {
			if event.header != nil {
				// No caller can take custody of an unregistered invocation.
				_ = replyHeaderCall(event.Operation, event.header.ticket, 2, nil)
			}
			if event.redirect != nil {
				_ = replyRedirectCall(event.Operation, event.redirect.ticket, 2, 0)
			}
			_ = control("cancel", "operation", event.Operation)
		}
	}
}

func perform(ctx context.Context, command any, data []byte, accept func(completion) error) error {
	return performStarted(ctx, command, data, nil, accept)
}

// started runs outside the pump lock, after native admission and registration.
func performStarted(ctx context.Context, command any, data []byte, started func(), accept func(completion) error) error {
	return performSubmitted(ctx, func() (uint64, error) {
		value, err := dispatch(command, data)
		if err != nil {
			return 0, err
		}
		var submitted struct {
			Operation uint64 `json:"operation"`
		}
		if json.Unmarshal(value, &submitted) != nil || submitted.Operation == 0 {
			return 0, &Error{Kind: "native_abi"}
		}
		return submitted.Operation, nil
	}, started, accept)
}

func performSubmitted(ctx context.Context, submit func() (uint64, error), started func(), accept func(completion) error) error {
	return performSubmittedWithHooks(ctx, submit, started, accept, nil)
}

func performSubmittedWithHooks(ctx context.Context, submit func() (uint64, error), started func(), accept func(completion) error, hooks *requestHooks) error {
	if ctx == nil {
		return &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ensureNativeIdentity(); err != nil {
		return err
	}
	pump.once.Do(func() { pump.pending = make(map[uint64]chan completion); go completionPump() })
	// Register before the pump can dispatch a very fast completion.
	pump.mu.Lock()
	if err := ctx.Err(); err != nil {
		pump.mu.Unlock()
		return err
	}
	if pump.failure != nil {
		err := pump.failure
		pump.mu.Unlock()
		return err
	}
	operation, err := submit()
	if err != nil {
		pump.mu.Unlock()
		return err
	}
	if operation == 0 {
		pump.mu.Unlock()
		return &Error{Kind: "native_abi"}
	}
	capacity := 1
	if hooks != nil {
		capacity = 2
	}
	channel := make(chan completion, capacity)
	pump.pending[operation] = channel
	if hooks != nil {
		if pump.headerCancels == nil {
			pump.headerCancels = make(map[uint64]context.CancelFunc)
		}
		pump.headerCancels[operation] = hooks.cancel
	}
	pump.mu.Unlock()
	cancel := func() {
		if hooks != nil {
			hooks.cancel()
			cancelHeaderRequest(operation)
			return
		}
		pump.mu.Lock()
		delete(pump.pending, operation)
		pump.mu.Unlock()
		_ = control("cancel", "operation", operation)
	}
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	if hooks != nil {
		defer func() {
			pump.mu.Lock()
			delete(pump.pending, operation)
			delete(pump.headerCancels, operation)
			pump.mu.Unlock()
			// Also reclaim custody if user code panics before terminal acknowledgement.
			_ = control("cancel", "operation", operation)
		}()
	}
	if started != nil {
		started()
	}
	done := ctx.Done()
	var hookFailure error
	for {
		select {
		case <-done:
			cancel()
			if hooks == nil {
				return ctx.Err()
			}
			done = nil
		case event := <-channel:
			if event.kind == 6 || event.kind == 7 {
				if hooks == nil {
					cancel()
					return &Error{Kind: "native_abi"}
				}
				var err error
				if event.kind == 6 {
					err = hooks.invoke(operation, event.header)
				} else {
					err = hooks.invokeRedirect(operation, event.redirect)
				}
				if err != nil {
					hookFailure = err
					cancelHeaderRequest(operation)
				}
				continue
			}
			stop()
			if err := ctx.Err(); err != nil {
				if hooks != nil {
					_ = control("ack", "operation", operation)
				} else {
					cancel()
				}
				return err
			}
			if hookFailure != nil {
				_ = control("ack", "operation", operation)
				return hookFailure
			}
			if event.Error != nil {
				_ = control("ack", "operation", operation)
				return event.Error
			}
			if err := accept(event); err != nil {
				cancel()
				return err
			}
			if err := ctx.Err(); err != nil {
				cancel()
				return err
			}
			return control("ack", "operation", operation)
		}
	}
}
