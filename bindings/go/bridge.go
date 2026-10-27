package phantom

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"unsafe"
)

const maxMetadata = 256 * 1024
const maxChunk = 64 * 1024
const maxUpload = 8 * 1024 * 1024

// Error is a redacted native failure. HTTP statuses remain responses.
type Error struct {
	Kind         string `json:"kind"`
	Protocol     string `json:"protocol"`
	TimeoutPhase string `json:"timeout_phase"`
	// Field is the canonical setting path for a profile import/export error.
	Field string `json:"field"`
	cause error
}

func (e *Error) Error() string { return "phantom: " + e.Kind }
func (e *Error) Timeout() bool { return e.Kind == "timeout" }
func (e *Error) Unwrap() error { return e.cause }

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
	once    sync.Once
	mu      sync.Mutex
	pending map[uint64]chan completion
	failure error
}

func completionPump() {
	arena := make([]byte, maxMetadata)
	data := make([]byte, maxChunk)
	fields := make([]nativeOutputField, maxMetadata/int(unsafe.Sizeof(nativeOutputField{})))
	hops := make([]nativeHop, maxMetadata/int(unsafe.Sizeof(nativeHop{})))
	for {
		var native nativeEvent
		err := nativeWaitEvent(&native, fields, hops, arena, data)
		var event completion
		if err == nil {
			event, err = eventCompletion(native, fields, hops, arena, data)
		}
		if err != nil {
			pump.mu.Lock()
			pump.failure = err
			pending := pump.pending
			pump.pending = make(map[uint64]chan completion)
			pump.mu.Unlock()
			for id, channel := range pending {
				_ = control("cancel", "operation", id)
				channel <- completion{Error: &Error{Kind: "native_abi"}}
			}
			return
		}
		pump.mu.Lock()
		channel := pump.pending[event.Operation]
		delete(pump.pending, event.Operation)
		pump.mu.Unlock()
		if channel != nil {
			channel <- event
			if event.kind == 1 || event.kind == 4 {
				// Upload producers need acknowledgements and part demand to continue.
				runtime.Gosched()
			}
		} else {
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
	channel := make(chan completion, 1)
	pump.pending[operation] = channel
	pump.mu.Unlock()
	cancel := func() {
		pump.mu.Lock()
		delete(pump.pending, operation)
		pump.mu.Unlock()
		_ = control("cancel", "operation", operation)
	}
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	if started != nil {
		started()
	}
	select {
	case <-ctx.Done():
		cancel()
		return ctx.Err()
	case event := <-channel:
		stop()
		if err := ctx.Err(); err != nil {
			cancel()
			return err
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
