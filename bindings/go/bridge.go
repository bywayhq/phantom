package phantom

import (
	"context"
	"encoding/json"
	"sync"
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
}

func (e *Error) Error() string { return "phantom: " + e.Kind }
func (e *Error) Timeout() bool { return e.Kind == "timeout" }

type reply struct {
	Value json.RawMessage `json:"value"`
	Error *Error          `json:"error"`
}
type completion struct {
	Operation  uint64          `json:"operation"`
	Value      json.RawMessage `json:"value"`
	Error      *Error          `json:"error"`
	DataLength int             `json:"data_length"`
	data       []byte
}

var scratch = sync.Pool{New: func() any { return make([]byte, maxMetadata) }}

func dispatch(command any, data []byte) (json.RawMessage, error) {
	input, err := json.Marshal(command)
	if err != nil || len(input) > 64*1024 || len(data) > maxUpload {
		return nil, &Error{Kind: "input_limit"}
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
	metadata := make([]byte, maxMetadata)
	data := make([]byte, maxChunk)
	for {
		length, err := nativeWait(metadata, data)
		var event completion
		if err == nil && (length <= 0 || length > len(metadata) || json.Unmarshal(metadata[:length], &event) != nil || event.DataLength < 0 || event.DataLength > len(data)) {
			err = &Error{Kind: "native_abi"}
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
		if event.DataLength != 0 {
			event.data = append([]byte(nil), data[:event.DataLength]...)
		}
		pump.mu.Lock()
		channel := pump.pending[event.Operation]
		delete(pump.pending, event.Operation)
		pump.mu.Unlock()
		if channel != nil {
			channel <- event
		} else {
			_ = control("cancel", "operation", event.Operation)
		}
	}
}

func perform(ctx context.Context, command any, data []byte, accept func(completion) error) error {
	if ctx == nil {
		return &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
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
	value, err := dispatch(command, data)
	if err != nil {
		pump.mu.Unlock()
		return err
	}
	var submitted struct {
		Operation uint64 `json:"operation"`
	}
	if json.Unmarshal(value, &submitted) != nil || submitted.Operation == 0 {
		pump.mu.Unlock()
		return &Error{Kind: "native_abi"}
	}
	channel := make(chan completion, 1)
	pump.pending[submitted.Operation] = channel
	pump.mu.Unlock()
	cancel := func() {
		pump.mu.Lock()
		delete(pump.pending, submitted.Operation)
		pump.mu.Unlock()
		_ = control("cancel", "operation", submitted.Operation)
	}
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
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
			_ = control("ack", "operation", submitted.Operation)
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
		return control("ack", "operation", submitted.Operation)
	}
}
