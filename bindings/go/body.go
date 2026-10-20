package phantom

import (
	"context"
	"encoding/json"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
)

// Response preserves ordered headers. Non-success statuses are ordinary responses.
type Response struct {
	Status   int
	Protocol string
	Headers  []Header
	Body     *Body
}
type bodyLifetime struct {
	id     uint64
	closed atomic.Bool
}

func (owner *bodyLifetime) close() error {
	if owner.closed.Swap(true) {
		return nil
	}
	return control("close_body", "body", owner.id)
}

// Body implements io.ReadCloser. Reads are serialized; Close can interrupt a read.
type Body struct {
	owner  *bodyLifetime
	client *Client
	ctx    context.Context
	stop   func() bool
	read   sync.Mutex
	eof    atomic.Bool
}

func newBody(ctx context.Context, client *Client, id uint64) *Body {
	owner := &bodyLifetime{id: id}
	body := &Body{owner: owner, client: client, ctx: ctx}
	// The callback retains only the native lifetime, not Body, so collection can
	// release an abandoned body even while a cancellable request context survives.
	body.stop = context.AfterFunc(ctx, func() { _ = owner.close() })
	runtime.SetFinalizer(body, func(value *Body) { _ = value.Close() })
	return body
}

// Read pulls at most 64 KiB; there is no background collector.
func (body *Body) Read(output []byte) (int, error) {
	if len(output) == 0 {
		return 0, nil
	}
	body.read.Lock()
	defer body.read.Unlock()
	if body.eof.Load() {
		return 0, io.EOF
	}
	if err := body.ctx.Err(); err != nil {
		_ = body.Close()
		return 0, err
	}
	if body.owner.closed.Load() {
		return 0, &Error{Kind: "body_closed"}
	}
	maximum := min(len(output), maxChunk)
	var bytes []byte
	eof := false
	err := perform(body.ctx, map[string]any{"kind": "read", "body": body.owner.id, "maximum": maximum}, nil, func(event completion) error {
		var result struct {
			EOF bool `json:"eof"`
		}
		if json.Unmarshal(event.Value, &result) != nil {
			return &Error{Kind: "native_abi"}
		}
		eof = result.EOF
		bytes = event.data
		return nil
	})
	runtime.KeepAlive(body)
	if err != nil {
		_ = body.Close()
		return 0, err
	}
	if eof {
		body.eof.Store(true)
		_ = body.Close()
		return 0, io.EOF
	}
	return copy(output, bytes), nil
}

// ReadAll collects at most maximum bytes and closes the body in all cases.
func (body *Body) ReadAll(maximum int) ([]byte, error) {
	defer body.Close()
	if maximum < 0 {
		return nil, &Error{Kind: "invalid_body_limit"}
	}
	var result []byte
	buffer := make([]byte, maxChunk)
	for {
		size := min(len(buffer), maximum-len(result))
		if size == 0 {
			size = 1
		}
		length, err := body.Read(buffer[:size])
		if length > maximum-len(result) {
			return nil, &Error{Kind: "response_body_limit"}
		}
		result = append(result, buffer[:length]...)
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// Close permanently cancels an incomplete body without closing other streams.
func (body *Body) Close() error {
	body.stop()
	runtime.SetFinalizer(body, nil)
	err := body.owner.close()
	runtime.KeepAlive(body.client)
	return err
}
