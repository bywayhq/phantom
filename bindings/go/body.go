package phantom

import (
	"context"
	"errors"
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
	// EffectiveURL is the absolute URL that produced this response.
	EffectiveURL string
	// RedirectsFollowed counts redirects before this response.
	RedirectsFollowed uint64
	// ConnectionSetupRetries counts caller-enabled connection-setup retries
	// across redirect hops, counted when setup starts. It excludes redirects,
	// status retries, reused-connection and GOAWAY replays, proxy authentication,
	// client hints and protocol fallback.
	ConnectionSetupRetries uint64
	// DecodedContentCodings records the applied chain in header order: gzip,
	// deflate, br or zstd.
	DecodedContentCodings []string
	// RedirectHistory is nil unless requested. An enabled zero-hop response has
	// a non-nil history with no entries. No history is returned on request errors.
	RedirectHistory *RedirectHistory
}
type bodyLifetime struct {
	id       uint64
	closed   atomic.Bool
	upload   *uploadLifetime
	trailers responseTrailersCache
}

func (owner *bodyLifetime) close() error {
	owner.trailers.settle(ResponseTrailers{State: TrailersUnavailable}, nil)
	if owner.closed.Swap(true) {
		return owner.upload.wrap(owner.upload.close())
	}
	err := control("close_body", "body", owner.id)
	return owner.upload.wrap(errors.Join(err, owner.upload.close()))
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

func newBody(ctx context.Context, client *Client, id uint64, upload *uploadLifetime) *Body {
	owner := &bodyLifetime{id: id, upload: upload}
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
		return 0, body.owner.upload.wrap(err)
	}
	if body.owner.closed.Load() {
		return 0, body.owner.upload.wrap(&Error{Kind: "body_closed"})
	}
	maximum := min(len(output), maxChunk)
	var bytes []byte
	eof := false
	var trailers ResponseTrailers
	err := performSubmitted(body.ctx, func() (uint64, error) { return submitOperation(1, body.owner.id, uint64(maximum), nil) }, nil, func(event completion) error {
		if event.kind != 2 && event.kind != 3 {
			return &Error{Kind: "native_abi"}
		}
		eof = event.eof
		trailers = event.trailers
		bytes = event.data
		return nil
	})
	runtime.KeepAlive(body)
	if err != nil {
		if kind := trailerProjectionError(err); kind != nil {
			body.owner.trailers.settle(ResponseTrailers{State: TrailersUnavailable}, kind)
		}
		_ = body.Close()
		return 0, body.owner.upload.wrap(err)
	}
	if eof {
		// Publish only after perform's context and acknowledgement checks succeed.
		body.owner.trailers.settle(trailers, nil)
		body.eof.Store(true)
		if err := body.Close(); err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	return copy(output, bytes), nil
}

// ReadAll collects at most maximum bytes and closes the body in all cases.
func (body *Body) ReadAll(maximum int) (result []byte, err error) {
	defer func() {
		closeErr := body.Close()
		if err != nil {
			err = body.owner.upload.wrap(err)
		} else if closeErr != nil {
			result, err = nil, closeErr
		}
	}()
	if maximum < 0 {
		return nil, &Error{Kind: "invalid_body_limit"}
	}
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
