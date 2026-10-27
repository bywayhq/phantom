package phantom

import (
	"context"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
)

// SSEEvent is one dispatched event. ID is the stream's persistent last-event ID;
// Type is message when no event field was supplied.
type SSEEvent struct{ Data, Type, ID string }

// SSELimits bound encoded bytes, excluding line endings. Explicit zero rejects
// nonempty lines or blocks. Lines may be at most 1 MiB, event blocks 8 MiB.
type SSELimits struct{ MaxLineBytes, MaxEventBytes int }

// EventResponse preserves the initial response metadata and owns its event
// stream. Read Events to EOF or close it. Non-200 responses are SSE errors.
type EventResponse struct {
	Status                 int
	Protocol               string
	Headers                []Header
	EffectiveURL           string
	RedirectsFollowed      uint64
	ConnectionSetupRetries uint64
	DecodedContentCodings  []string
	RedirectHistory        *RedirectHistory
	Events                 *EventStream
}

// Events sends an ordinary request and decodes its text/event-stream response
// using Rust. All Request options apply, including POST bodies and budgets.
// It never reconnects. Nil limits use 64 KiB lines and 1 MiB event blocks.
// The context controls setup and all later reads. Content-Encoding must be
// identity, including when generic response decoding was requested.
func (c *Client) Events(ctx context.Context, request Request, limits *SSELimits) (*EventResponse, error) {
	selected := SSELimits{MaxLineBytes: 64 * 1024, MaxEventBytes: 1024 * 1024}
	if limits != nil {
		selected = *limits
	}
	response, err := c.do(ctx, request, &selected)
	if err != nil {
		return nil, err
	}
	return &EventResponse{
		Status: response.Status, Protocol: response.Protocol, Headers: response.Headers,
		EffectiveURL: response.EffectiveURL, RedirectsFollowed: response.RedirectsFollowed,
		ConnectionSetupRetries: response.ConnectionSetupRetries,
		DecodedContentCodings:  response.DecodedContentCodings, RedirectHistory: response.RedirectHistory,
		Events: &EventStream{body: response.Body},
	}, nil
}

// EventStream pulls one event at a time without a background reader or queue.
// Next calls are serialized; Close may interrupt a pending Next.
type EventStream struct {
	body     *Body
	read     sync.Mutex
	finished atomic.Bool
	state    sync.Mutex
	lastID   string
	retry    uint64
	hasRetry bool
}

// Next returns the next complete event or io.EOF. An unterminated final event
// is discarded. A terminal error is returned once, then later calls return EOF.
// Cancelling the request context permanently closes this stream.
func (stream *EventStream) Next() (SSEEvent, error) {
	if stream == nil || stream.body == nil {
		return SSEEvent{}, &Error{Kind: "sse_closed"}
	}
	stream.read.Lock()
	defer stream.read.Unlock()
	if stream.finished.Load() {
		return SSEEvent{}, io.EOF
	}
	if err := stream.body.ctx.Err(); err != nil {
		stream.finish()
		return SSEEvent{}, stream.body.owner.upload.wrap(err)
	}
	if stream.body.owner.closed.Load() {
		stream.finished.Store(true)
		return SSEEvent{}, &Error{Kind: "sse_closed"}
	}
	var received receivedSSE
	var trailers ResponseTrailers
	err := performSubmitted(stream.body.ctx, func() (uint64, error) {
		var reply nativeReply
		if err := nativeSSENext(stream.body.owner.id, &reply); err != nil {
			return 0, err
		}
		return reply.Operation, reply.Error.err()
	}, nil, func(completion completion) error {
		if completion.kind != 1 && completion.kind != 3 {
			return &Error{Kind: "native_abi"}
		}
		value, err := readSSEEvent(completion.Operation)
		if err != nil {
			return err
		}
		if (completion.kind == 3) != (value.eof && value.err == nil) {
			return &Error{Kind: "native_abi"}
		}
		trailers = completion.trailers
		received = value
		return nil
	})
	runtime.KeepAlive(stream)
	if err != nil {
		if failure := trailerProjectionError(err); failure != nil {
			stream.body.owner.trailers.settle(ResponseTrailers{State: TrailersUnavailable}, failure)
		}
		stream.finish()
		return SSEEvent{}, stream.body.owner.upload.wrap(err)
	}
	stream.state.Lock()
	stream.lastID, stream.retry, stream.hasRetry = received.event.ID, received.retry, received.hasRetry
	stream.state.Unlock()
	if received.err != nil {
		stream.finish()
		return SSEEvent{}, stream.body.owner.upload.wrap(received.err)
	}
	if received.eof {
		stream.body.owner.trailers.settle(trailers, nil)
		stream.finished.Store(true)
		if err := stream.body.Close(); err != nil {
			return SSEEvent{}, err
		}
		return SSEEvent{}, io.EOF
	}
	return received.event, nil
}

// Trailers returns a non-draining snapshot. They become complete only after
// Next observes validated EOF; closing or failing earlier makes them unavailable.
func (stream *EventStream) Trailers() (ResponseTrailers, error) {
	if stream == nil || stream.body == nil {
		return ResponseTrailers{State: TrailersUnavailable}, nil
	}
	return stream.body.Trailers()
}

// LastEventID returns the committed ID after the latest completed Next, including
// ID-only blocks consumed before EOF or an error. An empty ID resets the state.
func (stream *EventStream) LastEventID() string {
	if stream == nil {
		return ""
	}
	stream.state.Lock()
	defer stream.state.Unlock()
	return stream.lastID
}

// RetryMilliseconds returns the latest valid retry field. The boolean is false
// until one is received. Milliseconds preserve delays beyond time.Duration's
// range. This one-response stream does not schedule reconnections.
func (stream *EventStream) RetryMilliseconds() (uint64, bool) {
	if stream == nil {
		return 0, false
	}
	stream.state.Lock()
	defer stream.state.Unlock()
	return stream.retry, stream.hasRetry
}

func (stream *EventStream) finish() {
	stream.finished.Store(true)
	// The read error remains primary; Close also releases an upload producer.
	_ = stream.body.Close()
}

// Close permanently cancels this stream and its upload, preserving other HTTP/2
// and HTTP/3 streams. Close does not wait for a pending Next to return.
func (stream *EventStream) Close() error {
	if stream == nil || stream.body == nil {
		return nil
	}
	return stream.body.Close()
}

func validateSSELimits(value SSELimits) error {
	if value.MaxLineBytes < 0 || value.MaxLineBytes > 1024*1024 || value.MaxEventBytes < 0 || value.MaxEventBytes > 8*1024*1024 {
		return &Error{Kind: "invalid_sse_limits"}
	}
	return nil
}
