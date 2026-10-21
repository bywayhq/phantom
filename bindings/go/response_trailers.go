package phantom

import (
	"encoding/json"
	"errors"
	"runtime"
	"sync"
)

// ResponseTrailersState distinguishes unread, unavailable and validated trailers.
type ResponseTrailersState string

const (
	TrailersPending     ResponseTrailersState = "pending"
	TrailersUnavailable ResponseTrailersState = "unavailable"
	TrailersComplete    ResponseTrailersState = "complete"
)

// ResponseTrailers is an owned snapshot. Complete includes an empty header list
// when validated EOF had no trailers. Headers preserve received order, duplicate
// names and raw values; Sensitive retains an observed compression marker.
type ResponseTrailers struct {
	State   ResponseTrailersState
	Headers []Header
}

// Trailers returns a non-draining snapshot of the body. Completion is published
// only after Read observes validated EOF, including content decoding and proxy
// authentication. Close or a body failure before EOF makes it unavailable.
// Metadata exceeding the native 256 KiB JSON reply limit returns metadata_limit.
// Each call owns its header values and is safe concurrently with Read or Close.
func (response *Response) Trailers() (ResponseTrailers, error) {
	return response.Body.Trailers()
}

// Trailers returns the same snapshot as Response.Trailers, including after Close.
func (body *Body) Trailers() (ResponseTrailers, error) {
	if body.ctx.Err() != nil || body.owner.closed.Load() || body.client.id.Load() == 0 {
		body.owner.trailers.settle(ResponseTrailers{State: TrailersUnavailable}, nil)
	}
	result, err := body.owner.trailers.snapshot()
	runtime.KeepAlive(body)
	return result, err
}

type responseTrailersCache struct {
	mu     sync.Mutex
	result ResponseTrailers
	err    error
}

func (cache *responseTrailersCache) settle(result ResponseTrailers, err error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.result.State == "" {
		cache.result, cache.err = result, err
	}
}

func (cache *responseTrailersCache) snapshot() (ResponseTrailers, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.result.State == "" {
		return ResponseTrailers{State: TrailersPending}, nil
	}
	result := ResponseTrailers{State: cache.result.State}
	if cache.result.Headers != nil {
		result.Headers = make([]Header, len(cache.result.Headers))
		for index, header := range cache.result.Headers {
			header.Value = append([]byte(nil), header.Value...)
			result.Headers[index] = header
		}
	}
	return result, cache.err
}

func decodeResponseTrailers(data json.RawMessage) (ResponseTrailers, error) {
	var result struct {
		State   ResponseTrailersState `json:"state"`
		Headers []Header              `json:"headers"`
	}
	if json.Unmarshal(data, &result) != nil || result.State == "" {
		return ResponseTrailers{State: TrailersUnavailable}, &Error{Kind: "native_abi"}
	}
	switch result.State {
	case TrailersComplete:
		if result.Headers == nil {
			return ResponseTrailers{State: TrailersUnavailable}, &Error{Kind: "native_abi"}
		}
		return ResponseTrailers{State: result.State, Headers: result.Headers}, nil
	case TrailersUnavailable:
		if len(result.Headers) == 0 {
			return ResponseTrailers{State: result.State}, nil
		}
		return ResponseTrailers{State: TrailersUnavailable}, &Error{Kind: "native_abi"}
	default:
		return ResponseTrailers{State: TrailersUnavailable}, &Error{Kind: "unsupported_response_trailers"}
	}
}

func trailerProjectionError(err error) error {
	var failure *Error
	if errors.As(err, &failure) && (failure.Kind == "metadata_limit" || failure.Kind == "unsupported_response_trailers" || failure.Kind == "native_abi") {
		return failure
	}
	return nil
}
