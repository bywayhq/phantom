package phantom

import (
	"context"
	"encoding/json"
	"io"
	"runtime"
	"time"
)

// Request holds one logical request. Body is replayable and limited to 8 MiB.
type Request struct {
	Method  string
	URL     string
	Headers []Header
	// Trailers are emitted after the body, in order. HTTP/1 uses chunked coding;
	// HTTP/2 and HTTP/3 require lowercase names. Invalid framing fails before I/O.
	Trailers []Header
	// ExpectContinue waits after sending the head for 100 Continue before sending
	// body data. Nil disables it; zero sends without waiting. Core deadlines apply.
	ExpectContinue *time.Duration
	Body           []byte
	// PreparedBody sends a reusable native form or multipart encoding. It cannot
	// be combined with Body, Upload or UploadLength. Content-Type placement is explicit.
	PreparedBody *PreparedBody
	// Multipart streams ordered fields using core framing and one reader at a
	// time. It cannot be combined with Body, Upload, UploadLength or PreparedBody.
	Multipart *StreamingMultipart
	// Upload transfers a one-shot source to Do, which closes it exactly once,
	// including on validation failure. Read may run concurrently with Close;
	// Close must unblock Read. It cannot be combined with Body.
	Upload io.ReadCloser
	// UploadLength is nil for unknown length, or an exact byte count (including
	// zero). Checks bytes read and observed EOF; unread suffixes are not validated.
	// Streaming uploads have bounded buffering, without Body's 8 MiB size cap.
	UploadLength *uint64
	Budget       *AttemptBudget
	// TransferControl shares body-byte caps, pacing and counters. Nil disables it.
	TransferControl *TransferControl
	// Diagnostics observes one logical request, including redirects and replays.
	// The owner is single-use and remains readable after send failure/cancellation.
	Diagnostics *RequestDiagnostics
	Timeout     time.Duration
	Timeouts    Timeouts
	// ContentDecoding is opt-in and uses the request's own Accept-Encoding fields.
	ContentDecoding ContentDecoding
	// RedirectPolicy replaces the client policy. Nil inherits; an empty value disables.
	RedirectPolicy *RedirectPolicy
	// RetryPolicy replaces the client policy. Nil inherits; an empty value disables.
	RetryPolicy *RetryPolicy
	// RedirectHistoryLimit opts into first-N selected hops. Nil disables; zero is invalid.
	RedirectHistoryLimit *uint64
}

// Do returns the response head and an owned pull-driven body. Keep ctx valid until
// EOF or Body.Close; cancelling it also closes a body already returned to you.
func (c *Client) Do(ctx context.Context, request Request) (response *Response, err error) {
	var upload *uploadLifetime
	if request.Upload != nil {
		upload = &uploadLifetime{source: request.Upload}
		if request.UploadLength != nil {
			length := *request.UploadLength
			upload.length = &length
		}
	}
	if request.Multipart != nil {
		multipart := multipartUpload(request.Multipart)
		if upload == nil {
			upload = multipart
		} else {
			upload.multipart = multipart.multipart
		}
	}
	transferred := false
	defer func() {
		if !transferred {
			_ = upload.close()
			if upload != nil && upload.multipart != nil && err != nil {
				err = upload.wrap(err)
			}
		}
	}()
	if multipartConflict(request) {
		return nil, &Error{Kind: "invalid_multipart"}
	}
	if (request.Upload != nil && request.Body != nil) || (request.Upload == nil && request.UploadLength != nil) {
		return nil, &Error{Kind: "invalid_upload"}
	}
	var prepared *uint64
	if request.PreparedBody != nil {
		if request.Body != nil || request.Upload != nil || request.UploadLength != nil {
			return nil, &Error{Kind: "invalid_prepared_body"}
		}
		id := request.PreparedBody.id.Load()
		if id == 0 {
			return nil, &Error{Kind: "invalid_handle"}
		}
		prepared = &id
	}
	if ctx == nil {
		return nil, &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.closing.Load() || c.id.Load() == 0 {
		return nil, &Error{Kind: "client_closed"}
	}
	if len(request.Body) > maxUpload {
		return nil, &Error{Kind: "upload_limit"}
	}
	var expectContinue *uint64
	if request.ExpectContinue != nil {
		wait := *request.ExpectContinue
		if wait < 0 {
			return nil, &Error{Kind: "invalid_expect_continue"}
		}
		nanoseconds := uint64(wait)
		expectContinue = &nanoseconds
	}
	timeouts, err := timeoutsWire(request.Timeouts, request.Timeout)
	if err != nil {
		return nil, err
	}
	decoding, err := contentDecodingWire(request.ContentDecoding)
	if err != nil {
		return nil, err
	}
	// Copy pointer-selected policies before submission; asynchronous work owns only JSON bytes.
	var retries *wireRetryPolicy
	if request.RetryPolicy != nil {
		snapshot, err := retryPolicyWire(*request.RetryPolicy)
		if err != nil {
			return nil, err
		}
		retries = &snapshot
	}
	var redirects *RedirectPolicy
	if request.RedirectPolicy != nil {
		snapshot := *request.RedirectPolicy
		redirects = &snapshot
	}
	var history *uint64
	if request.RedirectHistoryLimit != nil {
		snapshot := *request.RedirectHistoryLimit
		if snapshot == 0 {
			return nil, &Error{Kind: "invalid_redirect_history"}
		}
		history = &snapshot
	}
	type wireHeader struct {
		Name      string   `json:"name"`
		Value     []uint16 `json:"value"`
		Sensitive bool     `json:"sensitive"`
	}
	if len(request.Trailers) > 256 || len(request.Headers) > 256-len(request.Trailers) {
		return nil, &Error{Kind: "input_limit"}
	}
	size := len(request.URL) + len(request.Method)
	if size > 64*1024 {
		return nil, &Error{Kind: "input_limit"}
	}
	encodeHeaders := func(input []Header) ([]wireHeader, error) {
		fields := make([]wireHeader, 0, len(input))
		for _, header := range input {
			if len(header.Name) > 64*1024-size || len(header.Value) > 64*1024-size-len(header.Name) {
				return nil, &Error{Kind: "input_limit"}
			}
			size += len(header.Name) + len(header.Value)
			values := make([]uint16, len(header.Value))
			for i, value := range header.Value {
				values[i] = uint16(value)
			}
			fields = append(fields, wireHeader{header.Name, values, header.Sensitive})
		}
		return fields, nil
	}
	headers, err := encodeHeaders(request.Headers)
	if err != nil {
		return nil, err
	}
	trailers, err := encodeHeaders(request.Trailers)
	if err != nil {
		return nil, err
	}
	var budget *uint64
	if request.Budget != nil {
		value := request.Budget.id.Load()
		if value == 0 {
			return nil, &Error{Kind: "invalid_handle"}
		}
		budget = &value
	}
	var transfer *uint64
	if request.TransferControl != nil {
		value := request.TransferControl.id.Load()
		if value == 0 {
			return nil, &Error{Kind: "invalid_handle"}
		}
		transfer = &value
	}
	command := map[string]any{"kind": "request", "client": c.id.Load(), "method": request.Method, "url": request.URL, "headers": headers, "budget": budget, "timeouts": timeouts, "has_body": request.Body != nil, "content_decoding": decoding, "redirect_policy": redirects, "redirect_history_limit": history, "retry_policy": retries}
	if len(trailers) != 0 {
		command["trailers"] = trailers
	}
	if expectContinue != nil {
		command["expect_continue_nanoseconds"] = expectContinue
	}
	if transfer != nil {
		command["transfer"] = transfer
	}
	if request.Diagnostics != nil {
		value := request.Diagnostics.id.Load()
		if value == 0 {
			return nil, &Error{Kind: "invalid_handle"}
		}
		command["diagnostics"] = value
	}
	if prepared != nil {
		command["prepared_body"] = prepared
	}
	if upload != nil {
		if err := upload.prepare(ctx, c.id.Load()); err != nil {
			return nil, err
		}
		command["upload"] = upload.id
	}
	err = performStarted(ctx, command, request.Body, upload.start, func(event completion) error {
		var head struct {
			Body                   uint64           `json:"body"`
			Status                 int              `json:"status"`
			Protocol               string           `json:"protocol"`
			Headers                []Header         `json:"headers"`
			EffectiveURL           string           `json:"effective_url"`
			RedirectsFollowed      uint64           `json:"redirects_followed"`
			ConnectionSetupRetries uint64           `json:"connection_setup_retries"`
			DecodedContentCodings  []string         `json:"decoded_content_codings"`
			RedirectHistory        *RedirectHistory `json:"redirect_history"`
		}
		if json.Unmarshal(event.Value, &head) != nil || head.Body == 0 || head.EffectiveURL == "" {
			return &Error{Kind: "native_abi"}
		}
		response = &Response{
			Status: head.Status, Protocol: head.Protocol, Headers: head.Headers,
			Body: newBody(ctx, c, head.Body, upload), EffectiveURL: head.EffectiveURL,
			RedirectsFollowed: head.RedirectsFollowed, ConnectionSetupRetries: head.ConnectionSetupRetries,
			DecodedContentCodings: head.DecodedContentCodings,
			RedirectHistory:       head.RedirectHistory,
		}
		return nil
	})
	runtime.KeepAlive(request.Budget)
	runtime.KeepAlive(request.TransferControl)
	runtime.KeepAlive(request.Diagnostics)
	runtime.KeepAlive(request.PreparedBody)
	runtime.KeepAlive(c)
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		upload.close()
		return nil, upload.wrap(err)
	}
	transferred = true
	return response, nil
}
