package phantom

import (
	"context"
	"io"
	"runtime"
	"time"
	"unsafe"
)

// Request holds one logical request. Body is replayable and limited to 8 MiB.
type Request struct {
	Method  string
	URL     string
	Headers []Header
	// Context selects this request's catalog template: navigation, fetch,
	// fetchNoStore, fetchUpload, script, stylesheet, image or font.
	// Empty inherits the client default; raw sends without a template.
	Context string
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
func (c *Client) Do(ctx context.Context, request Request) (*Response, error) {
	return c.do(ctx, request, nil)
}

func (c *Client) do(ctx context.Context, request Request, events *SSELimits) (response *Response, err error) {
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
	if events != nil {
		if err := validateSSELimits(*events); err != nil {
			return nil, err
		}
		if err := loadSSE(); err != nil {
			return nil, err
		}
	}
	contextFlags, err := requestContextFlags(request.Context)
	if err != nil {
		return nil, err
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
	// Snapshot pointer-selected policies before native admission.
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
		snapshot, err := redirectPolicyWire(*request.RedirectPolicy)
		if err != nil {
			return nil, err
		}
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
	if len(request.Trailers) > 256 || len(request.Headers) > 256-len(request.Trailers) {
		return nil, &Error{Kind: "input_limit"}
	}
	size := len(request.URL) + len(request.Method)
	if size > 64*1024 {
		return nil, &Error{Kind: "input_limit"}
	}
	encodeHeaders := func(input []Header) ([]nativeField, error) {
		fields := make([]nativeField, 0, len(input))
		for _, header := range input {
			if len(header.Name) > 64*1024-size || len(header.Value) > 64*1024-size-len(header.Name) {
				return nil, &Error{Kind: "input_limit"}
			}
			size += len(header.Name) + len(header.Value)
			fields = append(fields, nativeField{borrowedString(header.Name), borrowedBytes(header.Value), boolean(header.Sensitive)})
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
	native := nativeRequest{
		Client: c.id.Load(), Method: borrowedString(request.Method), URL: borrowedString(request.URL),
		Headers: unsafe.Pointer(unsafe.SliceData(headers)), HeaderCount: uint64(len(headers)),
		Trailers: unsafe.Pointer(unsafe.SliceData(trailers)), TrailerCount: uint64(len(trailers)),
		Flags: boolean(request.Body != nil) | contextFlags, Budget: pointed(budget), Transfer: pointed(transfer), PreparedBody: pointed(prepared),
	}
	for i, value := range []wireTimeout{timeouts.PoolAdmission, timeouts.Connect, timeouts.ResponseHead, timeouts.ReadIdle, timeouts.Total} {
		mode := uint64(0)
		switch value.Mode {
		case "disabled":
			mode = 1
		case "limit":
			mode = 2
		}
		native.Timeouts[i] = nativeTimeout{Mode: mode, Nanoseconds: pointed(value.Nanoseconds)}
	}
	if expectContinue != nil {
		native.Flags |= 2
		native.ExpectContinue = *expectContinue
	}
	if decoding.Mode == "advertised" {
		native.Flags |= 4
		native.DecodedMaximum = pointed(decoding.MaximumDecodedBytes)
	}
	var credentials []nativeSpan
	if redirects != nil {
		native.Flags |= 8
		native.RedirectMaximum = redirects.MaximumHops
		for _, name := range redirects.CredentialHeaders {
			credentials = append(credentials, borrowedString(name))
		}
		native.CredentialHeaders = unsafe.Pointer(unsafe.SliceData(credentials))
		native.CredentialHeaderCount = uint64(len(credentials))
	}
	if history != nil {
		native.Flags |= 16
		native.RedirectHistory = *history
	}
	var statuses []uint16
	if retries != nil {
		native.Retry, statuses = nativeRetryValue(*retries)
	}
	if request.Diagnostics != nil {
		native.Diagnostics = request.Diagnostics.id.Load()
		if native.Diagnostics == 0 {
			return nil, &Error{Kind: "invalid_handle"}
		}
	}
	if upload != nil {
		if err := upload.prepare(ctx, c.id.Load()); err != nil {
			return nil, err
		}
		native.Upload = upload.id
	}
	err = performSubmitted(ctx, func() (uint64, error) {
		var result nativeReply
		var err error
		if events == nil {
			err = nativeSubmit(&native, request.Body, &result)
		} else {
			err = nativeSSESubmit(&native, request.Body, *events, &result)
		}
		runtime.KeepAlive(headers)
		runtime.KeepAlive(trailers)
		runtime.KeepAlive(credentials)
		runtime.KeepAlive(statuses)
		runtime.KeepAlive(request)
		runtime.KeepAlive(redirects)
		runtime.KeepAlive(retries)
		if err != nil {
			return 0, err
		}
		return result.Operation, result.Error.err()
	}, upload.start, func(event completion) error {
		head := event.head
		if head == nil {
			return &Error{Kind: "native_abi"}
		}
		response = &Response{
			Status: head.Status, Protocol: head.Protocol, Headers: head.Headers,
			Body: newBody(ctx, c, head.Body, upload), EffectiveURL: head.EffectiveURL,
			RedirectsFollowed: head.RedirectsFollowed, ConnectionSetupRetries: head.ConnectionSetupRetries,
			DecodedContentCodings: head.DecodedContentCodings, RedirectHistory: head.RedirectHistory,
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
