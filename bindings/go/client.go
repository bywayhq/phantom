// Package phantom provides native requests with explicit profiles and protocols.
package phantom

import (
	"context"
	"encoding/json"
	"io"
	"runtime"
	"sync/atomic"
	"time"
)

// Config selects one named or caller-owned profile and an explicit protocol.
// Context is raw/empty, profile, or an available named catalog context.
type Config struct {
	Profile string
	// ProfileSettings selects immutable settings instead of Profile. Supply exactly one.
	ProfileSettings *Profile
	Protocol        string
	Context         string
	Proxy           string
	// ProxyCredentials configures HTTP Basic or SOCKS5 username/password auth.
	// It requires an explicit corresponding Proxy URL; URI credentials are rejected.
	ProxyCredentials *ProxyCredentials
	// BaseURL resolves relative request URLs using the Rust client's URL rules.
	BaseURL string
	// Network optionally selects host overrides and outgoing socket bindings.
	Network *NetworkOptions
	// AdditionalRootsDER extends origin trust. ProxyAdditionalRootsDER extends
	// HTTPS-proxy trust separately. Certificates must be DER encoded.
	AdditionalRootsDER      [][]byte
	ProxyAdditionalRootsDER [][]byte
	// ServerSPKIPins accepts any of 1..32 SHA-256 leaf DER SubjectPublicKeyInfo
	// digests, in addition to normal certificate and hostname verification.
	// Nil disables pinning; a non-nil empty slice is invalid. Cleartext origins fail.
	ServerSPKIPins [][32]byte
	// ProxyServerSPKIPins applies the same policy to HTTPS-proxy TLS separately.
	// Direct routes remain usable; plaintext proxy routes fail before I/O.
	ProxyServerSPKIPins [][32]byte
	// ClientCertificate is the default parsed origin identity. Ordered overrides
	// are limited to 256 mappings and share the existing 64 KiB config command.
	ClientCertificate     *ClientCertificate
	ClientCertificatesFor []ClientCertificateOrigin
	DisableCookies        bool
	// Timeout retains the original total timeout. Do not combine it with Timeouts.Total.
	Timeout  time.Duration
	Timeouts Timeouts
	// RedirectPolicy applies to requests that do not override it. Zero follows none.
	RedirectPolicy RedirectPolicy
	// RetryPolicy enables caller retry classes. Zero enables none.
	RetryPolicy RetryPolicy
}

// ProxyCredentials is one explicit username/password pair. Empty values are
// passed to the Rust route validator. Formatting omits both credentials.
type ProxyCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (ProxyCredentials) String() string   { return "[redacted]" }
func (ProxyCredentials) GoString() string { return "[redacted]" }

// Header retains one field's position, name and byte value. Duplicate names work.
type Header struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
	// Sensitive requests never-indexed H2/H3 encoding, subject to the profile's
	// cookie-crumb policy. On responses it reports the retained wire marker.
	// HTTP/1 field bytes are unchanged.
	Sensitive bool `json:"sensitive,omitempty"`
}

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

// Client reuses native connection pools and cookies. It is safe for concurrent use.
type Client struct {
	id      atomic.Uint64
	closing atomic.Bool
}

// New creates a client. It performs no request and ignores proxy environment variables.
func New(config Config) (*Client, error) {
	size, err := networkInputSize(config.Network)
	if err != nil {
		return nil, err
	}
	if (config.Profile == "") == (config.ProfileSettings == nil) {
		return nil, &Error{Kind: "invalid_profile_selection"}
	}
	var profileID *uint64
	if config.ProfileSettings != nil {
		id := config.ProfileSettings.id.Load()
		if id == 0 {
			return nil, &Error{Kind: "profile_closed"}
		}
		profileID = &id
	}
	defer runtime.KeepAlive(config.ProfileSettings)
	defer runtime.KeepAlive(config)
	certificate, certificateOrigins, err := certificatesWire(config)
	if err != nil {
		return nil, err
	}
	timeouts, err := timeoutsWire(config.Timeouts, config.Timeout)
	if err != nil {
		return nil, err
	}
	retries, err := retryPolicyWire(config.RetryPolicy)
	if err != nil {
		return nil, err
	}
	if config.ServerSPKIPins != nil && (len(config.ServerSPKIPins) == 0 || len(config.ServerSPKIPins) > 32) {
		return nil, &Error{Kind: "invalid_server_spki_pins"}
	}
	if config.ProxyServerSPKIPins != nil && (len(config.ProxyServerSPKIPins) == 0 || len(config.ProxyServerSPKIPins) > 32) {
		return nil, &Error{Kind: "invalid_proxy_server_spki_pins"}
	}
	// Bound newly exposed data before expanding DER bytes into JSON arrays.
	values := []string{config.Profile, config.Protocol, config.Context, config.Proxy, config.BaseURL}
	for _, mapping := range config.ClientCertificatesFor {
		values = append(values, mapping.Origin)
	}
	if config.ProxyCredentials != nil {
		values = append(values, config.ProxyCredentials.Username, config.ProxyCredentials.Password)
	}
	for _, value := range values {
		if len(value) > 64*1024-size {
			return nil, &Error{Kind: "input_limit"}
		}
		size += len(value)
	}
	roots := func(input [][]byte) ([][]uint16, error) {
		if len(input) > 256 {
			return nil, &Error{Kind: "input_limit"}
		}
		result := make([][]uint16, 0, len(input))
		for _, certificate := range input {
			if len(certificate) > 64*1024-size {
				return nil, &Error{Kind: "input_limit"}
			}
			size += len(certificate)
			bytes := make([]uint16, len(certificate))
			for index, value := range certificate {
				bytes[index] = uint16(value)
			}
			result = append(result, bytes)
		}
		return result, nil
	}
	originRoots, err := roots(config.AdditionalRootsDER)
	if err != nil {
		return nil, err
	}
	proxyRoots, err := roots(config.ProxyAdditionalRootsDER)
	if err != nil {
		return nil, err
	}
	wire := struct {
		Profile            string                  `json:"profile"`
		ProfileSettings    *uint64                 `json:"profile_settings,omitempty"`
		Protocol           string                  `json:"protocol"`
		Context            string                  `json:"context,omitempty"`
		Proxy              string                  `json:"proxy,omitempty"`
		Cookies            bool                    `json:"cookies"`
		BaseURL            string                  `json:"base_url,omitempty"`
		Credentials        *ProxyCredentials       `json:"proxy_credentials,omitempty"`
		Roots              [][]uint16              `json:"additional_roots_der"`
		ProxyRoots         [][]uint16              `json:"proxy_additional_roots_der"`
		ServerPins         [][32]byte              `json:"server_spki_pins,omitempty"`
		ProxyPins          [][32]byte              `json:"proxy_server_spki_pins,omitempty"`
		Certificate        *uint64                 `json:"client_certificate,omitempty"`
		CertificateOrigins []wireCertificateOrigin `json:"client_certificates_for,omitempty"`
		Timeouts           wireTimeouts            `json:"timeouts"`
		RedirectPolicy     RedirectPolicy          `json:"redirect_policy"`
		RetryPolicy        wireRetryPolicy         `json:"retry_policy"`
		Network            *wireNetworkOptions     `json:"network,omitempty"`
	}{config.Profile, profileID, config.Protocol, config.Context, config.Proxy, !config.DisableCookies, config.BaseURL, config.ProxyCredentials, originRoots, proxyRoots, config.ServerSPKIPins, config.ProxyServerSPKIPins, certificate, certificateOrigins, timeouts, config.RedirectPolicy, retries, networkWire(config.Network)}
	value, err := dispatch(map[string]any{"kind": "new_client", "config": wire}, nil)
	if err != nil {
		return nil, err
	}
	return clientFromReply(value)
}

func clientFromReply(value json.RawMessage) (*Client, error) {
	var result struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(value, &result) != nil || result.ID == 0 {
		if result.ID != 0 {
			_ = control("release_client", "client", result.ID)
		}
		return nil, &Error{Kind: "native_abi"}
	}
	client := &Client{}
	client.id.Store(result.ID)
	runtime.SetFinalizer(client, func(owner *Client) {
		if id := owner.id.Swap(0); id != 0 {
			_ = control("release_client", "client", id)
		}
	})
	return client, nil
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

// Shutdown closes admission, then waits for active requests and bodies. A cancelled
// wait leaves admission closed; after closing bodies you can call Shutdown again.
func (c *Client) Shutdown(ctx context.Context) error {
	if c.id.Load() == 0 {
		return nil
	}
	if ctx == nil {
		return &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.closing.Store(true)
	err := perform(ctx, map[string]any{"kind": "shutdown", "client": c.id.Load()}, nil, func(completion) error { return nil })
	if err == nil {
		id := c.id.Swap(0)
		runtime.SetFinalizer(c, nil)
		if id != 0 {
			err = control("release_client", "client", id)
		}
	}
	runtime.KeepAlive(c)
	return err
}

// Close waits up to five seconds for graceful shutdown. Close response bodies first.
func (c *Client) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.Shutdown(ctx)
}

// SetCookie updates the native bounded jar using a Set-Cookie field.
func (c *Client) SetCookie(url, value string) error {
	_, err := dispatch(map[string]any{"kind": "cookie_set", "client": c.id.Load(), "url": url, "value": value}, nil)
	runtime.KeepAlive(c)
	return err
}

// CookiesForURL returns the native jar's request Cookie value, or an empty string.
func (c *Client) CookiesForURL(url string) (string, error) {
	value, err := dispatch(map[string]any{"kind": "cookie_get", "client": c.id.Load(), "url": url}, nil)
	runtime.KeepAlive(c)
	if err != nil {
		return "", err
	}
	var result struct {
		Cookie *string `json:"cookie"`
	}
	if json.Unmarshal(value, &result) != nil {
		return "", &Error{Kind: "native_abi"}
	}
	if result.Cookie == nil {
		return "", nil
	}
	return *result.Cookie, nil
}

// ClearCookies clears this client's jar.
func (c *Client) ClearCookies() error {
	err := control("cookie_clear", "client", c.id.Load())
	runtime.KeepAlive(c)
	return err
}

// AttemptBudget is an atomic native allowance shared across requests and clients.
// Admissions include initial attempts and resends, and are never refunded.
type AttemptBudget struct{ id atomic.Uint64 }

// NewAttemptBudget creates a shared allowance, including an initially empty one.
func NewAttemptBudget(maximum uint64) (*AttemptBudget, error) {
	value, err := dispatch(map[string]any{"kind": "new_budget", "maximum": maximum}, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(value, &result) != nil {
		return nil, &Error{Kind: "native_abi"}
	}
	budget := &AttemptBudget{}
	budget.id.Store(result.ID)
	runtime.SetFinalizer(budget, func(owner *AttemptBudget) { _ = owner.Close() })
	return budget, nil
}

// Remaining reports the allowance left.
func (b *AttemptBudget) Remaining() (uint64, error) {
	value, err := dispatch(map[string]any{"kind": "budget_remaining", "budget": b.id.Load()}, nil)
	runtime.KeepAlive(b)
	if err != nil {
		return 0, err
	}
	var result struct {
		Remaining uint64 `json:"remaining"`
	}
	if json.Unmarshal(value, &result) != nil {
		return 0, &Error{Kind: "native_abi"}
	}
	return result.Remaining, nil
}

// TryAdmit charges work initiated outside Phantom; Do charges its own attempts.
func (b *AttemptBudget) TryAdmit() error {
	err := control("budget_admit", "budget", b.id.Load())
	runtime.KeepAlive(b)
	return err
}

// Close releases this handle. Requests already admitted retain their allowance.
func (b *AttemptBudget) Close() error {
	id := b.id.Swap(0)
	if id == 0 {
		return nil
	}
	runtime.SetFinalizer(b, nil)
	return control("release_budget", "budget", id)
}
