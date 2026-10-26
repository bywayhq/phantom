// Package phantom provides native requests with explicit profiles and protocols.
package phantom

import (
	"context"
	"encoding/json"
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
	// Pool overrides core connection retention and per-origin admission settings.
	// Nil preserves the selected profile's defaults and core defaults.
	Pool *PoolOptions
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

// Client reuses native connection pools and cookies. It is safe for concurrent use.
type Client struct {
	id      atomic.Uint64
	closing atomic.Bool
}

// New creates a client. It performs no request and ignores proxy environment variables.
func New(config Config) (*Client, error) {
	pool, err := poolWire(config.Pool)
	if err != nil {
		return nil, err
	}
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
	redirects, err := redirectPolicyWire(config.RedirectPolicy)
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
		Pool               *wirePoolOptions        `json:"pool,omitempty"`
	}{config.Profile, profileID, config.Protocol, config.Context, config.Proxy, !config.DisableCookies, config.BaseURL, config.ProxyCredentials, originRoots, proxyRoots, config.ServerSPKIPins, config.ProxyServerSPKIPins, certificate, certificateOrigins, timeouts, redirects, retries, networkWire(config.Network), pool}
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
