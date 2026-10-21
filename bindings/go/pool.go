package phantom

import "time"

// PoolOptions overrides operational pool settings. Nil fields keep core defaults.
// Counts must be positive and fit the host's usize. Active and pending bounds
// are per origin-and-route pool key, across its connections; core also applies
// the peer's stream limit and validates semaphore bounds. These are independent
// of the Go binding's process-wide handle and operation capacities.
type PoolOptions struct {
	// Retention limits count pool entries, not necessarily individual sockets.
	// Negotiated H1/H2 uses the lower retention limit. An H3 entry retains up to
	// four transport locations, each with its own connection limit.
	MaxRetainedHTTP1Connections *uint64
	MaxRetainedHTTP2Connections *uint64
	MaxRetainedHTTP3Connections *uint64
	// The H1 active bound also caps open connections, including idle ones.
	MaxConcurrentHTTP1RequestsPerOrigin *uint64
	MaxPendingHTTP1RequestsPerOrigin    *uint64
	MaxConcurrentHTTP2RequestsPerOrigin *uint64
	MaxPendingHTTP2RequestsPerOrigin    *uint64
	MaxHTTP2ConnectionsPerOrigin        *uint64
	MaxConcurrentHTTP3RequestsPerOrigin *uint64
	MaxPendingHTTP3RequestsPerOrigin    *uint64
	// Core accepts at most eight H3 connections per transport location.
	MaxHTTP3ConnectionsPerOrigin *uint64
	// NegotiatedSetupWaitLimit bounds waiting behind another TLS handshake to
	// an origin previously selecting H2. Nil waits for that handshake; explicit
	// zero permits an immediate competing connection. Negative values fail.
	NegotiatedSetupWaitLimit *time.Duration
}

type wirePoolOptions struct {
	MaxRetainedHTTP1Connections         *uint64 `json:"max_retained_http1_connections,omitempty"`
	MaxRetainedHTTP2Connections         *uint64 `json:"max_retained_http2_connections,omitempty"`
	MaxRetainedHTTP3Connections         *uint64 `json:"max_retained_http3_connections,omitempty"`
	MaxConcurrentHTTP1RequestsPerOrigin *uint64 `json:"max_concurrent_http1_requests_per_origin,omitempty"`
	MaxPendingHTTP1RequestsPerOrigin    *uint64 `json:"max_pending_http1_requests_per_origin,omitempty"`
	MaxConcurrentHTTP2RequestsPerOrigin *uint64 `json:"max_concurrent_http2_requests_per_origin,omitempty"`
	MaxPendingHTTP2RequestsPerOrigin    *uint64 `json:"max_pending_http2_requests_per_origin,omitempty"`
	MaxHTTP2ConnectionsPerOrigin        *uint64 `json:"max_http2_connections_per_origin,omitempty"`
	MaxConcurrentHTTP3RequestsPerOrigin *uint64 `json:"max_concurrent_http3_requests_per_origin,omitempty"`
	MaxPendingHTTP3RequestsPerOrigin    *uint64 `json:"max_pending_http3_requests_per_origin,omitempty"`
	MaxHTTP3ConnectionsPerOrigin        *uint64 `json:"max_http3_connections_per_origin,omitempty"`
	NegotiatedSetupWaitLimitNS          *uint64 `json:"negotiated_setup_wait_limit_ns,omitempty"`
}

func poolWire(input *PoolOptions) (*wirePoolOptions, error) {
	if input == nil {
		return nil, nil
	}
	result := &wirePoolOptions{}
	for _, field := range []struct {
		input *uint64
		wire  **uint64
	}{
		{input.MaxRetainedHTTP1Connections, &result.MaxRetainedHTTP1Connections},
		{input.MaxRetainedHTTP2Connections, &result.MaxRetainedHTTP2Connections},
		{input.MaxRetainedHTTP3Connections, &result.MaxRetainedHTTP3Connections},
		{input.MaxConcurrentHTTP1RequestsPerOrigin, &result.MaxConcurrentHTTP1RequestsPerOrigin},
		{input.MaxPendingHTTP1RequestsPerOrigin, &result.MaxPendingHTTP1RequestsPerOrigin},
		{input.MaxConcurrentHTTP2RequestsPerOrigin, &result.MaxConcurrentHTTP2RequestsPerOrigin},
		{input.MaxPendingHTTP2RequestsPerOrigin, &result.MaxPendingHTTP2RequestsPerOrigin},
		{input.MaxHTTP2ConnectionsPerOrigin, &result.MaxHTTP2ConnectionsPerOrigin},
		{input.MaxConcurrentHTTP3RequestsPerOrigin, &result.MaxConcurrentHTTP3RequestsPerOrigin},
		{input.MaxPendingHTTP3RequestsPerOrigin, &result.MaxPendingHTTP3RequestsPerOrigin},
		{input.MaxHTTP3ConnectionsPerOrigin, &result.MaxHTTP3ConnectionsPerOrigin},
	} {
		if field.input != nil {
			value := *field.input
			if value == 0 || value > uint64(^uint(0)) {
				return nil, &Error{Kind: "invalid_pool_options"}
			}
			*field.wire = &value
		}
	}
	if input.NegotiatedSetupWaitLimit != nil {
		value := *input.NegotiatedSetupWaitLimit
		if value < 0 {
			return nil, &Error{Kind: "invalid_pool_options"}
		}
		nanoseconds := uint64(value)
		result.NegotiatedSetupWaitLimitNS = &nanoseconds
	}
	return result, nil
}
