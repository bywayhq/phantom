package phantom

import "time"

// RetryPolicy selects caller-enabled retries inside the Rust request loop.
// Its zero value enables none. Browser-required replays have separate limits.
type RetryPolicy struct {
	Connection             *ConnectionRetry
	Status                 *StatusRetry
	ReusedConnectionReplay bool
	UnprocessedReplays     *uint64
	// MaximumRetries caps all caller-enabled classes together. Nil adds no cap;
	// a pointer to zero disables them. Redirects and browser replays are separate.
	MaximumRetries *uint64
	// HTTP2Fallback explicitly permits eligible HTTP/3 setup failures to use H2.
	HTTP2Fallback bool
}

// ConnectionRetry retries eligible setup failures, before sending a request.
// Maximum must be positive. Delay may be zero; MaximumDelay enables doubling.
type ConnectionRetry struct {
	Maximum      uint64
	Delay        time.Duration
	MaximumDelay *time.Duration
	FullJitter   bool
}

// StatusRetry retries replayable idempotent requests for selected status codes.
// Supported codes are 408, 425, 429, 500, 502, 503 and 504. Maximum is positive.
// RetryAfterLimit enables bounded Retry-After handling; larger values return
// the original response. A delay that cannot fit the total deadline does too.
type StatusRetry struct {
	Statuses        []int
	Maximum         uint64
	Delay           time.Duration
	MaximumDelay    *time.Duration
	FullJitter      bool
	RetryAfterLimit *time.Duration
}

type wireConnectionRetry struct {
	Maximum        uint64  `json:"maximum"`
	DelayNS        uint64  `json:"delay_ns"`
	MaximumDelayNS *uint64 `json:"maximum_delay_ns,omitempty"`
	FullJitter     bool    `json:"full_jitter"`
}

type wireStatusRetry struct {
	Statuses          []int   `json:"statuses"`
	Maximum           uint64  `json:"maximum"`
	DelayNS           uint64  `json:"delay_ns"`
	MaximumDelayNS    *uint64 `json:"maximum_delay_ns,omitempty"`
	FullJitter        bool    `json:"full_jitter"`
	RetryAfterLimitNS *uint64 `json:"retry_after_limit_ns,omitempty"`
}

type wireRetryPolicy struct {
	Connection             *wireConnectionRetry `json:"connection,omitempty"`
	Status                 *wireStatusRetry     `json:"status,omitempty"`
	ReusedConnectionReplay bool                 `json:"reused_connection_replay"`
	UnprocessedReplays     *uint64              `json:"unprocessed_replays,omitempty"`
	MaximumRetries         *uint64              `json:"maximum_retries,omitempty"`
	HTTP2Fallback          bool                 `json:"http2_fallback"`
}

func retryPolicyWire(value RetryPolicy) (wireRetryPolicy, error) {
	invalid := func() (wireRetryPolicy, error) { return wireRetryPolicy{}, &Error{Kind: "invalid_retry_policy"} }
	copyCount := func(value *uint64) *uint64 {
		if value == nil {
			return nil
		}
		copy := *value
		return &copy
	}
	duration := func(value *time.Duration) (*uint64, bool) {
		if value == nil {
			return nil, true
		}
		if *value < 0 {
			return nil, false
		}
		copy := uint64(*value)
		return &copy, true
	}
	result := wireRetryPolicy{
		ReusedConnectionReplay: value.ReusedConnectionReplay,
		UnprocessedReplays:     copyCount(value.UnprocessedReplays),
		MaximumRetries:         copyCount(value.MaximumRetries),
		HTTP2Fallback:          value.HTTP2Fallback,
	}
	if result.UnprocessedReplays != nil && *result.UnprocessedReplays == 0 {
		return invalid()
	}
	if value.Connection != nil {
		item := *value.Connection
		maximum, ok := duration(item.MaximumDelay)
		if !ok || item.Maximum == 0 || item.Delay < 0 || maximum != nil && *maximum < uint64(item.Delay) {
			return invalid()
		}
		result.Connection = &wireConnectionRetry{item.Maximum, uint64(item.Delay), maximum, item.FullJitter}
	}
	if value.Status != nil {
		item := *value.Status
		maximum, ok := duration(item.MaximumDelay)
		after, afterOK := duration(item.RetryAfterLimit)
		if !ok || !afterOK || item.Maximum == 0 || item.Delay < 0 || maximum != nil && *maximum < uint64(item.Delay) {
			return invalid()
		}
		// The core stores a set of seven status codes. Preserve first appearance
		// without copying repeated entries into the bounded command channel.
		statuses := make([]int, 0, min(7, len(item.Statuses)))
		var seen uint8
		for _, status := range item.Statuses {
			var bit uint8
			switch status {
			case 408:
				bit = 1 << 0
			case 425:
				bit = 1 << 1
			case 429:
				bit = 1 << 2
			case 500:
				bit = 1 << 3
			case 502:
				bit = 1 << 4
			case 503:
				bit = 1 << 5
			case 504:
				bit = 1 << 6
			default:
				return invalid()
			}
			if seen&bit == 0 {
				statuses = append(statuses, status)
				seen |= bit
			}
		}
		if len(statuses) == 0 {
			return invalid()
		}
		result.Status = &wireStatusRetry{statuses, item.Maximum, uint64(item.Delay), maximum, item.FullJitter, after}
	}
	return result, nil
}
