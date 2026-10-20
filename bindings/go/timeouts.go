package phantom

import "time"

// TimeoutMode selects inheritance, no limit, or a finite limit.
type TimeoutMode string

const (
	// TimeoutInherit keeps the client limit. On Config, it leaves the limit disabled.
	TimeoutInherit TimeoutMode = ""
	// TimeoutDisabled removes this phase's limit.
	TimeoutDisabled TimeoutMode = "disabled"
	// TimeoutLimited applies Duration, including a finite zero limit.
	TimeoutLimited TimeoutMode = "limit"
)

// Timeout makes a finite zero limit distinct from inheritance and disabling.
type Timeout struct {
	Mode     TimeoutMode
	Duration time.Duration
}

// LimitTimeout applies a nonnegative duration without rounding to milliseconds.
func LimitTimeout(duration time.Duration) Timeout {
	return Timeout{Mode: TimeoutLimited, Duration: duration}
}

// Timeouts controls pool admission, setup, response head, body inactivity and total.
// The total deadline includes retries, redirects and response-body consumption.
type Timeouts struct {
	PoolAdmission Timeout
	Connect       Timeout
	ResponseHead  Timeout
	ReadIdle      Timeout
	Total         Timeout
}

type wireTimeout struct {
	Mode        string  `json:"mode"`
	Nanoseconds *uint64 `json:"nanoseconds,omitempty"`
}
type wireTimeouts struct {
	PoolAdmission wireTimeout `json:"pool_admission"`
	Connect       wireTimeout `json:"connect"`
	ResponseHead  wireTimeout `json:"response_head"`
	ReadIdle      wireTimeout `json:"read_idle"`
	Total         wireTimeout `json:"total"`
}

func timeoutWire(value Timeout) (wireTimeout, error) {
	switch value.Mode {
	case TimeoutInherit, TimeoutDisabled:
		if value.Duration != 0 {
			return wireTimeout{}, &Error{Kind: "invalid_timeout"}
		}
		mode := string(value.Mode)
		if mode == "" {
			mode = "inherit"
		}
		return wireTimeout{Mode: mode}, nil
	case TimeoutLimited:
		if value.Duration >= 0 {
			nanoseconds := uint64(value.Duration)
			return wireTimeout{Mode: "limit", Nanoseconds: &nanoseconds}, nil
		}
	}
	return wireTimeout{}, &Error{Kind: "invalid_timeout"}
}

func timeoutsWire(value Timeouts, legacy time.Duration) (wireTimeouts, error) {
	// Keep the original total-timeout field's minimum and millisecond rounding.
	if legacy != 0 {
		if legacy < time.Millisecond || value.Total != (Timeout{}) {
			return wireTimeouts{}, &Error{Kind: "invalid_timeout"}
		}
		value.Total = LimitTimeout(legacy.Truncate(time.Millisecond))
	}
	var result wireTimeouts
	for _, field := range []struct {
		value Timeout
		wire  *wireTimeout
	}{
		{value.PoolAdmission, &result.PoolAdmission},
		{value.Connect, &result.Connect},
		{value.ResponseHead, &result.ResponseHead},
		{value.ReadIdle, &result.ReadIdle},
		{value.Total, &result.Total},
	} {
		wire, err := timeoutWire(field.value)
		if err != nil {
			return wireTimeouts{}, err
		}
		*field.wire = wire
	}
	return result, nil
}
