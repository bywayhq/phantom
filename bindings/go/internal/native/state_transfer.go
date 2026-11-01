package native

import "unsafe"

const MaxStateCookies = 16384
const MaxStateAlternatives = 32768
const MaxStateText = 32 * 1024 * 1024
const MaxStateTickets = 16 * 1024 * 1024

// StateTimestamp preserves the full signed second range without UnixNano loss.
type StateTimestamp struct {
	Seconds     int64
	Nanoseconds uint64
}

type StateCookie struct {
	Name, Value, Domain, Path, PartitionKey Slice
	Flags, SourceScheme, SameSite           uint64
	Expiry                                  StateTimestamp
}

type StateAlternative struct {
	Origin, Host Slice
	Port         uint64
	Expiry       StateTimestamp
}

type StateRoute struct {
	Proxy, Username, Password Span
	Credentials               uint64
}

type StateTransfer struct {
	Client, Kind     uint64
	Cookies          unsafe.Pointer
	CookieCount      uint64
	Alternatives     unsafe.Pointer
	AlternativeCount uint64
	Arena, Key       Span
	Routes           unsafe.Pointer
	RouteCount       uint64
}

type StateResult struct {
	Kind, Enabled, CookieCount, AlternativeCount, ArenaLength, Entry uint64
	Error                                                            ErrorRecord
}

func StateResultBounds(value StateResult) error {
	if value.Kind < 1 || value.Kind > 6 || value.Enabled > 1 || value.CookieCount > MaxStateCookies ||
		value.AlternativeCount > MaxStateAlternatives || value.ArenaLength > MaxStateText ||
		(value.Kind != 1 && value.CookieCount != 0) || (value.Kind != 3 && value.AlternativeCount != 0) ||
		(value.Kind == 5 && value.ArenaLength > MaxStateTickets) ||
		(value.Kind != 1 && value.Kind != 3 && value.Kind != 5 && value.ArenaLength != 0) ||
		(value.Enabled == 0 && (value.CookieCount != 0 || value.AlternativeCount != 0 || value.ArenaLength != 0)) ||
		(value.Kind == 2 && value.Entry > MaxStateCookies) ||
		(value.Kind == 4 && value.Entry > MaxStateAlternatives) ||
		(value.Kind != 2 && value.Kind != 4 && value.Entry != 0) {
		return &Failure{Kind: "native_abi"}
	}
	return nil
}

// ReadStateResult probes once and copies an immutable result before operation ack.
func ReadStateResult(operation uint64) (StateResult, []StateCookie, []StateAlternative, []byte, error) {
	var probe StateResult
	if err := StateTransferCopy(operation, &probe, nil, nil, nil); err != nil {
		return StateResult{}, nil, nil, nil, err
	}
	if err := StateResultBounds(probe); err != nil {
		return StateResult{}, nil, nil, nil, err
	}
	if err := probe.Error.Err(); err != nil {
		return probe, nil, nil, nil, nil
	}
	cookies := make([]StateCookie, probe.CookieCount)
	alternatives := make([]StateAlternative, probe.AlternativeCount)
	arena := make([]byte, probe.ArenaLength)
	if len(cookies) != 0 || len(alternatives) != 0 || len(arena) != 0 {
		value := probe
		if err := StateTransferCopy(operation, &value, cookies, alternatives, arena); err != nil {
			clear(arena)
			return StateResult{}, nil, nil, nil, err
		}
		if value != probe {
			clear(arena)
			return StateResult{}, nil, nil, nil, &Failure{Kind: "native_abi"}
		}
	}
	return probe, cookies, alternatives, arena, nil
}
