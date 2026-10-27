package phantom

import (
	"bytes"
	"unsafe"
)

type nativeSpan struct {
	Pointer unsafe.Pointer
	Length  uint64
}
type nativeField struct {
	Name, Value nativeSpan
	Sensitive   uint64
}
type nativeTimeout struct{ Mode, Nanoseconds uint64 }
type nativeRetry struct {
	Flags                  uint64
	ConnectionMaximum      uint64
	ConnectionDelay        uint64
	ConnectionMaximumDelay uint64
	Statuses               unsafe.Pointer
	StatusCount            uint64
	StatusMaximum          uint64
	StatusDelay            uint64
	StatusMaximumDelay     uint64
	RetryAfter             uint64
	Unprocessed            uint64
	Maximum                uint64
}
type nativeRequest struct {
	Client                uint64
	Method, URL           nativeSpan
	Headers               unsafe.Pointer
	HeaderCount           uint64
	Trailers              unsafe.Pointer
	TrailerCount          uint64
	Flags                 uint64
	ExpectContinue        uint64
	Budget                uint64
	Transfer              uint64
	Diagnostics           uint64
	PreparedBody          uint64
	Upload                uint64
	Timeouts              [5]nativeTimeout
	DecodedMaximum        uint64
	RedirectMaximum       uint64
	CredentialHeaders     unsafe.Pointer
	CredentialHeaderCount uint64
	RedirectHistory       uint64
	Retry                 *nativeRetry
}
type nativeError struct{ Kind, Protocol, TimeoutPhase [64]byte }
type nativeReply struct {
	Operation uint64
	Error     nativeError
}
type nativeSlice struct{ Offset, Length uint64 }
type nativeOutputField struct {
	Name, Value nativeSlice
	Sensitive   uint64
}
type nativeHop struct {
	From, To, Method, NextMethod nativeSlice
	Status                       uint64
}
type nativeEvent struct {
	Operation      uint64
	Kind           uint64
	Body           uint64
	Status         uint64
	Protocol       uint64
	Redirects      uint64
	SetupRetries   uint64
	HistoryPresent uint64
	HistoryOmitted uint64
	Part           uint64
	TrailerState   uint64
	FieldCount     uint64
	HopCount       uint64
	CodingCount    uint64
	ArenaLength    uint64
	DataLength     uint64
	EffectiveURL   nativeSlice
	Error          nativeError
}

type responseHead struct {
	Body                   uint64
	Status                 int
	Protocol               string
	Headers                []Header
	EffectiveURL           string
	RedirectsFollowed      uint64
	ConnectionSetupRetries uint64
	DecodedContentCodings  []string
	RedirectHistory        *RedirectHistory
}

func (value nativeError) err() error {
	if value.Kind[0] == 0 {
		return nil
	}
	text := func(value []byte) string {
		if index := bytes.IndexByte(value, 0); index >= 0 {
			value = value[:index]
		}
		return string(value)
	}
	return &Error{Kind: text(value.Kind[:]), Protocol: text(value.Protocol[:]), TimeoutPhase: text(value.TimeoutPhase[:])}
}
func borrowedString(value string) nativeSpan {
	return nativeSpan{unsafe.Pointer(unsafe.StringData(value)), uint64(len(value))}
}
func borrowedBytes(value []byte) nativeSpan {
	return nativeSpan{unsafe.Pointer(unsafe.SliceData(value)), uint64(len(value))}
}
func boolean(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
func pointed(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

func submitOperation(kind, id, argument uint64, data []byte) (uint64, error) {
	if err := ensureNativeIdentity(); err != nil {
		return 0, err
	}
	var result nativeReply
	if err := nativeOperation(kind, id, argument, data, &result); err != nil {
		return 0, err
	}
	return result.Operation, result.Error.err()
}

func eventCompletion(event nativeEvent, fields []nativeOutputField, hops []nativeHop, arena, data []byte) (completion, error) {
	result := completion{Operation: event.Operation, Error: nil, kind: event.Kind, part: event.Part}
	invalid := func() (completion, error) { return completion{}, &Error{Kind: "native_abi"} }
	if event.Operation == 0 || event.ArenaLength > uint64(len(arena)) || event.DataLength > uint64(len(data)) || event.FieldCount > uint64(len(fields)) || event.CodingCount > uint64(len(fields))-event.FieldCount || event.HopCount > uint64(len(hops)) {
		return invalid()
	}
	if err := event.Error.err(); err != nil {
		result.Error = err.(*Error)
		return result, nil
	}
	arena = arena[:event.ArenaLength]
	slice := func(span nativeSlice) ([]byte, error) {
		if span.Offset > uint64(len(arena)) || span.Length > uint64(len(arena))-span.Offset {
			return nil, &Error{Kind: "native_abi"}
		}
		return arena[span.Offset : span.Offset+span.Length], nil
	}
	text := func(span nativeSlice) (string, error) { value, err := slice(span); return string(value), err }
	var headers []Header
	if event.FieldCount != 0 {
		headers = make([]Header, event.FieldCount)
	}
	for i := range headers {
		source := fields[i]
		name, err := text(source.Name)
		if err != nil {
			return completion{}, err
		}
		value, err := slice(source.Value)
		if err != nil {
			return completion{}, err
		}
		if source.Sensitive > 1 {
			return invalid()
		}
		headers[i] = Header{Name: name, Value: append([]byte(nil), value...), Sensitive: source.Sensitive != 0}
	}
	switch event.Kind {
	case 1:
	case 2:
		result.data = append([]byte(nil), data[:event.DataLength]...)
	case 3:
		result.eof = true
		switch event.TrailerState {
		case 1:
			result.trailers = ResponseTrailers{State: TrailersComplete, Headers: headers}
		case 2:
			result.trailers = ResponseTrailers{State: TrailersUnavailable}
		default:
			return invalid()
		}
	case 4:
	case 5:
		if event.Body == 0 || event.Status < 100 || event.Status > 999 || event.HistoryPresent > 1 {
			return invalid()
		}
		protocol := ""
		switch event.Protocol {
		case 1:
			protocol = "h1"
		case 2:
			protocol = "h2"
		case 3:
			protocol = "h3"
		default:
			return invalid()
		}
		url, err := text(event.EffectiveURL)
		if err != nil || url == "" {
			return invalid()
		}
		head := &responseHead{Body: event.Body, Status: int(event.Status), Protocol: protocol, Headers: headers, EffectiveURL: url, RedirectsFollowed: event.Redirects, ConnectionSetupRetries: event.SetupRetries}
		for _, field := range fields[event.FieldCount : event.FieldCount+event.CodingCount] {
			name, err := text(field.Name)
			if err != nil {
				return completion{}, err
			}
			head.DecodedContentCodings = append(head.DecodedContentCodings, name)
		}
		if event.HistoryPresent != 0 {
			history := &RedirectHistory{OmittedHops: event.HistoryOmitted}
			for _, hop := range hops[:event.HopCount] {
				from, err := text(hop.From)
				if err != nil {
					return completion{}, err
				}
				to, err := text(hop.To)
				if err != nil {
					return completion{}, err
				}
				method, err := text(hop.Method)
				if err != nil {
					return completion{}, err
				}
				next, err := text(hop.NextMethod)
				if err != nil {
					return completion{}, err
				}
				history.Entries = append(history.Entries, RedirectHop{FromURL: from, ToURL: to, Method: method, NextMethod: next, Status: int(hop.Status)})
			}
			head.RedirectHistory = history
		}
		result.head = head
	default:
		return invalid()
	}
	return result, nil
}

func nativeRetryValue(value wireRetryPolicy) (*nativeRetry, []uint16) {
	result := &nativeRetry{}
	if item := value.Connection; item != nil {
		result.Flags |= 1
		result.ConnectionMaximum = item.Maximum
		result.ConnectionDelay = item.DelayNS
		if item.MaximumDelayNS != nil {
			result.Flags |= 2
			result.ConnectionMaximumDelay = *item.MaximumDelayNS
		}
		if item.FullJitter {
			result.Flags |= 4
		}
	}
	var statuses []uint16
	if item := value.Status; item != nil {
		result.Flags |= 8
		result.StatusMaximum = item.Maximum
		result.StatusDelay = item.DelayNS
		for _, status := range item.Statuses {
			statuses = append(statuses, uint16(status))
		}
		result.Statuses = unsafe.Pointer(unsafe.SliceData(statuses))
		result.StatusCount = uint64(len(statuses))
		if item.MaximumDelayNS != nil {
			result.Flags |= 16
			result.StatusMaximumDelay = *item.MaximumDelayNS
		}
		if item.FullJitter {
			result.Flags |= 32
		}
		if item.RetryAfterLimitNS != nil {
			result.Flags |= 64
			result.RetryAfter = *item.RetryAfterLimitNS
		}
	}
	if value.ReusedConnectionReplay {
		result.Flags |= 128
	}
	if value.UnprocessedReplays != nil {
		result.Flags |= 256
		result.Unprocessed = *value.UnprocessedReplays
	}
	if value.MaximumRetries != nil {
		result.Flags |= 512
		result.Maximum = *value.MaximumRetries
	}
	if value.HTTP2Fallback {
		result.Flags |= 1024
	}
	return result, statuses
}
