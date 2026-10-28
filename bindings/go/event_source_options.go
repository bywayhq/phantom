package phantom

import (
	"time"
	"unsafe"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

// SSEHeader places a literal field or the managed Last-Event-ID field.
// Construct values with SSEField or LastEventID.
type SSEHeader struct {
	kind  uint64
	field Header
}

// SSEField adds an ordered literal field. Use LastEventID for the managed ID.
func SSEField(field Header) SSEHeader { return SSEHeader{kind: 1, field: field} }

// LastEventID positions the managed ID, omitted until an ID is received.
// Use Last-Event-ID for h1 and last-event-id for h2/h3.
func LastEventID(name string) SSEHeader { return SSEHeader{kind: 2, field: Header{Name: name}} }

// EventSourceOptions configure a reconnecting GET on h1, h2 or h3. Client
// cookies, trust, templates and retry/redirect policies still apply. For an
// ordinary Request, including bodies or attempt budgets, use Client.Events.
type EventSourceOptions struct {
	Protocol string
	// Nil keeps the default Accept and Cache-Control fields; non-nil replaces
	// the whole ordered template. Literal Last-Event-ID fields are invalid.
	Headers []SSEHeader
	Limits  *SSELimits
	// Nil uses core defaults: no idle limit, 3s initial retry and no minimum.
	// Explicit zero is passed through and validated by the core.
	IdleTimeout, InitialRetry, MinRetry *time.Duration
	// Nil permits three reconnects. Zero disables reconnects.
	MaxReconnects *uint64
	// Limits apply per attempt through its response head. ReadIdle must inherit;
	// use IdleTimeout for the event stream. Total does not cover its lifetime.
	Timeouts Timeouts
	// Nil inherits the client route; a pointer to "" selects direct routing.
	Proxy            *string
	ProxyCredentials *ProxyCredentials
}

type eventSourceOpening struct {
	descriptor native.EventSourceOpening
	headers    []native.EventSourceHeader
}

func eventSourceOpeningValue(client uint64, url string, options EventSourceOptions) (eventSourceOpening, error) {
	var result eventSourceOpening
	value := &result.descriptor
	value.Client, value.URL = client, native.BorrowedString(url)
	switch options.Protocol {
	case "h1":
		value.Protocol = 1
	case "h2":
		value.Protocol = 2
	case "h3":
		value.Protocol = 3
	default:
		return result, &Error{Kind: "invalid_event_source_protocol"}
	}
	limits := SSELimits{MaxLineBytes: 64 * 1024, MaxEventBytes: 1024 * 1024}
	if options.Limits != nil {
		limits = *options.Limits
	}
	if limits.MaxLineBytes < 0 || limits.MaxEventBytes < 0 || limits.MaxLineBytes > 1024*1024 || limits.MaxEventBytes > 8*1024*1024 {
		return result, &Error{Kind: "invalid_sse_limits"}
	}
	value.Line, value.Event = uint64(limits.MaxLineBytes), uint64(limits.MaxEventBytes)
	for _, field := range []struct {
		source *time.Duration
		target *uint64
		flag   uint64
	}{{options.IdleTimeout, &value.Idle, 1}, {options.InitialRetry, &value.InitialRetry, 2}, {options.MinRetry, &value.MinRetry, 4}} {
		if field.source != nil {
			if *field.source < 0 {
				return result, &Error{Kind: "invalid_timeout"}
			}
			value.Flags |= field.flag
			*field.target = uint64(*field.source)
		}
	}
	if options.MaxReconnects != nil {
		value.Flags |= 8
		value.Maximum = *options.MaxReconnects
	}
	if options.Timeouts.ReadIdle != (Timeout{}) {
		return result, &Error{Kind: "event_source_read_idle_unsupported"}
	}
	wire, err := timeoutsWire(options.Timeouts, 0)
	if err != nil {
		return result, err
	}
	for i, field := range []wireTimeout{wire.PoolAdmission, wire.Connect, wire.ResponseHead, wire.ReadIdle, wire.Total} {
		mode := uint64(0)
		switch field.Mode {
		case "disabled":
			mode = 1
		case "limit":
			mode = 2
		}
		value.Timeouts[i] = native.Timeout{Mode: mode, Nanoseconds: pointed(field.Nanoseconds)}
	}
	if options.ProxyCredentials != nil && (options.Proxy == nil || *options.Proxy == "") {
		return result, &Error{Kind: "invalid_proxy_credentials"}
	}
	size := len(url)
	if options.Proxy != nil {
		value.Flags |= 16
		value.Proxy = native.BorrowedString(*options.Proxy)
		size += len(*options.Proxy)
	}
	if options.ProxyCredentials != nil {
		value.Flags |= 32
		value.Username = native.BorrowedString(options.ProxyCredentials.Username)
		value.Password = native.BorrowedString(options.ProxyCredentials.Password)
		size += len(options.ProxyCredentials.Username) + len(options.ProxyCredentials.Password)
	}
	if len(options.Headers) > 256 {
		return result, &Error{Kind: "input_limit"}
	}
	if options.Headers != nil {
		value.HeadersPresent = 1
		result.headers = make([]native.EventSourceHeader, len(options.Headers))
		for i, header := range options.Headers {
			if header.kind != 1 && header.kind != 2 {
				return result, &Error{Kind: "invalid_event_source_header"}
			}
			size += len(header.field.Name) + len(header.field.Value)
			result.headers[i] = native.EventSourceHeader{Kind: header.kind, Field: native.Field{Name: native.BorrowedString(header.field.Name), Value: native.BorrowedBytes(header.field.Value), Sensitive: boolean(header.field.Sensitive)}}
		}
		value.Headers = unsafe.Pointer(unsafe.SliceData(result.headers))
		value.HeaderCount = uint64(len(result.headers))
	}
	if size > 64*1024 {
		return result, &Error{Kind: "input_limit"}
	}
	return result, nil
}
