package phantom

import (
	"time"
	"unsafe"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

// WebSocketOptions configure one opening. Empty Protocol uses the profile's
// connection policy; h1, h2 and h3 select an exact protocol without fallback.
// Ordinary Request templates, retry policies and attempt budgets do not apply.
type WebSocketOptions struct {
	Protocol string
	Headers  []Header
	// Template replaces the opening fields in order. Nil keeps profile fields.
	// An empty, non-nil template is validated as an explicit replacement.
	Template []WebSocketHeader
	// Nil Limits use 16 MiB frames, 64 MiB messages and 131072 fragments.
	Limits *WebSocketLimits
	// Nil inherits the profile timer; zero disables it. Negative is invalid.
	HandshakeTimeout *time.Duration
	// Setup retries apply only before opening bytes reach the origin.
	SetupRetries    uint64
	SetupRetryDelay time.Duration
	// Nil disables compression. A policy offers RFC 7692 negotiation.
	Deflate *WebSocketDeflate
}

// WebSocketLimits bound frames, reassembled messages and fragment counts.
// All must be positive; FrameBytes cannot exceed MessageBytes. The Go native
// boundary supports messages up to 64 MiB, including decompressed messages.
type WebSocketLimits struct{ FrameBytes, MessageBytes, MessageFragments uint64 }

// WebSocketHeader is a literal/default field or a generated-value placeholder.
// Kind is authority, key, cookies, caller, field, default or deflate. Only field
// and default accept Value or Sensitive. Names preserve the supplied spelling.
type WebSocketHeader struct {
	Kind      string
	Name      string
	Value     []byte
	Sensitive bool
}

// WebSocketDeflate controls the ordered compression offer and local encoder.
// Nil Parameters use client_max_window_bits without a value. A non-nil empty
// sequence offers bare permessage-deflate. WindowBits zero uses 15; nil Level
// uses 6; nil CompressEmpty uses true. Level accepts 0..9.
type WebSocketDeflate struct {
	Parameters    []WebSocketDeflateParameter
	WindowBits    uint8
	Level         *uint8
	CompressEmpty *bool
}

// WebSocketDeflateParameter names serverNoContextTakeover,
// clientNoContextTakeover, serverMaxWindowBits or clientMaxWindowBits.
// Bits must be zero for takeover options, 8..15 for serverMaxWindowBits,
// and zero (no value) or 8..15 for clientMaxWindowBits.
type WebSocketDeflateParameter struct {
	Kind string
	Bits uint8
}

type websocketOpening struct {
	descriptor native.WebSocketOpening
	headers    []native.Field
	template   []native.WebSocketTemplateField
	parameters []native.WebSocketDeflateParameter
}

func websocketOpeningValue(client uint64, url string, options WebSocketOptions) (websocketOpening, error) {
	var result websocketOpening
	value := &result.descriptor
	value.Client, value.URL = client, native.BorrowedString(url)
	switch options.Protocol {
	case "":
	case "h1":
		value.Protocol = 1
	case "h2":
		value.Protocol = 2
	case "h3":
		value.Protocol = 3
	default:
		return result, &Error{Kind: "invalid_websocket_protocol"}
	}
	limits := WebSocketLimits{16 * 1024 * 1024, 64 * 1024 * 1024, 128 * 1024}
	if options.Limits != nil {
		limits = *options.Limits
	}
	if limits.FrameBytes == 0 || limits.MessageBytes == 0 || limits.FrameBytes > limits.MessageBytes || limits.MessageBytes > native.MaxWebSocketMessage || limits.MessageFragments == 0 {
		return result, &Error{Kind: "invalid_websocket_limits"}
	}
	value.Frame, value.Message, value.Fragments = limits.FrameBytes, limits.MessageBytes, limits.MessageFragments
	if options.HandshakeTimeout != nil {
		if *options.HandshakeTimeout < 0 {
			return result, &Error{Kind: "invalid_timeout"}
		}
		value.Timeout.Mode = 1
		if *options.HandshakeTimeout > 0 {
			value.Timeout.Mode, value.Timeout.Nanoseconds = 2, uint64(*options.HandshakeTimeout)
		}
	}
	if options.SetupRetryDelay < 0 || (options.SetupRetries == 0 && options.SetupRetryDelay != 0) {
		return result, &Error{Kind: "invalid_websocket_retry"}
	}
	value.Retries, value.RetryDelay = options.SetupRetries, uint64(options.SetupRetryDelay)
	if len(options.Headers) > 256 || len(options.Template) > 256-len(options.Headers) {
		return result, &Error{Kind: "input_limit"}
	}
	size := len(url)
	for _, header := range options.Headers {
		size += len(header.Name) + len(header.Value)
	}
	for _, header := range options.Template {
		size += len(header.Name) + len(header.Value)
	}
	if size > 64*1024 {
		return result, &Error{Kind: "input_limit"}
	}
	result.headers = make([]native.Field, len(options.Headers))
	for i, header := range options.Headers {
		result.headers[i] = native.Field{Name: native.BorrowedString(header.Name), Value: native.BorrowedBytes(header.Value), Sensitive: boolean(header.Sensitive)}
	}
	value.Headers, value.HeaderCount = unsafe.Pointer(unsafe.SliceData(result.headers)), uint64(len(result.headers))
	if options.Template != nil {
		value.TemplatePresent = 1
		result.template = make([]native.WebSocketTemplateField, len(options.Template))
		for i, header := range options.Template {
			var kind uint64
			switch header.Kind {
			case "authority":
				kind = 1
			case "key":
				kind = 2
			case "cookies":
				kind = 3
			case "caller":
				kind = 4
			case "field":
				kind = 5
			case "default":
				kind = 6
			case "deflate":
				kind = 7
			default:
				return result, &Error{Kind: "invalid_websocket_template"}
			}
			if kind != 5 && kind != 6 && (len(header.Value) != 0 || header.Sensitive) {
				return result, &Error{Kind: "invalid_websocket_template"}
			}
			result.template[i] = native.WebSocketTemplateField{Kind: kind, Field: native.Field{Name: native.BorrowedString(header.Name), Value: native.BorrowedBytes(header.Value), Sensitive: boolean(header.Sensitive)}}
		}
		value.Template, value.TemplateCount = unsafe.Pointer(unsafe.SliceData(result.template)), uint64(len(result.template))
	}
	if options.Deflate != nil {
		policy := options.Deflate
		window, level := policy.WindowBits, uint8(6)
		if window == 0 {
			window = 15
		}
		if policy.Level != nil {
			level = *policy.Level
		}
		if window < 8 || window > 15 || level > 9 || len(policy.Parameters) > 4 {
			return result, &Error{Kind: "invalid_websocket_deflate"}
		}
		value.Deflate = &native.WebSocketDeflate{Window: uint64(window), Level: uint64(level)}
		if policy.CompressEmpty == nil || *policy.CompressEmpty {
			value.Deflate.Flags |= 2
		}
		if policy.Parameters != nil {
			value.Deflate.Flags |= 1
			seen := uint64(0)
			for _, parameter := range policy.Parameters {
				var kind uint64
				switch parameter.Kind {
				case "serverNoContextTakeover":
					kind = 1
				case "clientNoContextTakeover":
					kind = 2
				case "serverMaxWindowBits":
					kind = 3
				case "clientMaxWindowBits":
					kind = 4
				default:
					return result, &Error{Kind: "invalid_websocket_deflate"}
				}
				bits := parameter.Bits
				if seen&(1<<kind) != 0 || ((kind == 1 || kind == 2) && bits != 0) || (kind == 3 && (bits < 8 || bits > 15)) || (kind == 4 && bits != 0 && (bits < 8 || bits > 15)) {
					return result, &Error{Kind: "invalid_websocket_deflate"}
				}
				seen |= 1 << kind
				result.parameters = append(result.parameters, native.WebSocketDeflateParameter{Kind: kind, Bits: uint64(bits)})
			}
			value.Deflate.Parameters, value.Deflate.Count = unsafe.Pointer(unsafe.SliceData(result.parameters)), uint64(len(result.parameters))
		}
	}
	return result, nil
}
