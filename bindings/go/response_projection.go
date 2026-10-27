package phantom

import "github.com/bywayhq/phantom/bindings/go/internal/native"

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

func eventCompletion(event native.Event, fields []native.OutputField, hops []native.Hop, arena, data []byte) (completion, error) {
	result := completion{Operation: event.Operation, Error: nil, kind: event.Kind, part: event.Part}
	invalid := func() (completion, error) { return completion{}, &Error{Kind: "native_abi"} }
	if event.Operation == 0 || event.ArenaLength > uint64(len(arena)) || event.DataLength > uint64(len(data)) || event.FieldCount > uint64(len(fields)) || event.CodingCount > uint64(len(fields))-event.FieldCount || event.HopCount > uint64(len(hops)) {
		return invalid()
	}
	if err := nativeRecordError(event.Error); err != nil {
		result.Error = err.(*Error)
		return result, nil
	}
	arena = arena[:event.ArenaLength]
	slice := func(span native.Slice) ([]byte, error) {
		if span.Offset > uint64(len(arena)) || span.Length > uint64(len(arena))-span.Offset {
			return nil, &Error{Kind: "native_abi"}
		}
		return arena[span.Offset : span.Offset+span.Length], nil
	}
	text := func(span native.Slice) (string, error) { value, err := slice(span); return string(value), err }
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
