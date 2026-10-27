package phantom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// StreamingMultipart is an ordered one-shot core multipart encoding. Boundary
// is explicit; MaximumBytes includes all encoded contents, headers and delimiters.
// At most 1024 parts are accepted; a count rejection leaves readers caller-owned.
// Otherwise readers transfer to Do, which closes each exactly once, even on
// validation failure. Do not reuse readers or mutate parts during Do preparation.
// Read may run concurrently with Close; Close must unblock Read. A stalled custom
// Close cannot be forcibly interrupted. Use PreparedBody for replayable fields.
type StreamingMultipart struct {
	Boundary     string
	MaximumBytes uint64
	Parts        []MultipartPart
}

// MultipartReader streams a reader (including *os.File) without opening a file.
// It defaults to application/octet-stream. PrepareMultipart rejects readers;
// use Request.Multipart. Nil readers, including typed nils, are rejected by Do.
func MultipartReader(name string, source io.ReadCloser) MultipartPart {
	return MultipartPart{name: name, reader: &multipartSource{source: source}, streaming: true}
}

// ContentType returns core's exact header value, including boundary quoting.
// It does not read sources; place this field explicitly unless a profile slot does.
func (m StreamingMultipart) ContentType() (string, error) {
	if !utf8.ValidString(m.Boundary) || len(m.Boundary) > 70 {
		return "", &Error{Kind: "multipart_invalid_boundary"}
	}
	value, err := dispatch(map[string]any{"kind": "multipart_content_type", "boundary": m.Boundary}, nil)
	if err != nil {
		return "", err
	}
	var result struct {
		ContentType string `json:"content_type"`
	}
	if json.Unmarshal(value, &result) != nil || result.ContentType == "" {
		return "", &Error{Kind: "native_abi"}
	}
	return result.ContentType, nil
}

type multipartSource struct {
	source  io.ReadCloser
	once    sync.Once
	claimed atomic.Bool
}

func (s *multipartSource) close() error {
	var err error
	s.once.Do(func() { err = s.source.Close() })
	return err
}

type multipartLifetime struct {
	parts    []MultipartPart
	sources  []*multipartSource
	boundary string
	maximum  uint64
	invalid  bool
	oversize bool
}

// Check the count before capturing source custody. Comparable repeated reader
// identities share Close custody and are rejected before any Read.
func multipartUpload(m *StreamingMultipart) *uploadLifetime {
	group := &multipartLifetime{boundary: m.Boundary, maximum: m.MaximumBytes}
	if len(m.Parts) > 1024 {
		group.oversize = true
		return &uploadLifetime{multipart: group}
	}
	group.parts = append([]MultipartPart(nil), m.Parts...)
	seen := make(map[io.ReadCloser]*multipartSource)
	for _, part := range m.Parts {
		if !part.streaming {
			continue
		}
		if part.reader == nil || nilMultipartReader(part.reader.source) {
			group.invalid = true
			continue
		}
		if !part.reader.claimed.CompareAndSwap(false, true) {
			group.invalid = true
			continue
		}
		if reflect.TypeOf(part.reader.source).Comparable() {
			if source := seen[part.reader.source]; source != nil {
				group.invalid = true
				continue
			}
		}
		source := part.reader
		group.sources = append(group.sources, source)
		if reflect.TypeOf(part.reader.source).Comparable() {
			seen[part.reader.source] = source
		}
	}
	return &uploadLifetime{multipart: group}
}

func (m *multipartLifetime) close() error {
	var failure error
	for _, source := range m.sources {
		failure = errors.Join(failure, source.close())
	}
	return failure
}

func (m *multipartLifetime) prepare(ctx context.Context, client uint64, u *uploadLifetime) error {
	if m.oversize {
		return &Error{Kind: "multipart_too_many_parts"}
	}
	if m.invalid {
		return &Error{Kind: "invalid_multipart"}
	}
	if !utf8.ValidString(m.boundary) || len(m.boundary) > 70 {
		return &Error{Kind: "multipart_invalid_boundary"}
	}
	// Count and byte limits precede metadata copying and binary payload growth.
	size := len(m.boundary)
	for _, part := range m.parts {
		for _, value := range []*string{&part.name, part.filename, part.contentType} {
			if value == nil {
				continue
			}
			if !utf8.ValidString(*value) {
				return &Error{Kind: "invalid_multipart"}
			}
			if len(*value) > 4096 || len(*value) > 64*1024-size {
				return &Error{Kind: "input_limit"}
			}
			size += len(*value)
		}
	}
	type source struct {
		Kind string    `json:"kind"`
		Data *bodySpan `json:"data,omitempty"`
	}
	type field struct {
		Name        string  `json:"name"`
		Source      source  `json:"source"`
		Filename    *string `json:"filename,omitempty"`
		ContentType *string `json:"content_type,omitempty"`
	}
	wire := make([]field, 0, len(m.parts))
	var payload []byte
	for _, part := range m.parts {
		data := source{Kind: "reader"}
		if !part.streaming {
			var span bodySpan
			var err error
			if part.text != nil {
				if !utf8.ValidString(*part.text) {
					return &Error{Kind: "invalid_multipart"}
				}
				data.Kind = "text"
				span, err = appendBodyString(&payload, *part.text)
			} else {
				data.Kind = "bytes"
				span, err = appendBodyBytes(&payload, part.data)
			}
			if err != nil {
				return err
			}
			data.Data = &span
		}
		wire = append(wire, field{part.name, data, part.filename, part.contentType})
	}
	value, err := dispatch(map[string]any{"kind": "new_multipart", "client": client, "boundary": m.boundary, "maximum": m.maximum, "parts": wire}, payload)
	if err != nil {
		return err
	}
	var result struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(value, &result) != nil || result.ID == 0 {
		return &Error{Kind: "native_abi"}
	}
	u.id = result.ID
	u.ctx, u.cancel = context.WithCancel(ctx)
	// Native preparation now owns static fields; keep only source lifetimes.
	for i := range m.parts {
		m.parts[i].data = nil
		m.parts[i].text = nil
	}
	return nil
}

func (m *multipartLifetime) produce(u *uploadLifetime) {
	buffer := make([]byte, maxChunk)
	used := make(map[int]bool)
	for completed := 0; completed < len(m.sources); completed++ {
		var index int
		err := performSubmitted(u.ctx, func() (uint64, error) { return submitOperation(4, u.id, 0, nil) }, nil, func(event completion) error {
			result := struct{ Part int }{int(event.part)}
			if result.Part < 0 || result.Part >= len(m.parts) || !m.parts[result.Part].streaming || used[result.Part] || m.parts[result.Part].reader != m.sources[completed] {
				return &Error{Kind: "native_abi"}
			}
			index = result.Part
			return nil
		})
		if err != nil {
			u.close()
			return
		}
		used[index] = true
		// Source order is wire order; only the demanded source is active.
		source := m.sources[completed]
		if !u.produceSource(source.source, nil, buffer, source.close) {
			u.close()
			return
		}
	}
	// Child EOF is not whole multipart EOF: core still sends closing framing.
	// The terminal watcher owns final request cleanup, including early replies.
}

func multipartConflict(request Request) bool {
	return request.Multipart != nil && (request.Body != nil || request.Upload != nil || request.UploadLength != nil || request.PreparedBody != nil)
}

func nilMultipartReader(source io.ReadCloser) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}
