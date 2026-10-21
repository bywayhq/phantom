package phantom

import (
	"encoding/json"
	"runtime"
	"sync/atomic"
	"unicode/utf8"
)

// FormField is one UTF-8 field. Its position and duplicate names are retained.
type FormField struct{ Name, Value string }

// MultipartPart is an ordered text, byte or streaming reader field. Byte slices
// are borrowed until PrepareMultipart or Do preparation returns. PrepareMultipart
// rejects readers without taking custody; Request.Multipart takes their custody.
type MultipartPart struct {
	name        string
	text        *string
	data        []byte
	filename    *string
	contentType *string
	reader      *multipartSource
	streaming   bool
}

// MultipartText creates a field whose line endings are normalized to CRLF.
func MultipartText(name, value string) MultipartPart {
	return MultipartPart{name: name, text: &value}
}

// MultipartBytes creates a byte-exact field with application/octet-stream type.
func MultipartBytes(name string, value []byte) MultipartPart {
	return MultipartPart{name: name, data: value}
}

// WithFilename returns a part with an explicit filename; no file is opened.
func (p MultipartPart) WithFilename(value string) MultipartPart {
	p.filename = &value
	return p
}

// WithContentType returns a part with an explicit token/token media type.
// Invalid syntax is reported during preparation without echoing the value.
func (p MultipartPart) WithContentType(value string) MultipartPart {
	p.contentType = &value
	return p
}

// PreparedBody retains native replayable bytes and their content type. It is
// safe for concurrent requests. Do not copy it after first use. Close releases
// its handle without affecting already attached requests. At most 64 prepared
// owners may be open in one native library; Close releases that capacity.
type PreparedBody struct {
	id          atomic.Uint64
	length      uint64
	contentType string
}

// PrepareForm encodes ordered fields using the Rust form encoder. Spaces become
// +, literal + becomes %2B, and empty fields remain. maximumBytes bounds encoded
// bytes. Go buffered bodies also retain their existing 8 MiB bound; metadata
// commands allow 64 KiB. No request or network attempt is made.
func PrepareForm(fields []FormField, maximumBytes uint64) (*PreparedBody, error) {
	if len(fields) > 64*1024/2 {
		return nil, &Error{Kind: "input_limit"}
	}
	type field struct {
		Name  bodySpan `json:"name"`
		Value bodySpan `json:"value"`
	}
	payload := []byte{}
	wire := make([]field, 0, len(fields))
	for _, entry := range fields {
		if !utf8.ValidString(entry.Name) || !utf8.ValidString(entry.Value) {
			return nil, &Error{Kind: "invalid_prepared_body"}
		}
		name, err := appendBodyString(&payload, entry.Name)
		if err != nil {
			return nil, err
		}
		value, err := appendBodyString(&payload, entry.Value)
		if err != nil {
			return nil, err
		}
		wire = append(wire, field{name, value})
	}
	return prepareBody(map[string]any{"encoding": "form", "fields": wire}, payload, maximumBytes)
}

// PrepareMultipart uses Rust's multipart encoder with an explicit boundary of
// 1–70 ASCII boundary characters and at most 1024 parts. maximumBytes includes
// framing. Boundary collisions and invalid metadata produce precise errors.
// Body bytes are capped at 8 MiB and metadata commands at 64 KiB. Preparation
// copies the result into native ownership; later source mutations are harmless.
func PrepareMultipart(parts []MultipartPart, boundary string, maximumBytes uint64) (*PreparedBody, error) {
	for _, part := range parts {
		if part.streaming {
			return nil, &Error{Kind: "invalid_prepared_body"}
		}
	}
	if len(parts) > 1024 {
		return nil, &Error{Kind: "prepared_body_too_many_parts"}
	}
	if len(boundary) > 70 || !utf8.ValidString(boundary) {
		return nil, &Error{Kind: "prepared_body_invalid_boundary"}
	}
	type part struct {
		Kind        string   `json:"kind"`
		Name        string   `json:"name"`
		Data        bodySpan `json:"data"`
		Filename    *string  `json:"filename,omitempty"`
		ContentType *string  `json:"content_type,omitempty"`
	}
	payload := []byte{}
	wire := make([]part, 0, len(parts))
	metadata := len(boundary)
	for _, entry := range parts {
		for _, value := range []*string{&entry.name, entry.filename, entry.contentType} {
			if value == nil {
				continue
			}
			if !utf8.ValidString(*value) {
				return nil, &Error{Kind: "invalid_prepared_body"}
			}
			if len(*value) > 4096 {
				return nil, &Error{Kind: "prepared_body_too_large"}
			}
			if len(*value) > 64*1024-metadata {
				return nil, &Error{Kind: "input_limit"}
			}
			metadata += len(*value)
		}
		var span bodySpan
		var err error
		kind := "bytes"
		if entry.text != nil {
			if !utf8.ValidString(*entry.text) {
				return nil, &Error{Kind: "invalid_prepared_body"}
			}
			kind = "text"
			span, err = appendBodyString(&payload, *entry.text)
		} else {
			span, err = appendBodyBytes(&payload, entry.data)
		}
		if err != nil {
			return nil, err
		}
		wire = append(wire, part{kind, entry.name, span, entry.filename, entry.contentType})
	}
	return prepareBody(map[string]any{"encoding": "multipart", "boundary": boundary, "parts": wire}, payload, maximumBytes)
}

// Len returns the encoded byte count, including multipart framing.
func (p *PreparedBody) Len() uint64 {
	if p == nil {
		return 0
	}
	return p.length
}

// ContentType returns the exact field value to place at your chosen position,
// unless the selected request template already declares a Content-Type slot.
func (p *PreparedBody) ContentType() string {
	if p == nil {
		return ""
	}
	return p.contentType
}

// Close releases this owner. Repeated calls, including on nil, do nothing.
func (p *PreparedBody) Close() error {
	if p == nil {
		return nil
	}
	id := p.id.Swap(0)
	if id == 0 {
		return nil
	}
	runtime.SetFinalizer(p, nil)
	return control("release_prepared_body", "prepared_body", id)
}

type bodySpan struct {
	Offset int `json:"offset"`
	Length int `json:"length"`
}

func appendBodyString(payload *[]byte, value string) (bodySpan, error) {
	if len(value) > maxUpload-len(*payload) {
		return bodySpan{}, &Error{Kind: "input_limit"}
	}
	span := bodySpan{len(*payload), len(value)}
	*payload = append(*payload, value...)
	return span, nil
}

func appendBodyBytes(payload *[]byte, value []byte) (bodySpan, error) {
	if len(value) > maxUpload-len(*payload) {
		return bodySpan{}, &Error{Kind: "input_limit"}
	}
	span := bodySpan{len(*payload), len(value)}
	*payload = append(*payload, value...)
	return span, nil
}

func prepareBody(encoding map[string]any, payload []byte, maximum uint64) (*PreparedBody, error) {
	// Narrow against the existing buffered-body bound before crossing usize ABIs.
	if maximum > maxUpload {
		maximum = maxUpload
	}
	value, err := dispatch(map[string]any{"kind": "prepare_body", "encoding": encoding, "maximum": maximum}, payload)
	if err != nil {
		return nil, err
	}
	var result struct {
		ID          uint64  `json:"id"`
		Length      *uint64 `json:"length"`
		ContentType string  `json:"content_type"`
	}
	if json.Unmarshal(value, &result) != nil || result.ID == 0 || result.Length == nil || *result.Length > uint64(maxUpload) || result.ContentType == "" {
		return nil, &Error{Kind: "native_abi"}
	}
	body := &PreparedBody{length: *result.Length, contentType: result.ContentType}
	body.id.Store(result.ID)
	runtime.SetFinalizer(body, func(owner *PreparedBody) {
		// Finalizers cannot report release errors; callers can observe them via Close.
		_ = owner.Close()
	})
	return body, nil
}
