package phantom

import "strconv"

// DecodingMode selects encoded bytes or decoding of caller-advertised codings.
type DecodingMode string

const (
	// DecodingNone leaves response bytes encoded. This is the zero value.
	DecodingNone DecodingMode = ""
	// DecodingAdvertised decodes only codings advertised by the request.
	DecodingAdvertised DecodingMode = "advertised"
)

// ContentDecoding controls the decoded response stream, not collection helpers.
// It never adds Accept-Encoding or changes received Content-Encoding/Length fields.
type ContentDecoding struct {
	Mode                DecodingMode
	MaximumDecodedBytes uint64
}

// AdvertisedDecoding applies an inclusive decoded-stream cap. Zero is a real cap.
func AdvertisedDecoding(maximum uint64) ContentDecoding {
	return ContentDecoding{Mode: DecodingAdvertised, MaximumDecodedBytes: maximum}
}

type wireContentDecoding struct {
	Mode                string  `json:"mode"`
	MaximumDecodedBytes *uint64 `json:"maximum_decoded_bytes,omitempty"`
}

func contentDecodingWire(value ContentDecoding) (wireContentDecoding, error) {
	switch value.Mode {
	case DecodingNone:
		if value.MaximumDecodedBytes == 0 {
			return wireContentDecoding{Mode: "none"}, nil
		}
	case DecodingAdvertised:
		maximum := value.MaximumDecodedBytes
		return wireContentDecoding{Mode: "advertised", MaximumDecodedBytes: &maximum}, nil
	}
	return wireContentDecoding{}, &Error{Kind: "invalid_content_decoding"}
}

// RedirectPolicy follows at most MaximumHops redirects. Zero follows none.
// The core owns method changes, byte-body replay and credential stripping.
type RedirectPolicy struct {
	MaximumHops uint64 `json:"maximum_hops"`
}

// RedirectHistory contains the first requested number of selected hops.
// Later hops are counted by OmittedHops. Bodies and headers are not retained.
type RedirectHistory struct {
	Entries     []RedirectHop `json:"entries"`
	OmittedHops uint64        `json:"omitted_hops"`
}

// RedirectHop describes one selected redirect, not a retry or browser replay.
// URLs may contain credentials or private queries; formatting omits them.
type RedirectHop struct {
	FromURL    string `json:"from_url"`
	ToURL      string `json:"to_url"`
	Method     string `json:"method"`
	NextMethod string `json:"next_method"`
	Status     int    `json:"status"`
}

func (history RedirectHistory) String() string {
	return "RedirectHistory{entries:" + strconv.Itoa(len(history.Entries)) + ", omitted:" + strconv.FormatUint(history.OmittedHops, 10) + "}"
}
func (history RedirectHistory) GoString() string { return history.String() }
func (hop RedirectHop) String() string           { return "RedirectHop{status:" + strconv.Itoa(hop.Status) + "}" }
func (hop RedirectHop) GoString() string         { return hop.String() }
