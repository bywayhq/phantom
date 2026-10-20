package phantom

// DecodingMode selects encoded bytes or decoding of caller-advertised codings.
type DecodingMode string

const (
	// DecodingNone leaves response bytes encoded. This is the zero value.
	DecodingNone DecodingMode = ""
	// DecodingAdvertised decodes only codings advertised by the request.
	DecodingAdvertised DecodingMode = "advertised"
)

// ContentDecoding controls the remaining response stream, not collection helpers.
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
