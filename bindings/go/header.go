package phantom

// Header retains one field's position, name and byte value. Duplicate names work.
type Header struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
	// Sensitive requests never-indexed H2/H3 encoding, subject to the profile's
	// cookie-crumb policy. On responses it reports the retained wire marker.
	// HTTP/1 field bytes are unchanged.
	Sensitive bool `json:"sensitive,omitempty"`
}
