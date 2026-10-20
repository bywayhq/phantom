package phantom

import (
	"bytes"
	"encoding/json"
	"runtime"
	"sync/atomic"
)

const maxProfileDocument = 16 * 1024 * 1024

// Profile owns immutable native settings. Do not copy a Profile after use.
// Close releases this owner; clients already created from it remain valid.
type Profile struct {
	id        atomic.Uint64
	catalogID string
}

func (*Profile) String() string   { return "phantom.Profile([redacted])" }
func (*Profile) GoString() string { return "phantom.Profile([redacted])" }

// NewCatalogProfile instantiates an exact catalog identifier. An empty context
// attaches no template; a named context attaches navigation, fetch,
// fetchNoStore or fetchUpload. Client Config.Context still selects how it is used.
func NewCatalogProfile(identifier, context string) (*Profile, error) {
	if len(identifier) > 64*1024 || len(context) > 64*1024-len(identifier) {
		return nil, &Error{Kind: "input_limit"}
	}
	return newProfile(map[string]any{"kind": "catalog", "identifier": identifier, "context": optionalString(context)}, nil)
}

// ImportProfileJSON validates complete custom-profile JSON using the Rust core.
// It retains supported settings and ordering, but assigns no catalog identity or
// browser evidence. Documents are limited to 16 MiB plus the core's structural bounds.
func ImportProfileJSON(document []byte) (*Profile, error) {
	return newProfile(map[string]any{"kind": "import"}, document)
}

// ImportedProfile owns custom settings and reports their sources. Close Profile
// when finished. Field paths describe supplied observations or retained base
// settings; neither the result nor its reports establish browser identity.
type ImportedProfile struct {
	Profile            *Profile
	ObservedFields     []string
	SupplementedFields []string
}

// JA4RawFormat selects the ordering carried by a raw JA4 description.
type JA4RawFormat string

const (
	// JA4Sorted verifies membership and retains the explicit base's ordering.
	JA4Sorted JA4RawFormat = "sorted"
	// JA4Original applies the supplied cipher and extension ordering.
	JA4Original JA4RawFormat = "original"
)

// ImportJA3Profile imports a raw five-section JA3 string, not its hash. Missing
// settings come from base; a successful projection is not an exact browser claim.
func ImportJA3Profile(description string, base *Profile) (*ImportedProfile, error) {
	return importProfileText("import_ja3", description, base, nil)
}

// ImportClientHelloProfile imports a complete TCP TLS handshake including its
// four-byte handshake header, without a TLS record header. Captured randoms,
// keys, session IDs and SNI are not stored. Missing settings come from base.
func ImportClientHelloProfile(handshake []byte, base *Profile) (*ImportedProfile, error) {
	return importProfileObservation("import_client_hello", handshake, base, nil)
}

// ImportAkamaiProfile imports ordered HTTP/2 settings, connection window and
// pseudo-header order. Other settings come from the explicit base profile.
func ImportAkamaiProfile(description string, base *Profile) (*ImportedProfile, error) {
	return importProfileText("import_akamai", description, base, nil)
}

// ImportJA4Profile imports raw TCP JA4 with explicit ordering and base settings.
// Hashed values cannot reconstruct settings and are rejected.
func ImportJA4Profile(description string, format JA4RawFormat, base *Profile) (*ImportedProfile, error) {
	return importProfileText("import_ja4", description, base, &format)
}

// ImportQUICTransportProfile imports TLS extension 57 payload bytes, without TLS
// framing or a QUIC packet. Connection IDs are generated afresh; unsupported
// parameters fail rather than being ignored. Other settings come from base.
func ImportQUICTransportProfile(parameters []byte, base *Profile) (*ImportedProfile, error) {
	return importProfileObservation("import_quic_transport", parameters, base, nil)
}

func importProfileText(kind, input string, base *Profile, format *JA4RawFormat) (*ImportedProfile, error) {
	if len(input) > maxProfileDocument {
		return nil, &Error{Kind: "input_limit"}
	}
	return importProfileObservation(kind, []byte(input), base, format)
}

func importProfileObservation(kind string, input []byte, base *Profile, format *JA4RawFormat) (*ImportedProfile, error) {
	if base == nil {
		return nil, &Error{Kind: "profile_closed"}
	}
	id := base.id.Load()
	if id == 0 {
		return nil, &Error{Kind: "profile_closed"}
	}
	defer runtime.KeepAlive(base)
	command := map[string]any{"kind": kind, "base": id}
	if format != nil {
		command["format"] = *format
	}
	value, err := profileCall(command, input, nil)
	if err != nil {
		return nil, err
	}
	var result profileReply
	if json.Unmarshal(value, &result) != nil || result.ID == 0 || result.CatalogID != "" || result.ObservedFields == nil || result.SupplementedFields == nil {
		return nil, &Error{Kind: "native_abi"}
	}
	return &ImportedProfile{result.owner(), result.ObservedFields, result.SupplementedFields}, nil
}

func optionalString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func newProfile(command any, document []byte) (*Profile, error) {
	value, err := profileCall(command, document, nil)
	if err != nil {
		return nil, err
	}
	var result profileReply
	if json.Unmarshal(value, &result) != nil || result.ID == 0 {
		return nil, &Error{Kind: "native_abi"}
	}
	return result.owner(), nil
}

type profileReply struct {
	ID                 uint64   `json:"id"`
	CatalogID          string   `json:"catalog_id"`
	ObservedFields     []string `json:"observed_fields"`
	SupplementedFields []string `json:"supplemented_fields"`
}

func (result profileReply) owner() *Profile {
	profile := &Profile{catalogID: result.CatalogID}
	profile.id.Store(result.ID)
	runtime.SetFinalizer(profile, func(owner *Profile) { _ = owner.Close() })
	return profile
}

func profileCall(command any, document, output []byte) (json.RawMessage, error) {
	if len(document) > maxProfileDocument || len(output) > maxProfileDocument {
		return nil, &Error{Kind: "input_limit"}
	}
	input, err := json.Marshal(command)
	if err != nil || len(input) > 64*1024 {
		return nil, &Error{Kind: "input_limit"}
	}
	if err := ensureNativeIdentity(); err != nil {
		return nil, err
	}
	metadata := scratch.Get().([]byte)
	defer scratch.Put(metadata)
	length, err := nativeProfile(input, document, metadata, output)
	if err != nil {
		return nil, err
	}
	var result reply
	if length <= 0 || length > len(metadata) || json.Unmarshal(metadata[:length], &result) != nil {
		return nil, &Error{Kind: "native_abi"}
	}
	if result.Error != nil {
		return nil, result.Error
	}
	return result.Value, nil
}

// CatalogID returns the exact identifier, or empty for every imported profile.
func (p *Profile) CatalogID() string {
	if p == nil {
		return ""
	}
	return p.catalogID
}

// ExportJSON returns a fresh editable complete document, including literal header
// values. Treat it as potentially sensitive. Export does not change live clients.
func (p *Profile) ExportJSON() ([]byte, error) {
	if p == nil || p.id.Load() == 0 {
		return nil, &Error{Kind: "profile_closed"}
	}
	command := map[string]any{"kind": "export", "profile": p.id.Load()}
	defer runtime.KeepAlive(p)
	value, err := profileCall(command, nil, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Length int `json:"length"`
	}
	if json.Unmarshal(value, &result) != nil || result.Length <= 0 || result.Length > maxProfileDocument {
		return nil, &Error{Kind: "native_abi"}
	}
	output := make([]byte, result.Length)
	value, err = profileCall(command, nil, output)
	if err != nil {
		return nil, err
	}
	var copied struct {
		Length int `json:"length"`
	}
	if json.Unmarshal(value, &copied) != nil || copied.Length != len(output) {
		return nil, &Error{Kind: "native_abi"}
	}
	return output, nil
}

// Describe returns an independent editable document. Numbers use json.Number,
// preserving u64 settings exactly. Marshal your edits and call ImportProfileJSON
// to validate them; Go does not duplicate the native settings schema.
func (p *Profile) Describe() (map[string]any, error) {
	document, err := p.ExportJSON()
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var result map[string]any
	if decoder.Decode(&result) != nil || result == nil {
		return nil, &Error{Kind: "native_abi"}
	}
	return result, nil
}

// Close releases this owner. It is idempotent; a concurrent use either acquires
// the immutable settings or returns profile_closed. No existing client is closed.
func (p *Profile) Close() error {
	if p == nil {
		return nil
	}
	id := p.id.Swap(0)
	if id == 0 {
		return nil
	}
	runtime.SetFinalizer(p, nil)
	_, err := profileCall(map[string]any{"kind": "release", "profile": id}, nil, nil)
	runtime.KeepAlive(p)
	return err
}
