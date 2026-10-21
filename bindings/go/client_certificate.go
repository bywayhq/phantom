package phantom

import (
	"encoding/json"
	"runtime"
	"sync/atomic"
	"unicode/utf8"
)

// ClientCertificate owns a parsed leaf-first chain and matching unencrypted key.
// Do not copy an owner after use. Close releases it without invalidating clients
// already created from it. At most 64 certificate owners may be open per library.
type ClientCertificate struct{ id atomic.Uint64 }

func (*ClientCertificate) String() string   { return "phantom.ClientCertificate([redacted])" }
func (*ClientCertificate) GoString() string { return "phantom.ClientCertificate([redacted])" }

// ClientCertificateOrigin selects an identity for one HTTPS/WSS origin. Core URL
// normalization applies; the last mapping for a host and port wins. Other origins
// use Config.ClientCertificate. A certificate never authenticates outer proxy TLS.
type ClientCertificateOrigin struct {
	Origin      string
	Certificate *ClientCertificate
}

// ParseClientCertificatePEM parses a PEM chain and matching unencrypted PEM key.
// No file is opened. Callers must not mutate input during this synchronous call.
// Aggregate input is limited to the existing 8 MiB binary ABI; metadata to 64 KiB.
func ParseClientCertificatePEM(certificateChain, privateKey []byte) (*ClientCertificate, error) {
	return parseClientCertificate("pem", [][]byte{certificateChain}, privateKey)
}

// ParseClientCertificateDER parses one through 256 leaf-first DER certificates
// and a matching unencrypted PKCS#8 or traditional RSA/EC DER private key. The
// same 8 MiB aggregate bound and input ownership contract as PEM apply.
func ParseClientCertificateDER(certificateChain [][]byte, privateKey []byte) (*ClientCertificate, error) {
	if len(certificateChain) == 0 || len(certificateChain) > 256 {
		return nil, &Error{Kind: "client_certificate_invalid_chain_count"}
	}
	return parseClientCertificate("der", certificateChain, privateKey)
}

func parseClientCertificate(format string, chain [][]byte, key []byte) (*ClientCertificate, error) {
	total := len(key)
	if total > maxUpload {
		return nil, &Error{Kind: "input_limit"}
	}
	for _, item := range chain {
		if len(item) > maxUpload-total {
			return nil, &Error{Kind: "input_limit"}
		}
		total += len(item)
	}
	// Allocate once after the complete bound check, avoiding superseded key copies.
	payload := make([]byte, total)
	defer clear(payload)
	spans := make([]bodySpan, 0, len(chain))
	offset := 0
	for _, item := range chain {
		spans = append(spans, bodySpan{offset, len(item)})
		offset += copy(payload[offset:], item)
	}
	keySpan := bodySpan{offset, len(key)}
	copy(payload[offset:], key)
	value, err := dispatch(map[string]any{
		"kind": "parse_client_certificate", "format": format,
		"certificate_chain": spans, "private_key": keySpan,
	}, payload)
	if err != nil {
		return nil, err
	}
	var result struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(value, &result) != nil || result.ID == 0 {
		if result.ID != 0 {
			_ = control("release_client_certificate", "certificate", result.ID)
		}
		return nil, &Error{Kind: "native_abi"}
	}
	owner := &ClientCertificate{}
	owner.id.Store(result.ID)
	runtime.SetFinalizer(owner, func(certificate *ClientCertificate) { _ = certificate.Close() })
	return owner, nil
}

// Close releases this handle. Repeated calls, including on nil, do nothing.
// Native clients retain their own parsed identity; no private key is exported.
func (certificate *ClientCertificate) Close() error {
	if certificate == nil {
		return nil
	}
	id := certificate.id.Swap(0)
	if id == 0 {
		return nil
	}
	defer runtime.KeepAlive(certificate)
	if err := control("release_client_certificate", "certificate", id); err != nil {
		certificate.id.CompareAndSwap(0, id)
		return err
	}
	runtime.SetFinalizer(certificate, nil)
	return nil
}

type wireCertificateOrigin struct {
	Origin      string `json:"origin"`
	Certificate uint64 `json:"certificate"`
}

func certificatesWire(config Config) (*uint64, []wireCertificateOrigin, error) {
	if len(config.ClientCertificatesFor) > 256 {
		return nil, nil, &Error{Kind: "input_limit"}
	}
	total := 0
	for _, mapping := range config.ClientCertificatesFor {
		if !utf8.ValidString(mapping.Origin) {
			return nil, nil, &Error{Kind: "invalid_client_certificate_origin"}
		}
		if len(mapping.Origin) > 64*1024-total {
			return nil, nil, &Error{Kind: "input_limit"}
		}
		total += len(mapping.Origin)
		if mapping.Certificate == nil || mapping.Certificate.id.Load() == 0 {
			return nil, nil, &Error{Kind: "client_certificate_closed"}
		}
	}
	var id *uint64
	if config.ClientCertificate != nil {
		value := config.ClientCertificate.id.Load()
		if value == 0 {
			return nil, nil, &Error{Kind: "client_certificate_closed"}
		}
		id = &value
	}
	mappings := make([]wireCertificateOrigin, 0, len(config.ClientCertificatesFor))
	for _, mapping := range config.ClientCertificatesFor {
		value := mapping.Certificate.id.Load()
		if value == 0 {
			return nil, nil, &Error{Kind: "client_certificate_closed"}
		}
		mappings = append(mappings, wireCertificateOrigin{mapping.Origin, value})
	}
	return id, mappings, nil
}
