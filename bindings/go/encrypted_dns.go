package phantom

import (
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

// DNSOptions selects one native encrypted resolver. Nil uses the profile default.
// Configure it with *DNSOverHTTPS or *DNSOverTLS.
type DNSOptions interface{ encryptedDNS() }

// DNSAddressFamilies controls each complete lookup. The zero value queries both
// families concurrently and returns IPv6 addresses first.
type DNSAddressFamilies string

const (
	DNSDualStack DNSAddressFamilies = ""
	DNSIPv4Only  DNSAddressFamilies = "ipv4"
)

// DNSOverHTTPSMethod selects the HTTP method. The zero value uses POST.
type DNSOverHTTPSMethod string

const (
	DNSPost DNSOverHTTPSMethod = ""
	DNSGet  DNSOverHTTPSMethod = "get"
)

// DNSOverHTTPSWire selects existing DNS wire settings, independently of the
// endpoint's TLS/HTTP2 profile. The zero value uses standard DNS headers.
type DNSOverHTTPSWire string

const (
	DNSStandard    DNSOverHTTPSWire = ""
	DNSChromium154 DNSOverHTTPSWire = "chromium154"
)

// DNSOverHTTPS uses a verified, direct HTTP/2 endpoint without redirects or
// protocol fallback. Application proxies and trust settings do not apply to it.
// LookupTimeout and MaxConcurrent are required positive bounds.
type DNSOverHTTPS struct {
	Endpoint           string
	Bootstrap          []netip.Addr
	LookupTimeout      time.Duration
	MaxConcurrent      uint32
	Method             DNSOverHTTPSMethod
	Families           DNSAddressFamilies
	AdditionalRootsDER [][]byte
	Wire               DNSOverHTTPSWire
	QueryID            uint16
	// Nil retains the wire preset; zero disables padding; other values set its block size.
	PaddingBlock *uint16
}

// DNSOverTLS uses verified, direct TLS with ALPN dot and shared connections.
// Bootstrap addresses require an explicit nonzero port. LookupTimeout and
// MaxConcurrent are required; MaxConcurrent cannot exceed 32767.
type DNSOverTLS struct {
	ServerName         string
	Bootstrap          []netip.AddrPort
	LookupTimeout      time.Duration
	MaxConcurrent      uint32
	Families           DNSAddressFamilies
	AdditionalRootsDER [][]byte
	// Nil and zero disable padding; other values set its block size.
	PaddingBlock *uint16
}

func (*DNSOverHTTPS) encryptedDNS() {}
func (*DNSOverTLS) encryptedDNS()   {}

func (*DNSOverHTTPS) String() string   { return "phantom.DNSOverHTTPS([redacted])" }
func (*DNSOverHTTPS) GoString() string { return "phantom.DNSOverHTTPS([redacted])" }
func (*DNSOverTLS) String() string     { return "phantom.DNSOverTLS([redacted])" }
func (*DNSOverTLS) GoString() string   { return "phantom.DNSOverTLS([redacted])" }

type wireDNS struct {
	Kind               string     `json:"kind"`
	Endpoint           string     `json:"endpoint,omitempty"`
	ServerName         string     `json:"server_name,omitempty"`
	Bootstrap          []string   `json:"bootstrap"`
	TimeoutNS          uint64     `json:"timeout_ns"`
	MaxConcurrent      uint32     `json:"max_concurrent"`
	Families           string     `json:"families"`
	AdditionalRootsDER [][]uint16 `json:"additional_roots_der"`
	Method             string     `json:"method,omitempty"`
	Wire               string     `json:"wire,omitempty"`
	QueryID            *uint16    `json:"query_id,omitempty"`
	PaddingBlock       *uint16    `json:"padding_block,omitempty"`
}

func dnsInputSize(input DNSOptions, entries, bytes int) (int, error) {
	if input == nil {
		return 0, nil
	}
	var identity string
	var timeout time.Duration
	var maximum uint32
	var families DNSAddressFamilies
	var roots [][]byte
	var addresses int
	switch value := input.(type) {
	case *DNSOverHTTPS:
		if value == nil {
			return 0, &Error{Kind: "invalid_dns"}
		}
		identity, timeout, maximum, families, roots, addresses = value.Endpoint, value.LookupTimeout, value.MaxConcurrent, value.Families, value.AdditionalRootsDER, len(value.Bootstrap)
		if value.Method != DNSPost && value.Method != DNSGet {
			return 0, &Error{Kind: "invalid_dns_method"}
		}
		if value.Wire != DNSStandard && value.Wire != DNSChromium154 {
			return 0, &Error{Kind: "invalid_dns_wire"}
		}
	case *DNSOverTLS:
		if value == nil {
			return 0, &Error{Kind: "invalid_dns"}
		}
		identity, timeout, maximum, families, roots, addresses = value.ServerName, value.LookupTimeout, value.MaxConcurrent, value.Families, value.AdditionalRootsDER, len(value.Bootstrap)
		if maximum > 32767 {
			return 0, &Error{Kind: "invalid_dns_limits"}
		}
	default:
		return 0, &Error{Kind: "invalid_dns"}
	}
	if addresses == 0 {
		return 0, &Error{Kind: "invalid_dns_bootstrap"}
	}
	if addresses > entries || len(roots) > entries-addresses {
		return 0, &Error{Kind: "input_limit"}
	}
	if timeout <= 0 {
		return 0, &Error{Kind: "invalid_dns_timeout"}
	}
	if maximum == 0 {
		return 0, &Error{Kind: "invalid_dns_limits"}
	}
	if families != DNSDualStack && families != DNSIPv4Only {
		return 0, &Error{Kind: "invalid_dns_families"}
	}
	size := len(identity)
	if size > bytes {
		return 0, &Error{Kind: "input_limit"}
	}
	if identity == "" || !utf8.ValidString(identity) || strings.ContainsRune(identity, 0) {
		return 0, &Error{Kind: "invalid_dns_identity"}
	}
	addAddress := func(address netip.Addr, text string) error {
		if !address.IsValid() || address.Zone() != "" {
			return &Error{Kind: "invalid_dns_bootstrap"}
		}
		if len(text) > bytes-size {
			return &Error{Kind: "input_limit"}
		}
		size += len(text)
		return nil
	}
	switch value := input.(type) {
	case *DNSOverHTTPS:
		for _, address := range value.Bootstrap {
			if err := addAddress(address, address.String()); err != nil {
				return 0, err
			}
		}
	case *DNSOverTLS:
		for _, address := range value.Bootstrap {
			if !address.IsValid() || address.Port() == 0 {
				return 0, &Error{Kind: "invalid_dns_bootstrap"}
			}
			if err := addAddress(address.Addr(), address.String()); err != nil {
				return 0, err
			}
		}
	}
	for _, root := range roots {
		if len(root) > bytes-size {
			return 0, &Error{Kind: "input_limit"}
		}
		size += len(root)
	}
	return size, nil
}

// Called only after networkInputSize validates the complete configuration.
func dnsWire(input DNSOptions) *wireDNS {
	if input == nil {
		return nil
	}
	result := &wireDNS{Families: "dual"}
	var roots [][]byte
	var padding *uint16
	switch value := input.(type) {
	case *DNSOverHTTPS:
		result.Kind, result.Endpoint = "https", strings.Clone(value.Endpoint)
		result.TimeoutNS, result.MaxConcurrent = uint64(value.LookupTimeout), value.MaxConcurrent
		result.Method, result.Wire = "post", "standard"
		if value.Method == DNSGet {
			result.Method = "get"
		}
		if value.Wire == DNSChromium154 {
			result.Wire = "chromium154"
		}
		if value.Families == DNSIPv4Only {
			result.Families = "ipv4"
		}
		id := value.QueryID
		result.QueryID = &id
		result.Bootstrap = make([]string, len(value.Bootstrap))
		for index, address := range value.Bootstrap {
			result.Bootstrap[index] = address.String()
		}
		roots, padding = value.AdditionalRootsDER, value.PaddingBlock
	case *DNSOverTLS:
		result.Kind, result.ServerName = "tls", strings.Clone(value.ServerName)
		result.TimeoutNS, result.MaxConcurrent = uint64(value.LookupTimeout), value.MaxConcurrent
		if value.Families == DNSIPv4Only {
			result.Families = "ipv4"
		}
		result.Bootstrap = make([]string, len(value.Bootstrap))
		for index, address := range value.Bootstrap {
			result.Bootstrap[index] = address.String()
		}
		roots, padding = value.AdditionalRootsDER, value.PaddingBlock
	}
	result.AdditionalRootsDER = make([][]uint16, len(roots))
	for index, root := range roots {
		result.AdditionalRootsDER[index] = make([]uint16, len(root))
		for offset, value := range root {
			result.AdditionalRootsDER[index][offset] = uint16(value)
		}
	}
	if padding != nil {
		block := *padding
		result.PaddingBlock = &block
	}
	return result
}
