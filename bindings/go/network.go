package phantom

import (
	"net/netip"
	"slices"
	"unicode/utf8"
)

// NetworkOptions selects addresses without changing request hosts, TLS names or
// certificate verification. Nil Config.Network and an empty value use defaults.
// Overrides, their addresses and local addresses together allow 1024 entries;
// their UTF-8 representation and Interface share the 64 KiB config input limit.
type NetworkOptions struct {
	HostOverrides []HostOverride
	// LocalAddresses bind sockets to these addresses. The last of each family
	// wins; selecting only one family forbids an unbound fallback to the other.
	// Invalid and scoped (zone-bearing) addresses are rejected.
	LocalAddresses []netip.Addr
	// Interface binds outgoing sockets to this interface; empty leaves it unset.
	// Availability and permissions are checked by the operating system on connect.
	Interface string
}

// HostOverride retains ordered addresses for a name resolved by this client.
// Core normalizes names; the last duplicate wins. An empty Addresses slice
// deliberately fails resolution. Proxy-resolved targets are not overridden.
type HostOverride struct {
	Host      string
	Addresses []netip.Addr
}

type wireNetworkOptions struct {
	HostOverrides  []wireHostOverride `json:"host_overrides,omitempty"`
	LocalAddresses []netip.Addr       `json:"local_addresses,omitempty"`
	Interface      string             `json:"interface,omitempty"`
}

type wireHostOverride struct {
	Host      string       `json:"host"`
	Addresses []netip.Addr `json:"addresses"`
}

// Preflight the whole input before cloning slices or serializing addresses.
func networkInputSize(input *NetworkOptions) (int, error) {
	if input == nil {
		return 0, nil
	}
	entries := len(input.HostOverrides)
	if entries > 1024 || len(input.LocalAddresses) > 1024-entries {
		return 0, &Error{Kind: "input_limit"}
	}
	entries += len(input.LocalAddresses)
	for _, override := range input.HostOverrides {
		if len(override.Addresses) > 1024-entries {
			return 0, &Error{Kind: "input_limit"}
		}
		entries += len(override.Addresses)
	}
	size := 0
	text := func(value string) error {
		if len(value) > 64*1024-size {
			return &Error{Kind: "input_limit"}
		}
		if !utf8.ValidString(value) {
			return &Error{Kind: "invalid_network_options"}
		}
		size += len(value)
		return nil
	}
	address := func(value netip.Addr) error {
		if !value.IsValid() || value.Zone() != "" {
			return &Error{Kind: "invalid_network_address"}
		}
		return text(value.String())
	}
	if err := text(input.Interface); err != nil {
		return 0, err
	}
	for _, override := range input.HostOverrides {
		if err := text(override.Host); err != nil {
			return 0, err
		}
		for _, value := range override.Addresses {
			if err := address(value); err != nil {
				return 0, err
			}
		}
	}
	for _, value := range input.LocalAddresses {
		if err := address(value); err != nil {
			return 0, err
		}
	}
	return size, nil
}

func networkWire(input *NetworkOptions) *wireNetworkOptions {
	if input == nil {
		return nil
	}
	result := &wireNetworkOptions{Interface: input.Interface,
		LocalAddresses: slices.Clone(input.LocalAddresses),
		HostOverrides:  make([]wireHostOverride, len(input.HostOverrides))}
	for index, override := range input.HostOverrides {
		// An empty address list is a meaningful override, so encode [] not null.
		addresses := make([]netip.Addr, len(override.Addresses))
		copy(addresses, override.Addresses)
		result.HostOverrides[index] = wireHostOverride{Host: override.Host, Addresses: addresses}
	}
	return result
}
