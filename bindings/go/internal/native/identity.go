package native

import (
	"encoding/json"
	"sync"
)

type identityCheck struct {
	once sync.Once
	err  error
}

var loadedIdentity identityCheck

// EnsureIdentity checks the facade's package version and ABI before first use.
// The loaded runtime and this decision remain fixed for the process lifetime.
func EnsureIdentity(expectedABI uint64, expectedVersion string) error {
	return loadedIdentity.check(Dispatch, expectedABI, expectedVersion)
}

func (check *identityCheck) check(call func([]byte, []byte, []byte) (int, error), expectedABI uint64, expectedVersion string) error {
	check.once.Do(func() {
		output := make([]byte, 256*1024)
		length, err := call([]byte(`{"kind":"identity"}`), nil, output)
		if err != nil {
			check.err = err
			return
		}
		var response struct {
			Value json.RawMessage `json:"value"`
			Error *Failure        `json:"error"`
		}
		if length <= 0 || length > len(output) || json.Unmarshal(output[:length], &response) != nil {
			check.err = &Failure{Kind: "native_abi"}
			return
		}
		var identity struct {
			ABI     uint64 `json:"abi"`
			Version string `json:"version"`
		}
		if response.Error != nil {
			// An older library can export the ABI symbols but lack this command.
			check.err = &Failure{Kind: "native_abi_mismatch"}
		} else if json.Unmarshal(response.Value, &identity) != nil || identity.Version == "" {
			check.err = &Failure{Kind: "native_abi"}
		} else if identity.ABI != expectedABI {
			check.err = &Failure{Kind: "native_abi_mismatch"}
		} else if identity.Version != expectedVersion {
			check.err = &Failure{Kind: "native_version_mismatch"}
		}
	})
	return check.err
}
