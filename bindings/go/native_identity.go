package phantom

import (
	"encoding/json"
	"sync"
)

type identityCheck struct {
	once sync.Once
	err  error
}

var loadedIdentity identityCheck

func ensureNativeIdentity() error { return loadedIdentity.check(nativeDispatch) }

func (check *identityCheck) check(call func([]byte, []byte, []byte) (int, error)) error {
	check.once.Do(func() {
		output := scratch.Get().([]byte)
		defer scratch.Put(output)
		length, err := call([]byte(`{"kind":"identity"}`), nil, output)
		if err != nil {
			check.err = err
			return
		}
		var response reply
		if length <= 0 || length > len(output) || json.Unmarshal(output[:length], &response) != nil {
			check.err = &Error{Kind: "native_abi"}
			return
		}
		var identity struct {
			ABI     uint64 `json:"abi"`
			Version string `json:"version"`
		}
		if response.Error != nil {
			// An older library can export the ABI symbols but lack this command.
			check.err = &Error{Kind: "native_abi_mismatch"}
		} else if json.Unmarshal(response.Value, &identity) != nil || identity.Version == "" {
			check.err = &Error{Kind: "native_abi"}
		} else if identity.ABI != nativeABIVersion {
			check.err = &Error{Kind: "native_abi_mismatch"}
		} else if identity.Version != nativePackageVersion {
			check.err = &Error{Kind: "native_version_mismatch"}
		}
	})
	return check.err
}
