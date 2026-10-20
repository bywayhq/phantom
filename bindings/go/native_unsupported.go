//go:build (!windows && !linux && !darwin) || ((linux || darwin) && !cgo) || (windows && !amd64)

package phantom

func nativeDispatch([]byte, []byte, []byte) (int, error) {
	return 0, &Error{Kind: "unsupported_platform"}
}
func nativeWait([]byte, []byte) (int, error) { return 0, &Error{Kind: "unsupported_platform"} }
func nativeProfile([]byte, []byte, []byte, []byte) (int, error) {
	return 0, &Error{Kind: "unsupported_platform"}
}
