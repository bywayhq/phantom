//go:build (!windows && !linux && !darwin) || (!amd64 && !arm64) || (windows && !amd64)

package phantom

func nativeDispatch([]byte, []byte, []byte) (int, error) {
	return 0, &Error{Kind: "unsupported_platform"}
}
func nativeProfile([]byte, []byte, []byte, []byte) (int, error) {
	return 0, &Error{Kind: "unsupported_platform"}
}
func nativeSession([]byte, []byte, []byte, []byte, []byte) (int, error) {
	return 0, &Error{Kind: "unsupported_platform"}
}

func nativeSubmit(*nativeRequest, []byte, *nativeReply) error {
	return &Error{Kind: "unsupported_platform"}
}
func nativeOperation(uint64, uint64, uint64, []byte, *nativeReply) error {
	return &Error{Kind: "unsupported_platform"}
}
func nativeWaitEvent(*nativeEvent, []nativeOutputField, []nativeHop, []byte, []byte) error {
	return &Error{Kind: "unsupported_platform"}
}
func loadSSE() error { return &Error{Kind: "unsupported_platform"} }
func nativeSSESubmit(*nativeRequest, []byte, SSELimits, *nativeReply) error {
	return &Error{Kind: "unsupported_platform"}
}
func nativeSSENext(uint64, *nativeReply) error {
	return &Error{Kind: "unsupported_platform"}
}
func nativeSSEResult(uint64, *nativeSSEEvent, []byte) error {
	return &Error{Kind: "unsupported_platform"}
}
