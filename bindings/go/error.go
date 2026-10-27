package phantom

import "github.com/bywayhq/phantom/bindings/go/internal/native"

// Error is a redacted native failure. HTTP statuses remain responses.
type Error struct {
	Kind         string `json:"kind"`
	Protocol     string `json:"protocol"`
	TimeoutPhase string `json:"timeout_phase"`
	// Field is the canonical setting path for a profile import/export error.
	Field string `json:"field"`
	cause error
}

func (e *Error) Error() string { return "phantom: " + e.Kind }
func (e *Error) Timeout() bool { return e.Kind == "timeout" }
func (e *Error) Unwrap() error { return e.cause }

func nativeBoundaryError(err error) error {
	if failure, ok := err.(*native.Failure); ok {
		return &Error{
			Kind: failure.Kind, Protocol: failure.Protocol,
			TimeoutPhase: failure.TimeoutPhase, Field: failure.Field,
			cause: nativeBoundaryError(failure.Cause),
		}
	}
	return err
}

func nativeRecordError(value native.ErrorRecord) error {
	return nativeBoundaryError(value.Err())
}
