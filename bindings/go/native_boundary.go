package phantom

import "github.com/bywayhq/phantom/bindings/go/internal/native"

func ensureNativeIdentity() error {
	return nativeBoundaryError(native.EnsureIdentity(nativeABIVersion, nativePackageVersion))
}

func nativeDispatch(command, body, output []byte) (int, error) {
	length, err := native.Dispatch(command, body, output)
	return length, nativeBoundaryError(err)
}

func nativeProfile(command, document, metadata, output []byte) (int, error) {
	length, err := native.Profile(command, document, metadata, output)
	return length, nativeBoundaryError(err)
}

func nativeSession(command, key, ciphertext, metadata, output []byte) (int, error) {
	length, err := native.Session(command, key, ciphertext, metadata, output)
	return length, nativeBoundaryError(err)
}

func nativeSubmit(request *native.Request, body []byte, reply *native.Reply) error {
	return nativeBoundaryError(native.Submit(request, body, reply))
}

func nativeOperation(kind, id, argument uint64, data []byte, reply *native.Reply) error {
	return nativeBoundaryError(native.Operation(kind, id, argument, data, reply))
}

func nativeWaitEvent(event *native.Event, fields []native.OutputField, hops []native.Hop, arena, data []byte) error {
	return nativeBoundaryError(native.WaitEvent(event, fields, hops, arena, data))
}

func loadSSE() error {
	if err := ensureNativeIdentity(); err != nil {
		return err
	}
	return nativeBoundaryError(native.LoadSSE())
}

func nativeSSESubmit(request *native.Request, body []byte, limits SSELimits, reply *native.Reply) error {
	if err := ensureNativeIdentity(); err != nil {
		return err
	}
	return nativeBoundaryError(native.SSESubmit(request, body, uint64(limits.MaxLineBytes), uint64(limits.MaxEventBytes), reply))
}

func nativeSSENext(body uint64, reply *native.Reply) error {
	if err := ensureNativeIdentity(); err != nil {
		return err
	}
	return nativeBoundaryError(native.SSENext(body, reply))
}

func submitOperation(kind, id, argument uint64, data []byte) (uint64, error) {
	if err := ensureNativeIdentity(); err != nil {
		return 0, err
	}
	var result native.Reply
	if err := nativeOperation(kind, id, argument, data, &result); err != nil {
		return 0, err
	}
	return result.Operation, nativeRecordError(result.Error)
}
