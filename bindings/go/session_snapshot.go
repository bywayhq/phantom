package phantom

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
)

const maxSessionSnapshot = 32 * 1024 * 1024

// SessionRoute identifies a request-only ticket route accepted during restore.
// Its zero value is direct. Proxy and credentials follow Config's route rules.
type SessionRoute struct {
	Proxy            string            `json:"proxy,omitempty"`
	ProxyCredentials *ProxyCredentials `json:"proxy_credentials,omitempty"`
}

func (SessionRoute) String() string   { return "phantom.SessionRoute([redacted])" }
func (SessionRoute) GoString() string { return "phantom.SessionRoute([redacted])" }

// SessionSnapshotError preserves a core checkpoint error kind. Unwrap exposes
// the redacted native Error; neither value contains a key or ciphertext.
type SessionSnapshotError struct {
	Kind   string
	native *Error
}

func (e *SessionSnapshotError) Error() string { return "phantom session snapshot: " + e.Kind }
func (e *SessionSnapshotError) Unwrap() error { return e.native }

func snapshotError(kind string) *SessionSnapshotError {
	return &SessionSnapshotError{Kind: kind, native: &Error{Kind: "session_snapshot_" + kind}}
}

func sessionContext(ctx context.Context, c *Client) error {
	if ctx == nil {
		return &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || c.id.Load() == 0 {
		return &Error{Kind: "client_closed"}
	}
	return nil
}

func sessionCall(ctx context.Context, command any, key, ciphertext, output []byte) (json.RawMessage, error) {
	if len(key) > 32 || len(ciphertext) > maxSessionSnapshot || len(output) > maxSessionSnapshot {
		return nil, snapshotError("too_large")
	}
	input, err := json.Marshal(command)
	if err != nil || len(input) > 64*1024 {
		return nil, &Error{Kind: "input_limit"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	metadata := scratch.Get().([]byte)
	defer scratch.Put(metadata)
	length, err := nativeSession(input, key, ciphertext, metadata, output)
	if err != nil {
		return nil, err
	}
	var result reply
	if length <= 0 || length > len(metadata) || json.Unmarshal(metadata[:length], &result) != nil {
		return nil, &Error{Kind: "native_abi"}
	}
	if result.Error != nil {
		if kind, ok := strings.CutPrefix(result.Error.Kind, "session_snapshot_"); ok {
			return nil, &SessionSnapshotError{Kind: kind, native: result.Error}
		}
		return nil, result.Error
	}
	return result.Value, nil
}

// ExportSession exports supported state without consuming it. Supply a secret
// random 32-byte key. ctx is checked before/after native CPU calls; cancellation
// cannot preempt a call already running. No network or storage I/O occurs.
func (c *Client) ExportSession(ctx context.Context, key [32]byte) ([]byte, error) {
	defer clear(key[:])
	if err := sessionContext(ctx, c); err != nil {
		return nil, err
	}
	defer runtime.KeepAlive(c)
	value, err := sessionCall(ctx, map[string]any{"kind": "export", "client": c.id.Load()}, key[:], nil, nil)
	if err != nil {
		if cancelled := ctx.Err(); cancelled != nil {
			return nil, cancelled
		}
		return nil, err
	}
	return copySession(ctx, value)
}

// The prepared native operation owns one exact ciphertext until this handoff.
func copySession(ctx context.Context, value json.RawMessage) (output []byte, err error) {
	var result struct {
		Operation uint64 `json:"operation"`
		Length    int    `json:"length"`
	}
	if json.Unmarshal(value, &result) != nil || result.Operation == 0 {
		err := error(&Error{Kind: "native_abi"})
		if result.Operation != 0 {
			err = errors.Join(err, control("cancel", "operation", result.Operation))
		}
		return nil, err
	}
	defer func() {
		if cleanup := control("cancel", "operation", result.Operation); cleanup != nil {
			output = nil
			err = errors.Join(err, cleanup)
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if result.Length <= 0 || result.Length > maxSessionSnapshot {
		return nil, &Error{Kind: "native_abi"}
	}
	output = make([]byte, result.Length)
	value, err = sessionCall(ctx, map[string]any{"kind": "copy", "operation": result.Operation}, nil, nil, output)
	if cancelled := ctx.Err(); cancelled != nil {
		return nil, cancelled
	}
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

// RestoreSession uses this receiver's compatible configuration and returns a
// new independent client. Core expiry, capacity, route and trust checks apply;
// errors leave the receiver unchanged. Configuration is not deserialized.
// At most 256 receiving routes may be supplied.
// Keep snapshot unchanged until return. Cancellation cannot preempt CPU work;
// any restored owner is released before returning a context error.
func (c *Client) RestoreSession(ctx context.Context, snapshot []byte, key [32]byte, receivingRoutes []SessionRoute) (*Client, error) {
	defer clear(key[:])
	if err := sessionContext(ctx, c); err != nil {
		return nil, err
	}
	defer runtime.KeepAlive(c)
	if len(snapshot) > maxSessionSnapshot {
		return nil, snapshotError("too_large")
	}
	// Core accepts at most 256 receiving routes. Check before constructing the
	// bounded command; sessionCall also applies the exact 64 KiB encoded limit.
	if len(receivingRoutes) > 256 {
		return nil, &Error{Kind: "input_limit"}
	}
	size := 0
	for _, route := range receivingRoutes {
		values := []string{route.Proxy}
		if route.ProxyCredentials != nil {
			values = append(values, route.ProxyCredentials.Username, route.ProxyCredentials.Password)
		}
		for _, value := range values {
			if len(value) > 64*1024-size {
				return nil, &Error{Kind: "input_limit"}
			}
			size += len(value)
		}
	}
	// Materialize the bounded wire command before borrowing the native buffers.
	if receivingRoutes == nil {
		receivingRoutes = []SessionRoute{}
	}
	value, err := sessionCall(ctx, map[string]any{"kind": "restore", "client": c.id.Load(), "receiving_routes": receivingRoutes}, key[:], snapshot, nil)
	if err != nil {
		if cancelled := ctx.Err(); cancelled != nil {
			return nil, cancelled
		}
		return nil, err
	}
	return acceptSession(ctx, value)
}

// A restored native owner is not public until this context check succeeds.
func acceptSession(ctx context.Context, value json.RawMessage) (*Client, error) {
	client, err := clientFromReply(value)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		cleanup := control("release_client", "client", client.id.Load())
		if cleanup == nil {
			client.id.Store(0)
			runtime.SetFinalizer(client, nil)
		}
		return nil, errors.Join(err, cleanup)
	}
	return client, nil
}
