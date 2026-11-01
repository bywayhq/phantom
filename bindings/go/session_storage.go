package phantom

import (
	"context"
	"unicode"
	"unicode/utf8"
)

// SessionStore stores encrypted checkpoints, never keys or plaintext state.
// Load must bound reads to 32 MiB before allocating/collecting a complete object.
// A nil slice means absence; read/size/permission failures must return errors.
// Methods must honor ctx and release their operation's resources on cancellation.
// The backend owns admission, write ordering, atomicity and durability.
type SessionStore interface {
	Load(ctx context.Context, name string) ([]byte, error)
	Save(ctx context.Context, name string, snapshot []byte) error
}

// SessionStorageError redacts names and backend messages. Unwrap deliberately
// exposes the original backend error; checkpoint and context errors stay typed.
type SessionStorageError struct {
	Kind  string
	cause error
}

func (e *SessionStorageError) Error() string { return "phantom session storage: " + e.Kind }
func (e *SessionStorageError) Unwrap() error { return e.cause }

func storageInput(ctx context.Context, store SessionStore, name string) error {
	if name == "" || len(name) > 256 || !utf8.ValidString(name) {
		return &SessionStorageError{Kind: "invalid_name"}
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return &SessionStorageError{Kind: "invalid_name"}
		}
	}
	if ctx == nil {
		return &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return &SessionStorageError{Kind: "invalid_store"}
	}
	return nil
}

// SaveSession exports state and saves only encrypted bytes through store.
// The same ctx covers encoding and storage; no worker or goroutine is spawned.
// Already-running CPU work and a blocking backend cannot be preempted. A late
// completion returns ctx.Err; cancellation cannot undo an accepted external write.
func (c *Client) SaveSession(ctx context.Context, store SessionStore, name string, key [32]byte) error {
	defer clear(key[:])
	if err := storageInput(ctx, store, name); err != nil {
		return err
	}
	snapshot, err := c.ExportSession(ctx, key)
	if err != nil {
		return err
	}
	err = store.Save(ctx, name, snapshot)
	if cancelled := ctx.Err(); cancelled != nil {
		return cancelled
	}
	if err != nil {
		return &SessionStorageError{Kind: "backend", cause: err}
	}
	return nil
}

// LoadSession returns nil only for absence. It restores independent pools using
// the receiver's configuration and the existing receiving-route restrictions.
// The receiver is unchanged on success/failure; late cancelled native owners
// follow RestoreSession's cleanup. Backend calls must honor the same ctx.
func (c *Client) LoadSession(ctx context.Context, store SessionStore, name string, key [32]byte, receivingRoutes []SessionRoute) (*Client, error) {
	defer clear(key[:])
	if err := storageInput(ctx, store, name); err != nil {
		return nil, err
	}
	if err := sessionContext(ctx, c); err != nil {
		return nil, err
	}
	snapshot, err := store.Load(ctx, name)
	if cancelled := ctx.Err(); cancelled != nil {
		return nil, cancelled
	}
	if err != nil {
		return nil, &SessionStorageError{Kind: "backend", cause: err}
	}
	if snapshot == nil {
		return nil, nil
	}
	if len(snapshot) > maxSessionSnapshot {
		return nil, snapshotError("too_large")
	}
	return c.RestoreSession(ctx, snapshot, key, receivingRoutes)
}
