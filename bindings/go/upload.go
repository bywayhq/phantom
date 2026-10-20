package phantom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// uploadLifetime never retains a response Body: abandoned responses must remain
// collectible even while a source is blocked in Read.
type uploadLifetime struct {
	source  io.ReadCloser
	length  *uint64
	id      uint64
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
	mu      sync.Mutex
	failure error
}

func (u *uploadLifetime) close() {
	if u == nil {
		return
	}
	u.once.Do(func() {
		if u.id != 0 {
			_ = control("close_upload", "upload", u.id)
		}
		if u.cancel != nil {
			u.cancel()
		}
		_ = u.source.Close()
	})
}

func (u *uploadLifetime) prepare(ctx context.Context, client uint64) error {
	value, err := dispatch(map[string]any{"kind": "new_upload", "client": client, "length": u.length}, nil)
	if err != nil {
		return err
	}
	var result struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(value, &result) != nil || result.ID == 0 {
		return &Error{Kind: "native_abi"}
	}
	u.id = result.ID
	u.ctx, u.cancel = context.WithCancel(ctx)
	return nil
}

func (u *uploadLifetime) start() {
	if u == nil {
		return
	}
	go func() {
		_ = perform(u.ctx, map[string]any{"kind": "wait_upload", "upload": u.id}, nil, func(completion) error { return nil })
		u.close()
	}()
	go u.produce()
}

func (u *uploadLifetime) write(bytes []byte, end *bool) error {
	return perform(u.ctx, map[string]any{"kind": "write_upload", "upload": u.id, "end": end}, bytes, func(completion) error { return nil })
}

func (u *uploadLifetime) produce() {
	defer u.close()
	buffer := make([]byte, maxChunk)
	var total uint64
	empty := 0
	for {
		if u.ctx.Err() != nil {
			return
		}
		n, err := u.source.Read(buffer)
		if u.ctx.Err() != nil {
			return
		}
		if n < 0 || n > len(buffer) {
			u.fail(errors.New("invalid reader count"))
			return
		}
		if n > 0 {
			empty = 0
			if uint64(n) > ^uint64(0)-total || (u.length != nil && (total > *u.length || uint64(n) > *u.length-total)) {
				u.fail(errors.New("upload length mismatch"))
				return
			}
			total += uint64(n)
			// Reader permits final bytes and EOF (or another error) together.
			// Retain the cause even if the native write itself fails or is cancelled.
			if err != nil && err != io.EOF {
				u.remember(err)
			}
			if u.write(buffer[:n], nil) != nil {
				return
			}
		} else if err == nil {
			empty++
			if empty >= 100 {
				err = io.ErrNoProgress
			}
		}
		if err != nil {
			if err != io.EOF {
				u.fail(err)
			} else if u.length != nil && total != *u.length {
				u.fail(errors.New("upload length mismatch"))
			} else {
				failed := false
				_ = u.write(nil, &failed)
			}
			return
		}
	}
}

func (u *uploadLifetime) fail(err error) {
	u.remember(err)
	failed := true
	_ = u.write(nil, &failed)
}

func (u *uploadLifetime) remember(err error) {
	u.mu.Lock()
	u.failure = err
	u.mu.Unlock()
}

func (u *uploadLifetime) wrap(err error) error {
	if u == nil || err == nil {
		return err
	}
	u.mu.Lock()
	cause := u.failure
	u.mu.Unlock()
	if cause == nil {
		return err
	}
	var native *Error
	if errors.As(err, &native) {
		copy := *native
		copy.cause = cause
		return &copy
	}
	return err
}
