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
	source     io.ReadCloser
	length     *uint64
	id         uint64
	ctx        context.Context
	cancel     context.CancelFunc
	once       sync.Once
	mu         sync.Mutex
	failure    error
	multipart  *multipartLifetime
	closeError error
}

func (u *uploadLifetime) close() error {
	if u == nil {
		return nil
	}
	u.once.Do(func() {
		if u.id != 0 {
			_ = control("close_upload", "upload", u.id)
		}
		if u.cancel != nil {
			u.cancel()
		}
		if u.source != nil {
			err := u.source.Close()
			if u.multipart != nil {
				u.closeError = err
			}
		}
		if u.multipart != nil {
			u.closeError = errors.Join(u.closeError, u.multipart.close())
			if u.closeError != nil {
				u.remember(u.closeError)
			}
		}
	})
	return u.closeError
}

func (u *uploadLifetime) prepare(ctx context.Context, client uint64) error {
	if u.multipart != nil {
		return u.multipart.prepare(ctx, client, u)
	}
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
	if u.multipart != nil {
		go u.multipart.produce(u)
	} else {
		go u.produce()
	}
}

func (u *uploadLifetime) write(bytes []byte, end *bool) error {
	return perform(u.ctx, map[string]any{"kind": "write_upload", "upload": u.id, "end": end}, bytes, func(completion) error { return nil })
}

func (u *uploadLifetime) produce() {
	defer u.close()
	buffer := make([]byte, maxChunk)
	u.produceSource(u.source, u.length, buffer, nil)
}

func (u *uploadLifetime) produceSource(source io.Reader, length *uint64, buffer []byte, finish func() error) bool {
	var total uint64
	empty := 0
	for {
		if u.ctx.Err() != nil {
			return false
		}
		n, err := source.Read(buffer)
		if u.ctx.Err() != nil {
			return false
		}
		if n < 0 || n > len(buffer) {
			u.fail(errors.New("invalid reader count"))
			return false
		}
		if n > 0 {
			empty = 0
			if uint64(n) > ^uint64(0)-total || (length != nil && (total > *length || uint64(n) > *length-total)) {
				u.fail(errors.New("upload length mismatch"))
				return false
			}
			total += uint64(n)
			// Reader permits final bytes and EOF (or another error) together.
			// Retain the cause even if the native write itself fails or is cancelled.
			if err != nil && err != io.EOF {
				u.remember(err)
			}
			if u.write(buffer[:n], nil) != nil {
				return false
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
			} else if length != nil && total != *length {
				u.fail(errors.New("upload length mismatch"))
			} else if finish != nil {
				if err := finish(); err != nil {
					u.fail(err)
				} else {
					failed := false
					return u.write(nil, &failed) == nil
				}
			} else {
				failed := false
				return u.write(nil, &failed) == nil
			}
			return false
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
	u.failure = errors.Join(u.failure, err)
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
		copy.cause = errors.Join(native.cause, cause)
		return &copy
	}
	kind := "request_body"
	if errors.Is(err, context.Canceled) {
		kind = "cancelled"
	} else if errors.Is(err, context.DeadlineExceeded) {
		kind = "timeout"
	}
	return &Error{Kind: kind, cause: errors.Join(err, cause)}
}
