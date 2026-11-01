package phantom

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type memorySessionStore struct {
	values map[string][]byte
	load   func(context.Context, string) ([]byte, error)
	save   func(context.Context, string, []byte) error
}

func (s *memorySessionStore) Load(ctx context.Context, name string) ([]byte, error) {
	if s.load != nil {
		return s.load(ctx, name)
	}
	return s.values[name], nil
}
func (s *memorySessionStore) Save(ctx context.Context, name string, snapshot []byte) error {
	if s.save != nil {
		return s.save(ctx, name, snapshot)
	}
	s.values[name] = bytes.Clone(snapshot)
	return nil
}

func TestSessionStorageNamesAndContextFailBeforeBackendOrNative(t *testing.T) {
	store := &memorySessionStore{values: map[string][]byte{}}
	for _, name := range []string{"", strings.Repeat("é", 129), "a\x00", "a\u0085", "\xff"} {
		err := storageInput(context.Background(), store, name)
		var failure *SessionStorageError
		if !errors.As(err, &failure) || failure.Kind != "invalid_name" {
			t.Fatalf("name validation: %v", err)
		}
	}
	if err := storageInput(context.Background(), store, strings.Repeat("é", 128)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := storageInput(ctx, store, "session"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Time{})
	defer stop()
	if err := storageInput(expired, store, "session"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestSessionStorageAbsentBackendErrorsAndOversizeNeverRestore(t *testing.T) {
	// Only the facade's live-owner marker is set; these outcomes must never
	// reach native restoration or require a registered native handle.
	client := &Client{}
	client.id.Store(1)
	store := &memorySessionStore{values: map[string][]byte{}}
	key := [32]byte{1}
	if child, err := client.LoadSession(context.Background(), store, "absent", key, nil); child != nil || err != nil {
		t.Fatalf("absence: %v %v", child, err)
	}
	original := errors.New("private backend detail")
	store.load = func(context.Context, string) ([]byte, error) { return nil, original }
	_, err := client.LoadSession(context.Background(), store, "session", key, nil)
	if !errors.Is(err, original) || strings.Contains(err.Error(), "private") {
		t.Fatalf("backend cause/redaction: %v", err)
	}
	store.load = func(context.Context, string) ([]byte, error) { return make([]byte, maxSessionSnapshot+1), nil }
	_, err = client.LoadSession(context.Background(), store, "session", key, nil)
	var snapshot *SessionSnapshotError
	if !errors.As(err, &snapshot) || snapshot.Kind != "too_large" {
		t.Fatalf("oversize: %v", err)
	}
}

func TestSessionStorageUsesSameContextAndChecksLateBlockingRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := &memorySessionStore{load: func(received context.Context, _ string) ([]byte, error) {
		if received != ctx {
			t.Fatal("context was replaced")
		}
		cancel()
		return []byte("encrypted"), nil
	}}
	client := &Client{}
	client.id.Store(1)
	if child, err := client.LoadSession(ctx, store, "session", [32]byte{}, nil); child != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("late cancellation: %v %v", child, err)
	}
}

func TestNativeSessionStorageRoundTripPreservesSourceAndRejectsWrongKey(t *testing.T) {
	client := newClient(t)
	store := &memorySessionStore{values: map[string][]byte{}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key := [32]byte{1}
	if err := client.SetCookie("https://example.test", "state=original; Secure; Path=/"); err != nil {
		t.Fatal(err)
	}
	if err := client.SaveSession(ctx, store, "job/session", key); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(store.values["job/session"], []byte("state=original")) {
		t.Fatal("backend received plaintext")
	}
	if err := client.SetCookie("https://example.test", "state=changed; Secure; Path=/"); err != nil {
		t.Fatal(err)
	}
	child, err := client.LoadSession(ctx, store, "job/session", key, []SessionRoute{{}})
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	value, err := child.CookiesForURL("https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	if value != "state=original" {
		t.Fatalf("restored state: %s", value)
	}
	value, err = client.CookiesForURL("https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	if value != "state=changed" {
		t.Fatalf("receiver changed: %s", value)
	}
	_, err = client.LoadSession(ctx, store, "job/session", [32]byte{2}, nil)
	var snapshot *SessionSnapshotError
	if !errors.As(err, &snapshot) || snapshot.Kind != "authentication" {
		t.Fatalf("wrong-key cause: %v", err)
	}
	store.values["empty"] = []byte{}
	if absent, err := client.LoadSession(ctx, store, "empty", key, nil); absent != nil || err == nil {
		t.Fatalf("empty present object was treated as absence: %v %v", absent, err)
	}
}
