//go:build windows && amd64

package phantom

import (
	"strings"
	"testing"
)

func TestUnixSocketIsUnsupportedOnWindowsNative(t *testing.T) {
	// Require the actual addon, so the ordinary unsupported-platform stub cannot
	// satisfy this native constructor control.
	if err := ensureNativeIdentity(); err != nil {
		t.Fatal(err)
	}
	path := "private.sock"
	client, err := New(Config{Profile: profile, Protocol: "h1", Network: &NetworkOptions{UnixSocket: &path}})
	if client != nil {
		_ = client.Close()
		t.Fatal("Windows published a Unix client")
	}
	if kind(err) != "unsupported_platform" || strings.Contains(err.Error(), path) {
		t.Fatalf("Windows Unix option: %v", err)
	}
	ordinary, err := New(Config{Profile: profile, Protocol: "h1", Network: &NetworkOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ordinary.Close(); err != nil {
		t.Fatal(err)
	}
}
