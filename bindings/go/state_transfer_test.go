package phantom

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStateTransferNativeCookiesAtomicMergeAndDefaultJar(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	if err := client.SetCookie("https://example.com/", "held=original; Path=/; Secure"); err != nil {
		t.Fatal(err)
	}
	entries := []CookieEntry{
		{SourceScheme: CookieHTTPS, Name: "added", Value: "first", Domain: "example.com", Path: "/", HostOnly: true},
		{SourceScheme: CookieHTTPS, Name: "bad", Value: "second", Domain: "UPPER.invalid", Path: "/", HostOnly: true},
	}
	err := client.ImportCookies(ctx, CookieSnapshot{Enabled: true, Entries: entries})
	var failure *StateTransferError
	if !errors.As(err, &failure) || failure.Kind != "cookie_snapshot_invalid_cookie" || failure.EntryIndex == nil || *failure.EntryIndex != 1 {
		t.Fatalf("typed entry failure: %v", err)
	}
	if value, err := client.CookiesForURL("https://example.com/"); err != nil || value != "held=original" {
		t.Fatalf("partial import: %q %v", value, err)
	}
	past := time.Now().Add(-time.Hour)
	entries[1] = CookieEntry{SourceScheme: CookieHTTPS, Name: "expired", Value: "gone", Domain: "example.com", Path: "/", HostOnly: true, ExpiresAt: &past}
	entries = append(entries, CookieEntry{SourceScheme: CookieHTTPS, Name: "held", Value: "replacement", Domain: "example.com", Path: "/", HostOnly: true, Secure: true})
	if err := client.ImportCookies(ctx, CookieSnapshot{Enabled: true, Entries: entries}); err != nil {
		t.Fatal(err)
	}
	if value, err := client.CookiesForURL("https://example.com/"); err != nil || value != "added=first; held=original" {
		t.Fatalf("creation rank/precedence/expiry: %q %v", value, err)
	}

	full := newClient(t)
	entries = make([]CookieEntry, 3300)
	for index := range entries {
		entries[index] = CookieEntry{SourceScheme: CookieHTTPS, Name: "id", Value: strings.Repeat("x", 100),
			Domain: fmt.Sprintf("host%d.test", index), Path: "/", HostOnly: true}
	}
	if err := full.ImportCookies(ctx, CookieSnapshot{Enabled: true, Entries: entries}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := full.ExportCookies(ctx)
	if err != nil || !snapshot.Enabled || len(snapshot.Entries) != 3300 {
		t.Fatalf("default jar transfer: %d %v", len(snapshot.Entries), err)
	}
	for index, entry := range snapshot.Entries {
		if entry.Domain != entries[index].Domain || entry.Value != entries[index].Value {
			t.Fatalf("entry %d order/value changed", index)
		}
	}

	disabled, err := New(Config{Profile: profile, Protocol: "h1", DisableCookies: true})
	if err != nil {
		t.Fatal(err)
	}
	defer disabled.Close()
	if got, err := disabled.ExportCookies(ctx); err != nil || got.Enabled || len(got.Entries) != 0 {
		t.Fatalf("disabled jar: %+v %v", got, err)
	}
	if err := disabled.ImportCookies(ctx, CookieSnapshot{Enabled: true}); !errors.As(err, &failure) || failure.Kind != "cookie_snapshot_disabled" {
		t.Fatalf("disabled import: %v", err)
	}
}

func TestStateTransferNativeAltSvcAtomicImportAndConfigurationRetention(t *testing.T) {
	ctx := context.Background()
	disabled := newClient(t)
	if got, err := disabled.ExportAltSvc(ctx); err != nil || got.Enabled {
		t.Fatalf("disabled alternatives: %+v %v", got, err)
	}
	client, err := New(Config{Profile: profile, Protocol: "h1", Network: &NetworkOptions{MaxAltSvcOrigins: 16}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	entries := []AltSvcEntry{{Origin: "https://example.com", Host: "alt.example.com", Port: 443, ExpiresAt: time.Now().Add(time.Hour)}}
	if err := client.ImportAltSvc(ctx, AltSvcSnapshot{Enabled: true, Entries: entries}); err != nil {
		t.Fatal(err)
	}
	bad := append([]AltSvcEntry{{Origin: "https://second.example.com", Host: "alt.example.com", Port: 443, ExpiresAt: entries[0].ExpiresAt}},
		AltSvcEntry{Origin: "http://invalid.example.com", Host: "alt.example.com", Port: 443, ExpiresAt: entries[0].ExpiresAt})
	err = client.ImportAltSvc(ctx, AltSvcSnapshot{Enabled: true, Entries: bad})
	var failure *StateTransferError
	if !errors.As(err, &failure) || failure.Kind != "alt_svc_snapshot_noncanonical_origin" || failure.EntryIndex == nil || *failure.EntryIndex != 1 {
		t.Fatalf("typed alternative failure: %v", err)
	}
	got, err := client.ExportAltSvc(ctx)
	if err != nil || !got.Enabled || len(got.Entries) != 1 || got.Entries[0].Origin != entries[0].Origin || got.Entries[0].ExpiresAt.After(entries[0].ExpiresAt) {
		t.Fatalf("partial or extended import: %+v %v", got, err)
	}
	fork, err := client.Fork(SessionSharing{})
	if err != nil {
		t.Fatal(err)
	}
	defer fork.Close()
	if got, err := fork.ExportAltSvc(ctx); err != nil || !got.Enabled {
		t.Fatalf("fork lost opt-in: %+v %v", got, err)
	}
	key := [32]byte{23}
	checkpoint, err := client.ExportSession(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := client.RestoreSession(ctx, checkpoint, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if got, err := restored.ExportAltSvc(ctx); err != nil || !got.Enabled || len(got.Entries) != 1 {
		t.Fatalf("restore lost opt-in/state: %+v %v", got, err)
	}
}

func TestStateTransferNativeEncryptedTicketsAuthenticateAndRetainClient(t *testing.T) {
	ctx := context.Background()
	client := newClient(t)
	key := [32]byte{42}
	ciphertext, err := client.ExportSessionTickets(ctx, key)
	if err != nil || len(ciphertext) == 0 || key[0] != 42 {
		t.Fatalf("ticket export: %d %v", len(ciphertext), err)
	}
	if err := client.ImportSessionTickets(ctx, ciphertext, key, []SessionRoute{{}, {Proxy: "http://127.0.0.1:80"}}); err != nil {
		t.Fatal(err)
	}
	wrong := [32]byte{43}
	err = client.ImportSessionTickets(ctx, ciphertext, wrong, nil)
	var failure *StateTransferError
	if !errors.As(err, &failure) || failure.Kind != "session_ticket_authentication" {
		t.Fatalf("ticket authentication: %v", err)
	}
	if err := client.ImportSessionTickets(ctx, ciphertext[:1], key, nil); err == nil {
		t.Fatal("truncated ticket snapshot accepted")
	}
	if _, err := client.ExportSessionTickets(ctx, key); err != nil {
		t.Fatalf("source unusable after rejected import: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := client.ImportSessionTickets(cancelled, ciphertext, key, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled import: %v", err)
	}
}
