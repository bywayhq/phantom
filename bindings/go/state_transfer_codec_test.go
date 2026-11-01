package phantom

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

func TestStateCodecRetainsCookieAttributesAndExpiryOutsideUnixNanoRange(t *testing.T) {
	partition := "https://example.com"
	expiry := time.Date(9999, 12, 31, 23, 59, 58, 123456789, time.UTC)
	want := CookieSnapshot{Enabled: true, Entries: []CookieEntry{
		{SourceScheme: CookieHTTPS, Name: "session", Value: "private", Domain: "example.com", Path: "/",
			HostOnly: true, Secure: true, HTTPOnly: true, SameSite: CookieSameSiteNone, PartitionKey: &partition, ExpiresAt: &expiry},
		{SourceScheme: CookieHTTP, Name: "other", Value: "second", Domain: "example.com", Path: "/path"},
	}}
	rows, arena, err := cookieTransfer(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := projectCookies(stateResult{value: native.StateResult{Enabled: 1}, cookies: rows, arena: arena})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("cookie attributes/order/expiry changed: %v", err)
	}
	if rows[0].Expiry.Seconds != 253402300798 || rows[0].Expiry.Nanoseconds != 123456789 {
		t.Fatal("expiry truncated")
	}
	for _, value := range []any{want, want.Entries[0], AltSvcSnapshot{Enabled: true, Entries: []AltSvcEntry{{Origin: "secret"}}}} {
		if text := fmt.Sprintf("%+v %#v", value, value); strings.Contains(text, "private") || strings.Contains(text, "secret") {
			t.Fatal("snapshot formatting exposed state")
		}
	}
}

func TestStateCodecSupportsDefaultJarAndChecksAggregateTextBeforeAllocation(t *testing.T) {
	entries := make([]CookieEntry, 3300)
	for index := range entries {
		entries[index] = CookieEntry{SourceScheme: CookieHTTPS, Name: "name", Value: strings.Repeat("x", 100), Domain: "example.com", Path: "/"}
	}
	rows, arena, err := cookieTransfer(CookieSnapshot{Enabled: true, Entries: entries})
	if err != nil || len(rows) != 3300 || len(arena) <= maxMetadata {
		t.Fatalf("default jar rejected: %v", err)
	}
	entries = append(entries[:1], CookieEntry{SourceScheme: CookieHTTPS, Value: strings.Repeat("x", native.MaxStateText)})
	if rows, arena, err := cookieTransfer(CookieSnapshot{Enabled: true, Entries: entries}); rows != nil || arena != nil || kind(err) != "input_limit" {
		t.Fatalf("aggregate text admitted: %v", err)
	}
	if _, _, err := cookieTransfer(CookieSnapshot{Enabled: true, Entries: make([]CookieEntry, native.MaxStateCookies+1)}); kind(err) != "input_limit" {
		t.Fatalf("cookie count admitted: %v", err)
	}
	if _, _, err := altSvcTransfer(AltSvcSnapshot{Enabled: true, Entries: make([]AltSvcEntry, native.MaxStateAlternatives+1)}); kind(err) != "input_limit" {
		t.Fatalf("alternative count admitted: %v", err)
	}
}

func TestStateCodecRejectsMalformedRowsAndPreservesDisabledAbsence(t *testing.T) {
	for _, snapshot := range []CookieSnapshot{{}, {Enabled: true, Entries: []CookieEntry{{SourceScheme: "ftp"}}},
		{Enabled: true, Entries: []CookieEntry{{SourceScheme: CookieHTTP, SameSite: "unknown"}}},
		{Enabled: true, Entries: []CookieEntry{{SourceScheme: CookieHTTP, Value: string([]byte{0xff})}}}} {
		if _, _, err := cookieTransfer(snapshot); err == nil {
			t.Fatal("malformed input admitted")
		}
	}
	valid := native.StateCookie{SourceScheme: 2}
	for _, row := range []native.StateCookie{
		{SourceScheme: 2, Flags: 32}, {SourceScheme: 3}, {SourceScheme: 2, SameSite: 4},
		{SourceScheme: 2, Name: native.Slice{Offset: ^uint64(0), Length: 1}},
		{SourceScheme: 2, Flags: 16, Expiry: native.StateTimestamp{Nanoseconds: 1_000_000_000}},
		{SourceScheme: 2, Flags: 0, Expiry: native.StateTimestamp{Seconds: 1}},
	} {
		if _, err := projectCookies(stateResult{cookies: []native.StateCookie{row}}); kind(err) != "native_abi" {
			t.Fatalf("malformed row admitted: %v", err)
		}
	}
	got, err := projectCookies(stateResult{value: native.StateResult{Enabled: 1}, cookies: []native.StateCookie{valid}})
	if err != nil || !got.Enabled || len(got.Entries) != 1 {
		t.Fatal("valid session cookie lost")
	}
	disabled, err := projectCookies(stateResult{})
	if err != nil || disabled.Enabled || len(disabled.Entries) != 0 {
		t.Fatal("disabled jar changed")
	}
	empty, err := projectCookies(stateResult{value: native.StateResult{Enabled: 1}})
	if err != nil || !empty.Enabled || len(empty.Entries) != 0 {
		t.Fatal("enabled empty jar changed")
	}
}

func TestStateCodecAltSvcOrderAndPreEpochTimestamp(t *testing.T) {
	expiry := time.Unix(-1, 345678901).UTC()
	want := AltSvcSnapshot{Enabled: true, Entries: []AltSvcEntry{
		{Origin: "https://example.com", Host: "alt.example.com", Port: 443, ExpiresAt: expiry},
		{Origin: "https://example.com", Host: "second.example.com", Port: 8443, ExpiresAt: expiry},
	}}
	rows, arena, err := altSvcTransfer(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := projectAltSvc(stateResult{value: native.StateResult{Enabled: 1}, alternatives: rows, arena: arena})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("alternative order/precision changed: %v", err)
	}
	rows[0].Port = 65536
	if _, err := projectAltSvc(stateResult{alternatives: rows, arena: arena}); kind(err) != "native_abi" {
		t.Fatal("port truncated")
	}
}

func TestStateCodecTicketRoutesContextAndErrorIdentity(t *testing.T) {
	if _, err := ticketRoutes(make([]SessionRoute, 257)); kind(err) != "input_limit" {
		t.Fatal("route count admitted")
	}
	if _, err := ticketRoutes([]SessionRoute{{Proxy: strings.Repeat("p", 65537)}}); kind(err) != "input_limit" {
		t.Fatal("route text admitted")
	}
	if _, err := ticketRoutes([]SessionRoute{{ProxyCredentials: &ProxyCredentials{Password: string([]byte{0xff})}}}); err == nil {
		t.Fatal("invalid credential encoding admitted")
	}
	var missing *Client
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := missing.ExportCookies(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("context priority: %v", err)
	}
	if err := missing.ImportAltSvc(nil, AltSvcSnapshot{}); kind(err) != "invalid_context" {
		t.Fatalf("nil context: %v", err)
	}
	if _, err := missing.ExportSessionTickets(context.Background(), [32]byte{}); kind(err) != "client_closed" {
		t.Fatalf("nil client: %v", err)
	}
	index := 1
	want := &Error{Kind: "cookie_snapshot_invalid_cookie"}
	err := &StateTransferError{Kind: want.Kind, EntryIndex: &index, native: want}
	var original *Error
	if !errors.Is(err, want) || !errors.As(err, &original) || original != want {
		t.Fatal("native cause lost")
	}
	if size, err := networkInputSize(&NetworkOptions{MaxAltSvcOrigins: -1}); size != 0 || kind(err) != "invalid_alt_svc_capacity" {
		t.Fatal("negative Alt-Svc capacity admitted")
	}
	if got := networkWire(&NetworkOptions{MaxAltSvcOrigins: 64}); got.MaxAltSvcOrigins != 64 {
		t.Fatal("Alt-Svc opt-in lost")
	}
}
