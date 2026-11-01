package phantom

import (
	"context"
	"runtime"
	"time"
	"unsafe"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

// CookieSourceScheme is the scheme of the URL that originally set a cookie.
type CookieSourceScheme string

const (
	CookieHTTP  CookieSourceScheme = "http"
	CookieHTTPS CookieSourceScheme = "https"
)

// CookieSameSite is an explicit SameSite attribute; empty means absent.
type CookieSameSite string

const (
	CookieSameSiteStrict CookieSameSite = "strict"
	CookieSameSiteLax    CookieSameSite = "lax"
	CookieSameSiteNone   CookieSameSite = "none"
)

// CookieEntry retains one cookie's attributes. ExpiresAt nil means a session
// cookie. PartitionKey nil means unpartitioned. Import revalidates every entry.
// Subsecond expiry must be representable by the native platform clock.
type CookieEntry struct {
	SourceScheme               CookieSourceScheme
	Name, Value, Domain, Path  string
	HostOnly, Secure, HTTPOnly bool
	SameSite                   CookieSameSite
	PartitionKey               *string
	ExpiresAt                  *time.Time
}

func (CookieEntry) String() string   { return "phantom.CookieEntry([redacted])" }
func (CookieEntry) GoString() string { return "phantom.CookieEntry([redacted])" }

// CookieSnapshot holds cookies oldest first. Enabled distinguishes a disabled
// jar from an empty jar. Treat its contents as credentials.
type CookieSnapshot struct {
	Enabled bool
	Entries []CookieEntry
}

func (CookieSnapshot) String() string   { return "phantom.CookieSnapshot([redacted])" }
func (CookieSnapshot) GoString() string { return "phantom.CookieSnapshot([redacted])" }

// AltSvcEntry is one direct-route HTTP/3 alternative with an absolute expiry.
// Origin is a canonical HTTPS origin; Host is canonical and unbracketed.
type AltSvcEntry struct {
	Origin, Host string
	Port         uint16
	ExpiresAt    time.Time
}

func (AltSvcEntry) String() string   { return "phantom.AltSvcEntry([redacted])" }
func (AltSvcEntry) GoString() string { return "phantom.AltSvcEntry([redacted])" }

// AltSvcSnapshot holds direct-route alternatives, least recently used first.
// Alternatives for an origin stay consecutive and retain advertisement order.
type AltSvcSnapshot struct {
	Enabled bool
	Entries []AltSvcEntry
}

func (AltSvcSnapshot) String() string   { return "phantom.AltSvcSnapshot([redacted])" }
func (AltSvcSnapshot) GoString() string { return "phantom.AltSvcSnapshot([redacted])" }

// StateTransferError describes a rejected cookie, Alt-Svc or TLS-ticket
// transfer. EntryIndex is zero-based when a particular entry was rejected.
// Errors.As also reaches the underlying *Error. Formatting omits state and keys.
type StateTransferError struct {
	Kind       string
	EntryIndex *int
	native     *Error
}

func (e *StateTransferError) Error() string { return "phantom state transfer: " + e.Kind }
func (e *StateTransferError) Unwrap() error { return e.native }

type stateResult struct {
	value        native.StateResult
	cookies      []native.StateCookie
	alternatives []native.StateAlternative
	arena        []byte
}

func (c *Client) transferState(ctx context.Context, input *native.StateTransfer) (stateResult, error) {
	var result stateResult
	if err := sessionContext(ctx, c); err != nil {
		return result, err
	}
	if err := ensureNativeIdentity(); err != nil {
		return result, err
	}
	// Resolve the entire optional capability before admitting any state work.
	if err := nativeBoundaryError(native.LoadStateTransfer()); err != nil {
		return result, err
	}
	input.Client = c.id.Load()
	err := performSubmitted(ctx, func() (uint64, error) {
		var reply native.Reply
		if err := nativeBoundaryError(native.SubmitStateTransfer(input, &reply)); err != nil {
			return 0, err
		}
		return reply.Operation, nativeRecordError(reply.Error)
	}, nil, func(event completion) error {
		value, cookies, alternatives, arena, err := native.ReadStateResult(event.Operation)
		if err != nil {
			return nativeBoundaryError(err)
		}
		result = stateResult{value: value, cookies: cookies, alternatives: alternatives, arena: arena}
		if value.Kind != input.Kind {
			return &Error{Kind: "native_abi"}
		}
		if err := nativeRecordError(value.Error); err != nil {
			nativeError, ok := err.(*Error)
			if !ok {
				return err
			}
			failure := &StateTransferError{Kind: nativeError.Kind, native: nativeError}
			if value.Entry != 0 {
				index := int(value.Entry - 1)
				failure.EntryIndex = &index
			}
			return failure
		}
		return nil
	})
	runtime.KeepAlive(input)
	runtime.KeepAlive(c)
	if err != nil {
		clear(result.arena)
		return stateResult{}, err
	}
	return result, nil
}

// ExportCookies copies unexpired cookies without counting them as cookie use.
// Expiry follows the core's whole-second export rounding. Disabled jars return
// Enabled=false. The transfer allows 16,384 entries and 32 MiB of UTF-8 text.
func (c *Client) ExportCookies(ctx context.Context) (CookieSnapshot, error) {
	result, err := c.transferState(ctx, &native.StateTransfer{Kind: 1})
	if err != nil {
		return CookieSnapshot{}, err
	}
	defer clear(result.arena)
	return projectCookies(result)
}

// ImportCookies atomically validates a caller-owned snapshot, then merges it.
// Existing cookies take precedence; expired entries are dropped. Enabled must
// be true. Cancellation cannot undo a merge that has already committed.
func (c *Client) ImportCookies(ctx context.Context, snapshot CookieSnapshot) error {
	if err := sessionContext(ctx, c); err != nil {
		return err
	}
	rows, arena, err := cookieTransfer(snapshot)
	if err != nil {
		return err
	}
	defer clear(arena)
	defer runtime.KeepAlive(rows)
	_, err = c.transferState(ctx, &native.StateTransfer{Kind: 2, Cookies: unsafe.Pointer(unsafe.SliceData(rows)),
		CookieCount: uint64(len(rows)), Arena: native.BorrowedBytes(arena)})
	return err
}

// ExportAltSvc copies unexpired direct-route alternatives. Proxy-route entries
// are omitted. Enabled=false means Alt-Svc is disabled; enable it with
// NetworkOptions.MaxAltSvcOrigins. Up to 32,768 entries and 32 MiB are admitted.
func (c *Client) ExportAltSvc(ctx context.Context) (AltSvcSnapshot, error) {
	result, err := c.transferState(ctx, &native.StateTransfer{Kind: 3})
	if err != nil {
		return AltSvcSnapshot{}, err
	}
	defer clear(result.arena)
	return projectAltSvc(result)
}

// ImportAltSvc atomically validates and merges direct-route alternatives.
// Existing entries take precedence. Expiry is clamped without extending it.
// Enabled must be true. Cancellation cannot roll back a committed merge.
func (c *Client) ImportAltSvc(ctx context.Context, snapshot AltSvcSnapshot) error {
	if err := sessionContext(ctx, c); err != nil {
		return err
	}
	rows, arena, err := altSvcTransfer(snapshot)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(rows)
	_, err = c.transferState(ctx, &native.StateTransfer{Kind: 4, Alternatives: unsafe.Pointer(unsafe.SliceData(rows)),
		AlternativeCount: uint64(len(rows)), Arena: native.BorrowedBytes(arena)})
	return err
}

// ExportSessionTickets encrypts resumable TLS state without consuming it.
// Keep the 32-byte key separate from the returned opaque ciphertext (16 MiB
// maximum). Work uses the native blocking pool; no network operation occurs.
func (c *Client) ExportSessionTickets(ctx context.Context, key [32]byte) ([]byte, error) {
	defer clear(key[:])
	result, err := c.transferState(ctx, &native.StateTransfer{Kind: 5, Key: native.BorrowedBytes(key[:])})
	runtime.KeepAlive(key)
	if err != nil {
		return nil, err
	}
	return result.arena, nil
}

// ImportSessionTickets authenticates all state before changing ticket caches.
// Profile, trust and route checks remain those of the receiving Rust client.
// ReceivingRoutes admits request-only routes; it does not change routing.
// Matching owner caches are replaced; unmentioned owners retain their tickets.
// Context cancellation may return before blocking work finishes and cannot
// undo an import already committed. Native shutdown waits for actual exit.
func (c *Client) ImportSessionTickets(ctx context.Context, snapshot []byte, key [32]byte, receivingRoutes []SessionRoute) error {
	defer clear(key[:])
	if err := sessionContext(ctx, c); err != nil {
		return err
	}
	if len(snapshot) > native.MaxStateTickets {
		return &Error{Kind: "input_limit"}
	}
	routes, err := ticketRoutes(receivingRoutes)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(routes)
	defer runtime.KeepAlive(receivingRoutes)
	_, err = c.transferState(ctx, &native.StateTransfer{Kind: 6, Key: native.BorrowedBytes(key[:]),
		Arena: native.BorrowedBytes(snapshot), Routes: unsafe.Pointer(unsafe.SliceData(routes)), RouteCount: uint64(len(routes))})
	runtime.KeepAlive(snapshot)
	runtime.KeepAlive(key)
	return err
}
