# Phantom for Go

Make concurrent requests with reusable native connection pools and explicit
browser profiles. Response bodies implement `io.ReadCloser`.

```go
package example

import (
    "context"
    "time"

    phantom "github.com/bywayhq/phantom/bindings/go"
)

func example(ctx context.Context) error {
    client, err := phantom.New(phantom.Config{
        Profile: "chrome/154.0.8037.97/windows-11-26200/r1",
        Protocol: "negotiated",
        Timeout: 30 * time.Second,
    })
    if err != nil { return err }
    defer client.Close()

    for _, url := range []string{"https://example.com/", "https://example.com/next"} {
        if _, err := fetch(ctx, client, url); err != nil { return err }
    }
    return nil
}

func fetch(ctx context.Context, client *phantom.Client, url string) ([]byte, error) {
    response, err := client.Do(ctx, phantom.Request{Method: "GET", URL: url})
    if err != nil { return nil, err }
    defer response.Body.Close()
    return response.Body.ReadAll(1024 * 1024)
}
```

This example selects Windows Chrome. Choose your host's profile from the
[catalog](../../crates/phantom-profile/catalog/profiles.json). For repeated
requests, keep the client open and call `Do` from any goroutine.

## Native installation candidates

There are no public module tags or registry releases yet. Download a matching
candidate from the [installation workflow](../../.github/workflows/go-artifacts.yml).
Each archive pairs `module/` with `lib/`, licenses and a receipt. Keep that pair
together and add the local `replace` described in its README.

Candidates cover Windows x64 MSVC, Linux x64 GNU and macOS arm64, tested outside
the checkout. Receipts identify source, checksums and dependencies; only their
recorded hosts are verified. Windows needs
the x64 Visual C++ v14 runtime at least as recent as the receipt's build tools.
Runtime DLLs are not bundled. Keep the included notices when redistributing.

## Build and limits

Source builds require Go 1.26, Rust 1.88+ and the repository's
[native build tools](../../crates/phantom/src/docs/getting-started.md#install-the-build-tools).
Build from the repository root:

```sh
scripts/dev/with-cargo-lock.sh cargo build -p phantom-go --locked
```

From your application's module, select this local binding checkout:

```sh
go mod edit -replace=github.com/bywayhq/phantom/bindings/go=/absolute/path/phantom/bindings/go
go mod edit -require=github.com/bywayhq/phantom/bindings/go@v0.0.0
```

On Windows amd64, set `PHANTOM_GO_LIBRARY` to the absolute
`target/debug/phantom_go.dll` path or place it beside your executable. Windows
uses native DLL calls without cgo. Linux/macOS need cgo and a C compiler:
point `CGO_LDFLAGS` at the native library directory with `-L`, then add that
directory to `LD_LIBRARY_PATH` on Linux or `DYLD_LIBRARY_PATH` on macOS.
The library remains loaded for the process lifetime.

Phantom checks its ABI and package version once, before creating native
resources. A mismatch returns `*Error` with `Kind` `native_abi_mismatch` or
`native_version_mismatch`. Install the matching library and restart the process.
On Windows, set `PHANTOM_GO_LIBRARY` before the first native operation.

## Requests and streaming

`Protocol` accepts `h1`, `h2`, `h3` or `negotiated`. Exact protocols fail when
unsupported by a route. Direct H2 with an HTTP URL uses cleartext prior
knowledge. Add `Context: "navigation"` or `"fetch"` for the catalog's template;
an empty context uses caller headers only.

Headers are ordered `[]Header` values, including duplicates. Names and byte
values retain template placement rules; use lowercase caller names for H2/H3.
`Sensitive` requests never-indexed compression, subject to cookie policy.
Response headers retain received order and bytes. HTTP error statuses remain
responses; inspect `Status` before consuming the body.

`Body.ReadAll(maximum)` collects within your limit and closes the body on
success or failure. To stream to a writer, use the standard `io.Copy`:

```go
func download(ctx context.Context, client *phantom.Client, url string, out io.Writer) error {
    response, err := client.Do(ctx, phantom.Request{Method: "GET", URL: url})
    if err != nil { return err }
    defer response.Body.Close()
    _, err = io.Copy(out, response.Body)
    return err
}
```

Add `io` to your imports. Copying imposes no total download limit. Reads pull
up to 64 KiB at a time. Content stays encoded unless you set
`Request.ContentDecoding = phantom.AdvertisedDecoding(limit)` and supply
`Accept-Encoding`. The decoded-stream limit and collection limit are separate.
`DecodedContentCodings` records the selected chain; headers remain unchanged.
EOF, read errors and `Close` release the native body. Concurrent reads are
serialized. Byte uploads use replayable `Request.Body`, limited to 8 MiB.

For larger uploads, set `Request.Upload` to an `io.ReadCloser`, such as an open
file. `Do` takes ownership and closes it once, including on validation failure.
Its `Close` must unblock a concurrent `Read`. Set `UploadLength` for an exact
byte count, or leave it nil for unknown length. Unread suffixes are not validated.
Streaming uses bounded chunks and cannot be combined with `Body`. A reader is
one-shot; retries cannot reopen it. Cancellation and the total deadline remain
active after an early response.

## Cancellation and state

Keep `ctx` alive through body EOF or close. Cancelling it interrupts setup,
uploads and later reads without cancelling another multiplexed response.
Errors from context cancellation are Go's context errors.

`Shutdown(ctx)` closes admission and waits for active work. Close unused bodies
first. Cancelling the wait leaves admission closed; retrying can briefly return
`shutdown_in_progress`. `Close` waits up to five seconds. Use explicit shutdown;
finalizers provide eventual handle cleanup.

`CloseIdleConnections(ctx)` retires idle connections. `RefreshConnections(ctx)`
retires pools while active work finishes. Both retain learned state; cancellation
can leave some pools unvisited. Use `ClearSessionTickets`, `ClearDNSCache`,
`ClearClientHints`, `ClearAltSvc` or `ClearAltSvcRacingHistory` to clear state.

`Config.BaseURL` joins relative request URLs; a trailing slash appends to its
directory. Routing is direct unless `Proxy` selects HTTP(S), SOCKS4(a) or
SOCKS5(h). Proxy environment variables are ignored. Set `ProxyCredentials` for
HTTP Basic or SOCKS5 username/password auth, separately from the URI.
`AdditionalRootsDER` and `ProxyAdditionalRootsDER` separately extend origin
and HTTPS-proxy trust while retaining certificate verification.

Cookies are enabled unless `DisableCookies` is set. Use `SetCookie`,
`CookiesForURL` and `ClearCookies`. Matching uses top-level navigation semantics,
independently of the header template.

Create `NewAttemptBudget(maximum)` and attach it as `Request.Budget` across
clients. Initial origin attempts and internal resends spend it atomically.
Admissions are not refunded, even if no bytes are sent. DNS/setup/proxy
negotiation are separate. Use `TryAdmit()` for attempts outside Phantom only.
Close the budget handle when finished; in-flight requests retain it.

Client/request `Timeouts` has `PoolAdmission`, `Connect`, `ResponseHead`,
`ReadIdle` and `Total`. Use `LimitTimeout(duration)`,
`Timeout{Mode: TimeoutDisabled}`, or default `TimeoutInherit`. Request fields
inherit the client; client limits start disabled. `Connect` includes setup,
`ResponseHead` includes upload and `Total` includes body reads. Zero is finite;
ready work can win. The older `Timeout` field uses milliseconds with a
one-millisecond minimum; do not combine it with explicit `Timeouts.Total`.

`*Error` exposes redacted `Kind`, protocol and timeout phase when known.
Messages omit URLs, credentials and native source chains. Responses retain
`EffectiveURL`, `RedirectsFollowed` and `ConnectionSetupRetries`; the last
counter covers caller-enabled setup retries only.

`Config.RedirectPolicy` and `RetryPolicy` default to disabled. Set
`RedirectPolicy{MaximumHops: 5}` to follow redirects. Use `StatusRetry` or
`ConnectionRetry` for bounded retries, with optional capped backoff, jitter and
`Retry-After`. Request pointers inherit when nil and replace the whole policy
otherwise. `Request.RedirectHistoryLimit` retains selected hops and their URLs.
All attempts share the total deadline and budget. See [policy types](policy.go)
and [retry settings](retry.go) for fields and replay rules.

## Edit profiles

`NewCatalogProfile(identifier, context)` and `ImportProfileJSON(document)` create
immutable settings. Choose exactly one of `Config.Profile` and `ProfileSettings`.
Close profile owners when finished; existing clients retain their settings.

Use `settings.Describe()` for an editable `map[string]any`, edit it, then
`json.Marshal` and `ImportProfileJSON` to validate the result. Numbers use
`json.Number` to preserve large integers. `ExportJSON()` returns complete bytes
within a separate 16 MiB document limit. Documents can contain literal headers;
import errors expose redacted `Kind` and `Field`. Imports have no catalog identity
or browser-fidelity claim. `Context: "profile"` selects an attached template;
`raw` omits it, and named contexts require catalog ownership.

`ImportJA3Profile`, `ImportAkamaiProfile`, `ImportJA4Profile`,
`ImportClientHelloProfile` and `ImportQUICTransportProfile` require a base
`*Profile`. Results contain `Profile`, `ObservedFields` and `SupplementedFields`;
close the returned profile owner. JA3/JA4 take raw descriptions, not hashes.
JA4 requires `JA4Sorted` or `JA4Original`. ClientHello bytes include the
four-byte handshake header without TLS records; QUIC bytes are extension 57's
payload. Missing settings come from the base, without a browser-fidelity claim.

## Fork session state

`worker, err := client.Fork(phantom.SessionSharing{Cookies: true, DNS: true})`
creates independent pools sharing selected live state. Close each client.
Selectors are `Cookies`, `DNS`, `ClientHints`, `Discovery` and `Tickets`; the
zero value shares nothing. Selected changes, expiry and clears are shared;
other state starts empty. Sharing does not enable disabled features. Profile,
routes, trust and timeouts are retained; admission and shutdown are independent.
Shared tickets remain single-use. Forks use ordinary client capacity. Go cannot
fork a released owner after successful shutdown.

## Capacity and feature limits

Process-wide limits are 64 each for clients, budgets, response handles and
ordinary operations, plus 64 separate shutdown operations. Exhaustion returns
a typed error without waiting. Uploads allow 8 MiB each and 16 MiB aggregate
native custody until responses close. Metadata limits are 64 KiB per command,
256 response fields/32 KiB and 256 KiB per encoded reply.

Pinning/client certificates, custom connectors, CONNECT-UDP and session
snapshots are not exposed yet.

## Next

See the [library guides](../../crates/phantom/src/docs/overview.md) for the
underlying protocols and profiles.
