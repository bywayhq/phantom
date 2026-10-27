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
        Profile: "chrome-154-windows",
        Protocol: "negotiated",
        Context: "navigation",
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

This example uses Chrome's Windows settings. Choose other profiles from the
[catalog](../../crates/phantom-profile/catalog/profiles.json). Keep the client
open for later requests and call `Do` from any goroutine. The navigation context
supplies page-load headers for each request.

Set `Request.Context` when a request needs different headers:

```go
response, err := client.Do(ctx, phantom.Request{
    Method: "GET", URL: "https://example.com/api", Context: "fetch",
})
```

The same client keeps its connections and session. An empty request context
inherits the client default; `"raw"` omits the template for that request.
Available contexts are `"navigation"`, `"fetch"`, `"fetchNoStore"`, `"fetchUpload"`,
`"script"`, `"stylesheet"`, `"image"` and `"font"`, depending on the profile.
Supply required fields such as `Referer` and `Origin` in `Request.Headers`.
Unavailable contexts return a `request_template` error before sending.

## Read server-sent events

Use the same request options for an event-stream response, including POST bodies:

```go
response, err := client.Events(ctx, phantom.Request{
    Method: "GET", URL: "https://example.com/events", Context: "fetch",
}, nil)
if err != nil { return err }
defer response.Events.Close()
for {
    event, err := response.Events.Next()
    if err == io.EOF { break }
    if err != nil { return err }
    fmt.Println(event.Data)
}
```

Import `io` and `fmt` for this example. Reads use Rust's SSE decoder and stop
when `ctx` is cancelled. Nil limits allow 64 KiB lines and 1 MiB event blocks;
pass `SSELimits` to change them, up to 1 MiB and 8 MiB. Explicit zero rejects
nonempty input. `LastEventID` and `RetryMilliseconds` expose committed state.
This API reads one response and does not reconnect. Reconnecting EventSource
is not exposed yet. Content encoding must be `identity`.

SSE requires a matching native payload with the optional SSE ABI. Older payloads
return `native_sse_unavailable` before sending.

## Install

There are no public module tags or registry releases yet. Download a matching
candidate from the [installation workflow](../../.github/workflows/go-artifacts.yml).
Each archive pairs `module/` with `lib/`, licenses and a receipt. Keep that pair
together and add the local `replace` described in its README.

Candidates cover Windows x64 MSVC, Linux x64 GNU and macOS arm64. Check the
receipt for source, checksums and tested hosts. Windows needs the x64 Visual C++
v14 runtime at least as recent as the recorded build tools; runtime DLLs are
not bundled. Keep the included notices when redistributing.

## Build from source

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

Set `PHANTOM_GO_LIBRARY` to the native library's absolute path, or place it
beside your executable. Use `phantom_go.dll` on Windows, `libphantom_go.so`
on Linux, or `libphantom_go.dylib` on macOS. Go builds do not need cgo or a
C compiler. The native library remains loaded for the process lifetime.

Phantom checks its ABI and package version once, before creating native
resources. A mismatch returns `*Error` with `Kind` `native_abi_mismatch` or
`native_version_mismatch`. Install the matching library and restart the process.
Set `PHANTOM_GO_LIBRARY` before the first native operation.

## Request settings

`Protocol` accepts `h1`, `h2`, `h3` or `negotiated`. Exact protocols fail when
unsupported by a route. Direct H2 with an HTTP URL uses cleartext prior
knowledge. Add `Context: "navigation"` or `"fetch"` for the catalog's template;
an empty context uses caller headers only.

Headers are ordered `[]Header` values, including duplicates. Names and byte
values retain template placement rules; use lowercase caller names for H2/H3.
`Sensitive` requests never-indexed compression, subject to cookie policy.
`Request.Trailers` retains the same order and spelling after the body. H1 uses
chunked coding; H2/H3 names must be lowercase. `Request.ExpectContinue` opts into
waiting for `100 Continue` after sending the head. Supply a nonnegative
`*time.Duration`; nil disables it, and zero sends without waiting. A final
response received while waiting suppresses body transmission. Existing upload
prefetch can still occur.

## Read a response

`Response.Headers` retains received order, raw bytes and `Sensitive` markers.
A false marker can mean the protocol decoder did not retain it. HTTP error
statuses remain responses; inspect `Status` before consuming the body.

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
serialized.

`Response.Trailers()` returns an owned ordered snapshot: pending until observed
validated EOF, complete (possibly empty) after EOF, or unavailable after early
close/body failure. It never drains and survives close; projection exceeding the
256 KiB native JSON reply limit returns an error.

## Send a body

Byte uploads use replayable `Request.Body`, limited to 8 MiB.

Use `PrepareForm(fields, maximumBytes)` for ordered form fields, or
`PrepareMultipart(parts, boundary, maximumBytes)` for text and byte parts.
Set `Request.PreparedBody` and place its `ContentType()` in your headers,
unless your template provides a matching slot. Duplicate fields stay ordered.
Close the prepared body after use; attached requests retain their bytes.
Prepared bodies keep the 8 MiB body and 64 KiB metadata-command limits.
At most 64 prepared bodies may be open; `Close` releases that capacity.

For larger uploads, set `Request.Upload` to an `io.ReadCloser`, such as an open
file. `Do` takes ownership and closes it once, including on validation failure.
Its `Close` must unblock a concurrent `Read`. Set `UploadLength` for an exact
byte count, or leave it nil for unknown length. Unread suffixes are not validated.
Streaming uses bounded chunks and cannot be combined with `Body`. A reader is
one-shot; retries cannot reopen it. Cancellation and the total deadline remain
active after an early response.

Use `Request.Multipart = &StreamingMultipart{Boundary: "upload",
MaximumBytes: maximum, Parts: []MultipartPart{MultipartText("tag", "value"),
MultipartReader("file", file).WithFilename("input.bin")}}` for ordered streaming
multipart. Place its `ContentType()` explicitly as above. The encoded length is
unknown; the maximum includes framing. At most 1024 parts use one upload handle
and one active reader with a 64 KiB source chunk. Count rejection leaves readers
caller-owned; otherwise `Do` closes active and unstarted readers once, even on
validation failure. `Close` must unblock `Read`. Do not reuse readers. Text/byte
fields retain the 8 MiB binary-input limit; metadata retains 64 KiB. Readers stream
up to the encoded maximum. Streaming multipart is one-shot, exclusive with
other body options, and cannot be used with `PrepareMultipart`.

## Observe a request

Create an observer with `NewRequestDiagnostics(128)` and check its error. Set
`Request.Diagnostics` and retain the owner to call `Snapshot()`, including after
send failure. Each owner is single-use.
Snapshots distinguish response headers from body completion and keep unavailable
phases absent. Timings are exact monotonic offsets, with connection and TLS facts
on connection-use events. Oversized snapshots fail explicitly; `Close` releases
the observer handle without cancelling the request.

## Cancellation and shutdown

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

## Routing and trust

`Config.BaseURL` joins relative request URLs; a trailing slash appends to its
directory. Routing is direct unless `Proxy` selects HTTP(S), SOCKS4(a) or
SOCKS5(h). Proxy environment variables are ignored. Set `ProxyCredentials` for
HTTP Basic or SOCKS5 username/password auth, separately from the URI.
`AdditionalRootsDER` and `ProxyAdditionalRootsDER` separately extend origin
and HTTPS-proxy trust while retaining certificate verification.
`Config.Network` selects ordered `HostOverrides` (host plus `[]netip.Addr`),
`LocalAddresses` and an optional `Interface`. Overrides retain the original
host for TLS and HTTP; the last duplicate wins, and an empty address list fails
resolution. Source bindings never fall back to unbound sockets of another family.
On Unix, set `NetworkOptions.UnixSocket` to a socket path for direct HTTP/1 or
HTTP/2, retaining the URL's HTTP and verified TLS identity. Use an absolute path;
host overrides, source bindings, proxies, HTTP/3 and session checkpoints are
unsupported with this transport. Windows returns `unsupported_platform`.
`ServerSPKIPins` and `ProxyServerSPKIPins` add separate origin/proxy policies.
Supply one to 32 `[32]byte` SHA-256 digests of the leaf DER SubjectPublicKeyInfo;
normal certificate and hostname verification still apply. Nil omits a policy;
a non-nil empty slice is invalid. Proxy pins require TLS when a proxy is used,
while direct routes remain usable.

`ParseClientCertificatePEM(chain, key)` or `ParseClientCertificateDER(chain, key)`
creates an immutable origin identity from bytes, without file I/O. Set
`Config.ClientCertificate` and optional ordered `ClientCertificatesFor` overrides;
normal server verification remains enabled. Close the owner after constructing
clients; their identities remain valid. Parsing allows 8 MiB aggregate input,
1..256 DER certificates and 64 open owners; configuration allows 256 origin
mappings within its 64 KiB command. Keys must be unencrypted. Outer proxy mTLS,
custom connectors and CONNECT-UDP are not exposed.

## Cookies and checkpoints

Cookies are enabled unless `DisableCookies` is set. Use `SetCookie`,
`CookiesForURL` and `ClearCookies`. Matching uses top-level navigation semantics,
independently of the header template.

`ExportSession(ctx, key)` returns encrypted checkpoint bytes; `key` is a secret
random `[32]byte`. `RestoreSession(ctx, bytes, key, receivingRoutes)` returns
independent pools using the receiver's compatible settings, never changing it.
Checkpoints contain enabled cookies, direct Alt-Svc and TLS tickets, within
32 MiB. Address DNS, client hints and racing history start empty.
`SessionRoute{}` means direct; its proxy fields follow `Config` rules. Expiry,
capacity and isolation are checked on restore. `SessionSnapshotError`
retains the typed core kind and wraps `*Error`; unsupported state is rejected.
These CPU-only calls cannot be preempted once running; context cancellation
discards any unpublished result. Configuration and file I/O are not serialized.

## Budgets, deadlines and retries

Create `NewAttemptBudget(maximum)` and attach it as `Request.Budget` across
clients. Initial origin attempts and internal resends spend it atomically.
Admissions are not refunded, even if no bytes are sent. DNS/setup/proxy
negotiation are separate. Use `TryAdmit()` for attempts outside Phantom only.
Close the budget handle when finished; in-flight requests retain it.

Client/request `Timeouts` has `PoolAdmission`, `Connect`, `ResponseHead`,
`ReadIdle` and `Total`. Use `LimitTimeout(duration)`,
`Timeout{Mode: TimeoutDisabled}`, or default `TimeoutInherit`. Request fields
inherit the client; client limits start disabled. `Connect` includes setup,
`ResponseHead` includes upload and `Total` includes body reads. Total zero
rejects before sending; other zero phase timers can race ready work.
The older `Timeout` field uses milliseconds with a one-millisecond minimum;
do not combine it with explicit `Timeouts.Total`.

`*Error` exposes redacted `Kind`, protocol and timeout phase when known.
Messages omit URLs, credentials and native source chains. Responses retain
`EffectiveURL`, `RedirectsFollowed` and `ConnectionSetupRetries`; the last
counter covers caller-enabled setup retries only.

`Config.RedirectPolicy` and `RetryPolicy` default to disabled. Set
`RedirectPolicy{MaximumHops: 5}` to follow redirects. Add
`CredentialHeaders: []string{"x-api-key"}` to strip custom secrets permanently
when a redirect changes origin. Standard credentials are always stripped.
Use `NetworkOptions{PublicOnly: true}` to admit only public IPs for new direct
connections. Proxies and custom streams are unsupported; live pools stay usable.
Use `StatusRetry` or
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
import errors expose redacted `Kind` and `Field`. Imports have no catalog identity.
`Context: "profile"` selects an attached template;
`raw` omits it, and named contexts require catalog ownership.

`ImportJA3Profile`, `ImportAkamaiProfile`, `ImportJA4Profile`,
`ImportClientHelloProfile` and `ImportQUICTransportProfile` require a base
`*Profile`. Results contain `Profile`, `ObservedFields` and `SupplementedFields`;
close the returned profile owner. JA3/JA4 take raw descriptions, not hashes.
JA4 requires `JA4Sorted` or `JA4Original`. ClientHello bytes include the
four-byte handshake header without TLS records; QUIC bytes are extension 57's
payload. Missing settings come from the explicit base.

## Fork session state

`worker, err := client.Fork(phantom.SessionSharing{Cookies: true, DNS: true})`
creates independent pools sharing selected live state. Close each client.
Selectors are `Cookies`, `DNS`, `ClientHints`, `Discovery` and `Tickets`; the
zero value shares nothing. Selected changes, expiry and clears are shared;
other state starts empty. Sharing does not enable disabled features. Profile,
routes, trust and timeouts are retained; admission and shutdown are independent.
Shared tickets remain single-use. Forks use ordinary client capacity. Go cannot
fork a released owner after successful shutdown.

## Transfer limits and counters

Create `NewTransferControl(TransferLimits{UploadBytes: &maximum})`, check its
error, and attach the owner with `Request.TransferControl`. Close the owner
when finished; already attached requests retain their policy. Share it across
requests or clients for one allowance. `Snapshot` returns coherent counters.
Unset fields are unlimited. Rates are positive body bytes per second.
Download caps count encoded data; decoded counters can include the body's
unread buffer. Headers and transport overhead are excluded. Cancellation
retains paced reservations and their gaps in the shared schedule.

## Capacity and feature limits

Set `Config.Pool` to a `PoolOptions` value for per-origin active/pending bounds,
H2/H3 connection counts and retained pool entries. Nil fields preserve defaults;
count pointers must be positive. `NegotiatedSetupWaitLimit` is a duration pointer
(nil waits for the existing handshake; zero permits a competing connection).
These core limits are separate from the binding capacities below.

Process-wide limits are 64 each for clients, budgets and transfer controls.
Pending requests and open responses share 64 response slots. A request reserves
its slot before sending; close or finish responses to admit more requests.
Ordinary operations, body reads and shutdowns each have 64 separate slots, so
pending requests cannot prevent an existing response from being read.
Exhaustion returns a typed error without waiting. Byte uploads allow 8 MiB each
and 16 MiB total in native buffers until responses close. Metadata limits are
64 KiB per command, 256 response fields/32 KiB and 256 KiB per reply.

## Next

See the [library guides](../../crates/phantom/src/docs/overview.md) for the
underlying protocols and profiles.
