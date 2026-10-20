# Go binding

Reuse one native client for connection pools and cookies. Choose an exact
catalog profile and a protocol. Add `Context: "navigation"` or `"fetch"`
when you want that profile's request headers.

```go
client, err := phantom.New(phantom.Config{
    Profile: "chrome/154.0.8037.97/windows-11-26200/r1",
    Protocol: "h2",
    Timeout: 30 * time.Second,
})
if err != nil { return err }
defer client.Close()
response, err := client.Do(ctx, phantom.Request{Method: "GET", URL: url})
if err != nil { return err }
defer response.Body.Close()
data, err := response.Body.ReadAll(1024 * 1024)
```

`Protocol` accepts `h1`, `h2`, `h3`, or `negotiated`. Exact protocols fail
when the route cannot support them. Direct `h2` with an HTTP URL uses prior
knowledge. An empty `Proxy` selects direct connections. Explicit HTTP,
HTTPS, SOCKS4(a), and SOCKS5(h) proxy URLs use the Rust client's routing.
Proxy environment variables are ignored.
For HTTP Basic or SOCKS5 authentication, set `ProxyCredentials` to an explicit
`Username`/`Password` pair. It requires the matching proxy URL. Credentials in
URLs remain unsupported. HTTP authentication follows the native challenge and
credential-isolation rules. SOCKS4 credentials and Digest are not exposed.

`BaseURL` resolves relative request URLs. Include a trailing slash when you
want paths appended to its directory. Absolute request URLs override the base.
`AdditionalRootsDER` extends origin trust. `ProxyAdditionalRootsDER` separately
extends HTTPS-proxy trust. Both take DER certificates and retain hostname
verification. Neither bypasses verification or configures client certificates.

`Headers` is an ordered slice of names and byte values. Duplicate names
remain separate. Templates apply the public Rust API's placement rules.
Set `Header.Sensitive` for never-indexed HTTP/2 and HTTP/3 fields. A profile's
cookie-crumb policy can choose its own encoding. HTTP/1 field bytes are unchanged.
Response headers retain their received order, duplicates, and byte values.
Cookies are enabled unless `DisableCookies` is set. Use `SetCookie`,
`CookiesForURL`, and `ClearCookies` to manage them.
Cookie matching uses top-level navigation semantics. Selecting a fetch
template changes headers only.

Create an `AttemptBudget` and attach it to requests across clients. It is
the Rust client's shared allowance, including internal HTTP replays. Close
the budget handle when finished. In-flight requests retain their allowance.

Keep the request context alive until EOF or `Body.Close`. Cancelling it
also closes an already returned body. Reads pull at most 64 KiB through the
native boundary. EOF, a failed read, or close releases the body handle.
Body bytes retain content encoding; decompression is not automatic.
Read errors are terminal. `ReadAll` enforces your collection limit and
closes the body, including when the limit is invalid.
Concurrent calls to one body's `Read` are serialized;
`Close` can interrupt a blocked read.

`Shutdown(ctx)` closes admission and waits for active requests and bodies.
Close bodies you no longer need. Cancelling the wait leaves admission
closed. A retry can briefly return `shutdown_in_progress` while the old
wait settles. `Close` allows five seconds for graceful shutdown. Explicit
shutdown is preferred; finalizers provide eventual handle cleanup.

`CloseIdleConnections(ctx)` releases idle connections and keeps active work.
`RefreshConnections(ctx)` makes later requests select fresh connections while
existing work can finish. Both retain tickets and learned state. Cancelling a
maintenance call can leave some pools unvisited. Neither waits for old transport
drivers to stop. Use `ClearSessionTickets`, `ClearDNSCache`, `ClearClientHints`,
`ClearAltSvc` or `ClearAltSvcRacingHistory` when you need to forget that state.
Clearing caches does not close active connections or disable their configuration.

Client and request `Timeouts` contain `PoolAdmission`, `Connect`, `ResponseHead`,
`ReadIdle` and `Total`. Each field uses `LimitTimeout(duration)`, including zero,
`Timeout{Mode: TimeoutDisabled}`, or its default `TimeoutInherit`. Request fields
inherit client settings. Client fields start without limits. For example:

```go
config.Timeouts = phantom.Timeouts{
    Connect: phantom.LimitTimeout(10 * time.Second),
    Total: phantom.LimitTimeout(time.Minute),
}
request.Timeouts.ReadIdle = phantom.Timeout{Mode: phantom.TimeoutDisabled}
```

Finite zero is an expired limit, not disabling; a ready native operation can
still win. `Connect` covers DNS, proxy and TLS setup. `ResponseHead` includes
uploading. `Total` spans all attempts and the response body. The original
`Timeout` remains a total limit with millisecond precision and a one-millisecond
minimum. Do not combine a nonzero `Timeout` with an explicit `Timeouts.Total`.

`*Error` contains a redacted `Kind`, protocol, and timeout phase when known.
HTTP error statuses remain responses. Context cancellation returns Go's
context error. Error messages omit URLs, proxy credentials, and native
source chains.

Responses expose `EffectiveURL`, `RedirectsFollowed` and
`ConnectionSetupRetries` from the core response metadata. The last count
covers caller-enabled connection-setup retries across redirect hops, counted
when setup starts. It excludes redirects, status retries, reused-connection
and GOAWAY replays, proxy authentication, client hints and protocol fallback.
This Go facade keeps the core defaults: no automatic redirects or retries.
Redirect and retry policy setters are not exposed yet.

## Build and limits

Build the workspace package `phantom-go` with Rust 1.88 or later, including
the repository's native TLS prerequisites. The Go module requires Go 1.26.
On Windows amd64, set `PHANTOM_GO_LIBRARY` to the absolute path of
`target/debug/phantom_go.dll`, or put the DLL beside your executable.
Windows uses native DLL calls and does not require cgo. The DLL stays
loaded for the process lifetime.

Linux and macOS use cgo and require a C compiler. Point `CGO_LDFLAGS` and
your platform's dynamic loader at the built `libphantom_go` directory.

## Native installation candidates

The [Go installation workflow](../../.github/workflows/go-artifacts.yml)
prepares optimized candidates for Windows x64 MSVC, Linux x64 GNU and macOS
arm64. Each archive pairs `module/` sources with `lib/`, licenses and a
receipt. Keep that pair together. Add a local `replace` in your Go module
to the extracted `module/` directory, as the archive's README describes.
Windows uses `PHANTOM_GO_LIBRARY`; Unix uses the cgo and loader paths above.

Each successful receipt records source, lockfile, native library and archive
hashes, tools and native dependencies. Verification extracts outside the
checkout, builds a separate consumer and runs the existing Go controls
without skips. Only candidates passing those checks are uploaded. Failure
logs remain available. There are no public module tags or registry releases.

The receipt covers its recorded native host, not older OS/libc versions or
other architectures. Windows requires the Microsoft x64 Visual C++ v14
runtime, at least as recent as the recorded build tools. SDK/OS runtimes
are not bundled. Keep all included notices when redistributing an archive.

To prepare one locally from a clean checkout, run
`scripts/release/go_artifact.py` through `scripts/dev/with-cargo-lock.sh`
with `--target` and a new `--output` directory. This uses locked release
dependencies; the ordinary development gate still uses its debug build.

## Capacity and feature limits

This first slice has fixed process-wide caps: 64 clients, budgets, response
handles, and ordinary operations, plus 64 separately reserved shutdown
operations. Byte uploads are limited to 8 MiB each and 16 MiB of aggregate
native upload custody, retained conservatively until the response closes.
Command metadata is limited to 64 KiB. Response headers allow 256 fields
and 32 KiB of names and values. Encoded replies are limited to 256 KiB.
Capacity exhaustion returns a typed error without waiting for admission.

One shared Rust runtime runs requests. One Go completion pump blocks on a
native wakeup, using one OS thread. At most 64 completed ordinary operations
retain up to 64 KiB of body data each until Go accepts or cancels them.
These bounds exclude caller buffers, the native HTTP/TLS pools, and Go
responses already delivered to application code. They are capacity limits,
not a measured high-throughput claim.

Streaming uploads (`io.Reader` and files), custom profile definitions,
pinning/client certificates, custom connectors, CONNECT-UDP configuration, session
snapshots, and independent shared-state forks are not exposed in this slice.
