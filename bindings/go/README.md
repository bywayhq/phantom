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
Proxy credentials are not exposed in this slice.

`Headers` is an ordered slice of names and byte values. Duplicate names
remain separate. Templates apply the public Rust API's placement rules.
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
closes the body. Concurrent calls to one body's `Read` are serialized;
`Close` can interrupt a blocked read.

`Shutdown(ctx)` closes admission and waits for active requests and bodies.
Close bodies you no longer need. Cancelling the wait leaves admission
closed. A retry can briefly return `shutdown_in_progress` while the old
wait settles. `Close` allows five seconds for graceful shutdown. Explicit
shutdown is preferred; finalizers provide eventual handle cleanup.

`*Error` contains a redacted `Kind`, protocol, and timeout phase when known.
HTTP error statuses remain responses. Context cancellation returns Go's
context error. Error messages omit URLs, proxy credentials, and native
source chains.

## Build and limits

Build the workspace package `phantom-go` with Rust 1.88 or later, including
the repository's native TLS prerequisites. The Go module requires Go 1.26.
On Windows amd64, set `PHANTOM_GO_LIBRARY` to the absolute path of
`target/debug/phantom_go.dll`, or put the DLL beside your executable.
Windows uses native DLL calls and does not require cgo. The DLL stays
loaded for the process lifetime.

Linux and macOS source uses cgo. Point `CGO_LDFLAGS` and your platform's
dynamic loader at the built `libphantom_go` directory. Platform packaging
and these Unix paths require their own verification; no binary release is
provided here.

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
custom trust/connector configuration, CONNECT-UDP configuration, session
snapshots, and independent shared-state forks are not exposed in this slice.
