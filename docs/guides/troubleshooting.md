# Troubleshooting

Find the error or behavior you see, why Phantom produces it, and the fix.

> For builders and coding agents who have read [Using the client](client.md).

| You see | Section |
| --- | --- |
| A build script or link error from `btls-sys` | [The build fails compiling BoringSSL](#the-build-fails-compiling-boringssl) |
| `E0599`, `E0432`, or `E0004` from rustc | [Phantom code does not compile](#phantom-code-does-not-compile) |
| `BuildErrorKind::*` | [Building the client fails](#building-the-client-fails) |
| `Timeout`, `InvalidTimeout`, `RuntimeUnavailable`, or a request that never ends | [A request fails with a `Timeout` error](#a-request-fails-with-a-timeout-error) |
| `Connect`, `Http3`, or `Timeout` on an H3 request | [An HTTP/3 request fails where a browser would fall back](#an-http3-request-fails-where-a-browser-would-fall-back) |
| `UnsupportedRoute`, `ProtocolUnavailable` | [A negotiated request is rejected on a proxy route](#a-negotiated-request-is-rejected-on-a-proxy-route) |
| `UnsupportedScheme`, `Redirect` | [A request or redirect is rejected](#a-request-or-redirect-is-rejected) |
| `RequestBody` | [A streaming body cannot be sent again](#a-streaming-body-cannot-be-sent-again) |
| `RequestTemplate` | [A request template rejects the request](#a-request-template-rejects-the-request) |
| `InvalidUri`, `InvalidAuthority`, `InvalidTarget`, `InvalidHeader` | [A request field or URI is rejected](#a-request-field-or-uri-is-rejected) |
| `Resolve`, `Connect`, `Proxy`, `Tls`, `Capacity` | [The connection cannot be opened](#the-connection-cannot-be-opened) |
| `ResponseBodyLimit`, `ContentDecoding` | [Reading the body fails](#reading-the-body-fails) |
| A new connection for every request | [The connection is not reused](#the-connection-is-not-reused) |
| A WebSocket connect that never ends | [A WebSocket connect ignores the client's timeout](#a-websocket-connect-ignores-the-clients-timeout) |

## The build fails compiling BoringSSL

The first `cargo build` compiles BoringSSL in the `btls-sys` build script. It
fails when CMake, Clang, or a C++ toolchain is missing, and on Windows also
NASM or the Visual C++ build tools. Install the
[prerequisites](../getting-started.md#prerequisites);
[CONTRIBUTING.md](../../CONTRIBUTING.md#windows) lists the Windows `PATH`
entries for NASM and LLVM and when to set `LIBCLANG_PATH`. If Cargo reports
two packages that link `boringssl`, another dependency such as `boring-sys`
also builds it, and only one can be in the graph
([Adding Phantom to a project](downstream.md#limits)).

## Phantom code does not compile

```text
error[E0599]: no method named `websocket` found for reference `&Client`
error[E0432]: unresolved import `phantom::CookieJar`
error[E0004]: non-exhaustive patterns: `_` not covered
```

The cookie, SSE, and WebSocket APIs exist only with their Cargo features, and
none is on by default. Add `cookies`, `sse`, `websocket`, or `full` to the
`phantom` dependency ([Optional features](../getting-started.md#optional-features)).

Every error-kind enum and `TimeoutPhase` is non-exhaustive, so a `match`
needs a fallback arm:

```rust
use phantom::{RequestError, RequestErrorKind, TimeoutPhase};

fn describe(error: &RequestError) -> String {
    match (error.kind(), error.timeout_phase()) {
        (RequestErrorKind::Timeout, Some(TimeoutPhase::Connect)) => "setup timed out".into(),
        (RequestErrorKind::Timeout, Some(phase)) => format!("{phase:?} timed out"),
        (kind, _) => format!("{kind:?}"),
    }
}
```

## Building the client fails

`ClientBuilder::build` checks the profile and policies before any I/O.

| Kind | Cause and fix |
| --- | --- |
| `InvalidProfile` | A recipe value is invalid, or the host cannot apply it; Windows requires a TCP keepalive interval, for example. Fix the field the source error names ([Build a custom profile](profiles.md#build-a-custom-profile)). |
| `InvalidPolicy` | A timeout or retry delay exceeds the runtime clock, disabled server authentication meets added roots or HTTP/3, Alt-Svc racing lacks `alt_svc`, or Alt-Svc lacks negotiation or HTTP/3 settings. |
| `TrustStore` | A root passed to `add_root_certificate_der` or `add_proxy_root_certificate_der` could not be loaded. Pass DER bytes, not PEM text. |
| `ProtocolConfiguration`, `NoSupportedProtocol` | A protocol connector cannot represent the profile, or the profile enables no protocol the client implements. Start from a [built-in profile](profiles.md#choose-a-built-in-profile). |

## A request fails with a `Timeout` error

A phase ran past its `RequestTimeouts` limit, for example
`request connection setup timed out`. `RequestError::timeout_phase` names the
phase: `PoolAdmission`, `Connect`, `ResponseHead`, `ReadIdle`, or `Total`.
Timeouts are never retried. Raise that phase's limit, or `Total`
([Configure the client](client.md#configure-the-client)).

- A request that never ends has no timeout: timeouts are off by default.
- `InvalidTimeout`: a timeout or retry delay exceeds the runtime clock.
- `RuntimeUnavailable`: no Tokio runtime with I/O and time enabled. Run under
  `#[tokio::main]` or a runtime built with `enable_all()`.

## An HTTP/3 request fails where a browser would fall back

A browser that cannot reach a server over QUIC uses TCP. When UDP is
blocked, an exact H3 request in Phantom fails, usually with `Connect`,
`Http3`, or a `Connect`-phase `Timeout`. A negotiated request whose learned
H3 alternative fails returns an H3 error and evicts the advertisement; it is
not resent over HTTP/1.1 or HTTP/2.

To behave like Chrome, send negotiated requests with Alt-Svc racing, so the
origin connection wins when QUIC fails
([Race the alternative against the origin](http3-discovery.md#race-the-alternative-against-the-origin)).
To fall back yourself, catch the error and send a new request on another
protocol; that request has a different fingerprint.

## A negotiated request is rejected on a proxy route

`get_negotiated` and `request_negotiated` fail with `UnsupportedRoute` on a
CONNECT-UDP route, which carries only QUIC, and exact H3 fails the same way
on an HTTP proxy, whose tunnel carries only TCP. Use a route that carries the
protocol ([route matrix](../reference/route-matrix.md)). Negotiated requests
through an HTTP proxy stay on H1 or H2 and learn no Alt-Svc alternative; for
the H3 upgrade through a proxy, use SOCKS5.

`ProtocolUnavailable` means the profile lacks a component the request needs:
HTTP/3 settings for H3, or both HTTP/1.1 and HTTP/2 for a negotiated request.
Add the recipe to the profile.

## A request or redirect is rejected

`UnsupportedScheme` means a scheme other than `http` or `https`, or an
`http://` URI with exact H2 or H3. Send plaintext with `HttpProtocol::Http1`
or `get_negotiated`, except through an HTTP proxy with
`with_http2_transport`, which needs `HttpProtocol::Http2` or
`get_negotiated`. CONNECT-UDP carries no plaintext (`UnsupportedRoute`).

`Redirect` means a target that is not `http://` or `https://`, more than one
`Location`, or an exhausted limit; the redirect response is not returned.
Raise the limit, or use `RedirectPolicy::none()` and follow the hop yourself
([Follow redirects](redirects.md#follow-redirects)).

## A streaming body cannot be sent again

A body from `streaming_body` is sent at most once. A 307 or 308 redirect or
a `Critical-CH` retry that needs it again fails with `RequestBody` before the
second attempt starts. Send an owned body with `body` when the request may be
resent. `RequestBody` also reports an error from your own body stream.

## A request template rejects the request

`RequestTemplate` means the template cannot place a field the request would
send: no HTTP/3 list for a request that may use H3, no slot for the profile's
client hints, or conflicting `Accept-Encoding` values with decoding on.
Firefox templates have neither an HTTP/3 list nor hint slots
([Template limits](../reference/profiles.md#template-limits)). It also means
a required caller slot is empty: the Edge templates require your `User-Agent`
([Required caller fields](../reference/profiles.md#required-caller-fields)).

Invalid template data fails earlier, at `PreparedRequestTemplate::new`, with
`InvalidRequestTemplate`.

## A request field or URI is rejected

Each fails before any I/O. `InvalidHeader`: you supplied `Host`, which
Phantom derives from the URI; a malformed `Accept-Encoding` with decoding on;
an `Alt-Used` field; or `Proxy-Authorization` on an `http://` request unless
the route is an HTTP proxy without configured credentials. `InvalidTarget`:
the URI has a fragment, or its path or query is not a valid request target.
`InvalidUri`, `InvalidAuthority`: the URI, host, or port does not parse.

## The connection cannot be opened

| Kind | Cause |
| --- | --- |
| `Resolve` | DNS returned no address, locally or through a `socks5h://` proxy |
| `Connect` | The TCP connect or QUIC setup to the origin failed |
| `Proxy` | The proxy refused the connection, rejected credentials, or failed negotiation |
| `Tls` | The handshake failed, the certificate is not trusted, or ALPN chose an unsupported protocol |
| `Capacity` | More requests wait for one origin than its `max_pending_*_requests_per_origin` bound allows (100 per protocol by default); limit concurrency or raise the [bound](../reference/limits.md#connection-pools) |

Phantom never tries another proxy, route, or protocol after these.
`RetryPolicy::connection_failures` retries failed connects and resolution on
the same route; TLS, proxy authentication, and proxy rejection are never
retried ([Retries and replays](retries.md#retry-when-a-connection-fails-to-open)).
For a private CA, [add its root](routes-and-proxies.md#trust-a-private-root-or-a-proxys-root).

## Reading the body fails

`ResponseBodyLimit` means the body passed the limit given to
`collect_with_limit`, which then drops the body. Raise the limit or read
frame by frame. `ContentDecoding` appears on the first body read, with
decoding on, for a coding the request did not advertise, an unknown coding,
or corrupt data. Browsers pass unknown codings through; Phantom does not
([Content decoding](content-decoding.md#limits)).

## The connection is not reused

A body dropped before its end can close an H1 connection, so read bodies to
the end. Pools are keyed by origin and complete route, retain 32 entries by
default, and belong to one client: clone it instead of building another
([Share a client between tasks](connections-and-state.md#share-a-client-between-tasks)).

## A WebSocket connect ignores the client's timeout

WebSocket connects apply none of the client's timeouts, retries, or
redirects. Wrap the connect in `tokio::time::timeout`
([Bound a connect with a timeout](websocket.md#bound-a-connect-with-a-timeout)).
WebSocket, SSE, cookie, and proxy errors have their own kinds.

## Next

- [Responses and errors](responses.md#handle-errors): sort errors by kind in
  code.
- [Defaults and limits](../reference/limits.md): every bound and default.
- [Route matrix](../reference/route-matrix.md): what each route carries.
