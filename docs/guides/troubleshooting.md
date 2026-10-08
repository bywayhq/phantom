# Troubleshooting

Find what you see, its likely cause, and the fix. Read
[Using the client](client.md) first if you haven't built a client yet.

| You see | Go to |
| --- | --- |
| A site blocks or challenges the request | [A site blocks the request even with a Chrome profile](#a-site-blocks-the-request-even-with-a-chrome-profile) |
| A build error from `btls-sys` | [The build fails compiling BoringSSL](#the-build-fails-compiling-boringssl) |
| `E0599`, `E0432` or `E0004` from rustc | [Phantom code does not compile](#phantom-code-does-not-compile) |
| `BuildErrorKind::*` | [Building the client fails](#building-the-client-fails) |
| `Timeout`, or a request that never ends | [A request fails with a `Timeout` error](#a-request-fails-with-a-timeout-error) |
| `Connect` or `Http3` on HTTP/3 | [An HTTP/3 request fails where a browser would fall back](#an-http3-request-fails-where-a-browser-would-fall-back) |
| `UnsupportedRoute`, `ProtocolUnavailable` | [A negotiated request is rejected on a proxy route](#a-negotiated-request-is-rejected-on-a-proxy-route) |
| `UnsupportedScheme`, `Redirect` | [A request or redirect is rejected](#a-request-or-redirect-is-rejected) |
| `RequestBody` | [A streaming body cannot be sent again](#a-streaming-body-cannot-be-sent-again) |
| `RequestTemplate` | [A request template rejects the request](#a-request-template-rejects-the-request) |
| `InvalidHeader`, `InvalidUri`, `InvalidTarget` | [A request header or URI is rejected](#a-request-header-or-uri-is-rejected) |
| `Resolve`, `Connect`, `Proxy`, `Tls`, `Capacity` | [The connection cannot be opened](#the-connection-cannot-be-opened) |
| `ResponseBodyLimit`, `ContentDecoding` | [Reading the body fails](#reading-the-body-fails) |
| A new connection for every request | [The connection is not reused](#the-connection-is-not-reused) |
| A WebSocket connect that never ends | [A WebSocket connect ignores the client's timeout](#a-websocket-connect-ignores-the-clients-timeout) |

## A site blocks the request even with a Chrome profile

The request probably doesn't look like Chrome in every part. A profile sets
how the connection looks. The headers come from elsewhere. Check these:

- No request template. Without one, Phantom sends only the headers you add,
  plus client hints, and no `User-Agent`. Add the browser's page-load
  template ([Request templates](request-templates.md#apply-a-captured-request-template)).
- Parts from different browsers or versions, such as a Chrome 154 profile
  with a Chrome 153 `User-Agent`. Take the profile, template, client hints
  and `User-Agent` from one browser version.
- A protocol the browser wouldn't use, such as HTTP/1.1 to a site Chrome
  reaches over HTTP/2. Use `get_negotiated`, or the protocol the browser
  uses.
- Signals Phantom doesn't control. Phantom doesn't run JavaScript, so it
  can't pass a JavaScript challenge. Your IP address also counts.

To see the difference, request the same test page from your browser and
from Phantom, and compare
([See your own fingerprint](../fingerprinting.md#see-your-own-fingerprint)).

## The build fails compiling BoringSSL

The first build compiles BoringSSL, which needs CMake, Clang and a C++
compiler, plus NASM on Windows. Install the
[prerequisites](../getting-started.md#prerequisites).

If Cargo reports two packages that link `boringssl`, another dependency,
such as `boring-sys`, builds it too. Only one can be in your build
([Adding Phantom to a project](downstream.md#limits)).

## Phantom code does not compile

```text
error[E0599]: no method named `websocket` found for reference `&Client`
error[E0432]: unresolved import `phantom::CookieJar`
error[E0004]: non-exhaustive patterns: `_` not covered
```

The cookie, SSE and WebSocket APIs need their Cargo features, and none is
on by default. Add `cookies`, `sse`, `websocket` or `full` to the `phantom`
dependency ([Optional features](../getting-started.md#optional-features)).

New error kinds can appear in later versions, so a `match` on an error kind
or `TimeoutPhase` needs a fallback arm:

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

`ClientBuilder::build` checks the profile and settings. The source error
names the value at fault.

| Kind | Likely cause | Fix |
| --- | --- | --- |
| `InvalidProfile` | A recipe value is invalid or unsupported on this OS | Fix the value ([Build a custom profile](profiles.md#build-a-custom-profile)) |
| `InvalidPolicy` | Settings that conflict, or a delay too long for the runtime clock | Fix the setting the error names |
| `TrustStore` | A root certificate in PEM text | Pass DER bytes |
| `ProtocolConfiguration`, `NoSupportedProtocol` | A profile Phantom can't use | Start from a [built-in profile](profiles.md#choose-a-built-in-profile) |

## A request fails with a `Timeout` error

A step of the request took longer than its limit.
`RequestError::timeout_phase` tells you which one. Raise that limit, or the
total ([Configure the client](client.md#configure-the-client)).

A request that never ends has no timeout, because timeouts are off by
default. Set one.

## An HTTP/3 request fails where a browser would fall back

UDP is probably blocked. A browser then switches to TCP, but Phantom stays on
the protocol you asked for. It fails, usually with `Connect`, `Http3` or a
`Timeout`.

For an HTTP/3 request, set `RetryPolicy::with_http2_fallback`
([Fall back to HTTP/2 when QUIC fails](http3.md#fall-back-to-http2-when-quic-fails)).
For a negotiated request, turn on Alt-Svc racing, as Chrome does
([Race the alternative against the origin](http3-discovery.md#race-the-alternative-against-the-origin)).

## A negotiated request is rejected on a proxy route

`UnsupportedRoute` means the route can't carry the protocol. A CONNECT-UDP
proxy carries only HTTP/3. An HTTP proxy carries only HTTP/1.1 and HTTP/2.
Pick a route that carries what you need, such as SOCKS5 for HTTP/3
([route matrix](../reference/route-matrix.md)).

`ProtocolUnavailable` means the profile lacks a recipe the request needs.
HTTP/3 needs HTTP/3 settings. A negotiated request needs both HTTP/1.1 and
HTTP/2. Add the missing recipe to the profile.

## A request or redirect is rejected

`UnsupportedScheme` means the URL isn't `http` or `https`, or it's an
`http://` URL sent as exact HTTP/2 or HTTP/3. Send `http://` URLs with
`HttpProtocol::Http1` or `get_negotiated`. An HTTP/2 proxy route works
differently ([route matrix](../reference/route-matrix.md)).

`Redirect` means a redirect went to a scheme other than `http` or `https`,
had more than one `Location`, or passed the redirect limit. Raise the limit,
or turn off redirects with `RedirectPolicy::none()` and follow them yourself
([Follow redirects](redirects.md#follow-redirects)).

## A streaming body cannot be sent again

A body from `streaming_body` can be sent only once. A 307 or 308 redirect,
or a client-hint retry, would need it again. Use `body` with owned bytes
when the request might be resent.

## A request template rejects the request

The template has no place for a header the request would send. Common
causes:

- A required slot is empty, such as `User-Agent` for the Edge, Brave and
  Opera templates. Add the header
  ([Required caller fields](../reference/profiles.md#required-caller-fields)).
- The profile sends client hints and the template has no slots for them, as
  with a Chrome profile and a Firefox template. Take both from one browser
  ([Template limits](../reference/profiles.md#template-limits)).
- The request may use HTTP/3, and the template has no HTTP/3 list.

## A request header or URI is rejected

`InvalidHeader` most often means you set `Host`. Phantom sets it from the
URL, so remove yours. Phantom also rejects `Alt-Used`. On `http://`
requests it rejects `Proxy-Authorization` too, unless the route is an HTTP
proxy with no credentials of its own.

`InvalidTarget` means the URL has a `#fragment` or an invalid path or
query. `InvalidUri` and `InvalidAuthority` mean the URL, host or port
doesn't parse.

## The connection cannot be opened

| Kind | Likely cause |
| --- | --- |
| `Resolve` | No DNS address for the host |
| `Connect` | TCP or QUIC connect to the server failed |
| `Proxy` | Proxy refused, rejected credentials or failed |
| `Tls` | Failed handshake or untrusted certificate |
| `Capacity` | Too many requests waiting for one origin ([pool limits](../reference/limits.md#connection-pools)) |

To retry failed connects on the same route, use
`RetryPolicy::connection_failures`
([Retries and replays](retries.md#retry-when-a-connection-fails-to-open)).
For a server with a private CA,
[add its root](routes-and-proxies.md#trust-a-private-root-or-a-proxys-root).

## Reading the body fails

`ResponseBodyLimit` means the body was larger than the limit you gave
`collect_with_limit`. Raise the limit, or read the body frame by frame.

`ContentDecoding` means decoding is on and the response used a compression
you didn't list in `Accept-Encoding`, an unknown one, or corrupt data
([Content decoding](content-decoding.md#limits)).

## The connection is not reused

A body you drop before the end can close an HTTP/1.1 connection, so read
bodies to the end. Each client has its own pool, so clone one client
instead of building new ones
([Share a client between tasks](connections-and-state.md#share-a-client-between-tasks)).

## A WebSocket connect ignores the client's timeout

WebSocket connects don't use the client's timeouts, retries or redirects.
Set `WebSocketRequestBuilder::handshake_timeout` instead
([Bound a connect with a timeout](websocket.md#bound-a-connect-with-a-timeout)).

## Next

- [Responses and errors](responses.md#handle-errors): handle errors by kind
  in code.
- [Defaults and limits](../reference/limits.md): every limit and default.
- [Route matrix](../reference/route-matrix.md): what each route carries.
