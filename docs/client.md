# Using the client

This guide is for integrators. It explains the public client model and the
choices that affect requests; packet-level details live elsewhere.

## The three layers

| Layer | Owns |
| --- | --- |
| Profile | Immutable TLS, HTTP/2, HTTP/3, QUIC, and client-hint wire settings |
| Client | Pools, route defaults, trust, limits, redirects, cookies, learned hints, and TLS sessions |
| Request | Method, URL, ordered fields and static trailers, body, protocol, route override, and timeout override |

Built-in and custom profiles use the same typed model. A recipe name records
capture provenance; it does not make the runtime branch on browser family or
host operating system.

## Configure policy once

Client policy is immutable after `build`; request policy can replace only the
documented per-request settings.

```rust
use std::{num::NonZeroUsize, time::Duration};

use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, RedirectPolicy, RequestTimeouts};

fn build() -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v152_macos_tls())
        .with_http2(chromium::v152_macos_http2());
    let timeouts = RequestTimeouts::new()
        .connect(Duration::from_secs(10))
        .response_head(Duration::from_secs(20))
        .read_idle(Duration::from_secs(30))
        .total(Duration::from_secs(60));

    let client = Client::builder(profile)
        .redirect_policy(RedirectPolicy::limited(
            NonZeroUsize::new(5).expect("five is nonzero"),
        ))
        .request_timeouts(timeouts)
        .build()?;
    Ok(client)
}
```

Every timeout and redirect is disabled until configured. Pool and client-hint
limits have finite defaults and can be tightened on `ClientBuilder`.

## Choose a protocol

- `get` and `request` select exactly H1, H2, or H3.
- `get_negotiated` and `request_negotiated` perform one direct TLS handshake
  and select H2 for `h2`, or H1 for `http/1.1` or absent ALPN.
- H3 uses a separate QUIC path and accepts direct routes only.

Unsupported combinations fail explicitly before another protocol or route is
attempted.

## Preserve request intent

`RequestHeader` preserves field-name spelling, value bytes, duplicates, and
global order. Ordinary methods can carry owned bytes or a pull-driven
`http_body::Body<Data = Bytes>`.

`RequestBuilder::trailers` adds an ordered static trailer block after successful
body completion. It works with exact H1, H2, and H3 requests and negotiated
H1/H2 requests:

```rust
use phantom::{Client, HttpProtocol, Method, RequestHeader};

async fn send(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .request(HttpProtocol::Http2, Method::POST, "https://example.com/upload")?
        .body("payload")
        .trailers(vec![
            RequestHeader::new("x-checksum", "first"),
            RequestHeader::new("x-token", "secret").sensitive(),
            RequestHeader::new("x-checksum", "second"),
        ])
        .send()
        .await?;

    drop(response);
    Ok(())
}
```

Trailer order, duplicate interleaving, and sensitivity are preserved. H1 also
preserves field-name spelling, uses chunked framing, and generates the
`Trailer` declaration; H2 and H3 require lowercase field names. Negotiated
requests must satisfy both H1 and H2 rules, so their trailer names must be
lowercase. Invalid or forbidden trailers fail before network I/O or body
polling. A body error suppresses the trailer block. Trailers produced
dynamically by a streaming body's `Frame::trailers` remain unsupported.

Owned bodies can be replayed where a configured redirect requires it.
Streaming bodies are one-shot. Phantom validates a supplied `Content-Length`;
unknown-length H1 uploads use chunked transfer coding, while H2 and H3 omit the
field.

Method-preserving redirects replay owned static trailers with the body. A
redirect that rewrites the request to GET clears both, and a cross-origin
redirect removes credential-bearing header and trailer fields before the next
attempt.

## Routes and proxies

Set a default route on `ClientBuilder`, or override it on one request. Supported
TCP routes are direct, unauthenticated HTTP/1.1 absolute-form forwarding over a
plaintext or TLS-encrypted proxy, HTTP/HTTPS CONNECT, and SOCKS5 with local or
proxy-owned DNS and optional credentials.

Forwarding is limited to exact HTTP/1.1 requests for `http://` origins. An
`https://` proxy endpoint verifies the proxy certificate and hostname with the
independent proxy trust store, then carries the absolute-form request inside
that TLS connection; the origin itself is still plain HTTP. Forwarding never changes to CONNECT,
negotiated H1/H2, H2, H3, or a direct route. Proxy credentials are not yet
accepted for forwarding. Unsupported combinations fail explicitly instead of
selecting another route or protocol.

The complete route participates in pool identity. Proxy failure never falls
back direct, and H3 rejects TCP-only proxy routes before network I/O. Proxy
credentials are validated before I/O and excluded from diagnostics.

This credential-bearing example applies to an HTTPS origin, where the route
uses CONNECT. The same credentials are rejected for an `http://` forwarding
request.

```rust
use phantom::{HttpProxy, Route};

fn route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = HttpProxy::new("https://proxy.example:8443")?
        .with_basic_auth("proxy-user", "proxy-password")?;
    let route = Route::http_proxy(proxy);
    Ok(route)
}
```

Add private DER roots with `add_root_certificate_der`; use
`add_proxy_root_certificate_der` for an HTTPS proxy, including a TLS-encrypted
forward proxy. The proxy and origin trust stores are independent. Certificate
and hostname verification remain enabled by default.

## Client-owned state

`Client` is cheap to clone. Clones share bounded state; independently built
clients do not.

- H1 connections are reused sequentially without pipelining.
- H2 and H3 multiplex within peer and local limits.
- Pool admission and retained connections are bounded per origin and route.
- Dropping one H2 or H3 request cancels its stream, not unrelated work.
- Redirects are disabled until a finite policy is configured.
- Cookies require the `cookies` feature and explicit builder activation.
- Learned `Accept-CH` state is bounded and scoped to the exact secure origin.

## Timeouts

Timeouts are disabled by default. Client or request policy can bound pool
admission, connection setup, response head, response-body inactivity, and the
whole operation across redirects and bounded replays. Errors identify the
phase and selected protocol.

## Responses

Every successful request returns `http::Response<ResponseBody>`. Its extensions
include `ResponseInfo` and `OrderedResponseHeaders`. The latter preserves
duplicate interleaving on every protocol and original field-name spelling on
H1.

The body is streaming and backpressured. Consume it to completion when you want
the connection to remain eligible for reuse.

`ResponseBody` implements `http_body::Body<Data = Bytes>`. Body errors use the
same `RequestError` type as request establishment. Dropping an incomplete H1
body may retire that connection; dropping an H2 or H3 body cancels its stream.

## Handle stable error categories

`BuildError::kind` and `RequestError::kind` provide non-exhaustive stable
categories. Request errors also expose the selected protocol and timeout phase
when known. Match the category you need and keep a fallback arm for future
variants.

```rust
use phantom::{RequestError, RequestErrorKind};

fn classify(error: &RequestError) -> &'static str {
    match error.kind() {
        RequestErrorKind::Timeout => "timeout",
        RequestErrorKind::Capacity => "local capacity",
        RequestErrorKind::Proxy => "proxy",
        RequestErrorKind::Tls => "tls",
        _ => "request",
    }
}
```

Errors and debug output intentionally omit credentials, cookies, payloads, and
endpoint details. Use bounded tracing or protocol diagnostics when deeper
evidence is required.

## Integration checklist

- Confirm the [distribution constraints](getting-started.md#distribution-status)
  are acceptable.
- Select only profile components listed in [Coverage](coverage.md).
- Run inside Tokio with I/O and time enabled.
- Configure route, origin trust, and proxy trust explicitly.
- Choose redirect and timeout policy; neither is inferred from a browser name.
- Treat streaming request bodies as one-shot and consume response bodies when
  reuse matters.
- Handle non-exhaustive error categories and avoid logging sensitive inputs.
- Enable cookies, SSE, or WebSocket only when the matching Cargo feature and
  lifecycle are required.

For optional APIs, see [Server-sent events](sse.md) and
[WebSocket](websocket.md). For exhaustive support and planned gaps, see
[Coverage](coverage.md).
