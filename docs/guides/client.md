# Using the client

This guide explains how to configure a `Client` and send requests with it. It
assumes you have finished [Getting started](../getting-started.md). Focused
guides cover [routes and proxies](routes-and-proxies.md),
[retries](retries.md), [connections, redirects, and cookies](connections-and-state.md),
[HTTP/3 and Alt-Svc](http3.md), [content decoding](content-decoding.md), and
[browser profiles](profiles.md).

## Key terms

- **Profile**: an immutable description of what the client puts on the wire:
  TLS ClientHello, HTTP/2 and HTTP/3 settings, QUIC transport parameters, and
  client hints. See [Browser profiles](profiles.md).
- **Recipe**: a built-in profile component captured from a real browser, such
  as `chromium::v152_tls()`.
- **H1, H2, H3**: HTTP/1.1, HTTP/2, and HTTP/3.
- **Exact protocol**: the request uses the protocol you chose, or fails. It
  never falls back to another one.
- **Negotiated**: one TLS handshake lets the server choose H1 or H2 through
  ALPN (the TLS extension that selects an application protocol).
- **Route**: how the client reaches the origin: directly or through an HTTP,
  SOCKS5, or CONNECT-UDP proxy.
- **Origin**: the scheme, host, and port of a URL.

## The three layers

| Layer | Owns |
| --- | --- |
| Profile | Immutable TLS, HTTP/2, HTTP/3, QUIC, and client-hint wire settings |
| Client | Pools, route defaults, trust, limits, redirects, connection retries, cookies, learned hints and alternatives, and TLS sessions |
| Request | Method, URL, ordered fields and trailers, body, protocol, route, retry, and timeout overrides |

Built-in and custom profiles use the same typed model. A recipe name records
where the capture came from; it does not make the runtime branch on browser
family or host operating system.

## Configure policy once

Client policy is fixed after `build`. A request can replace only the settings
documented as per-request: route, timeouts, retry policy, and content decoding.

```rust
use std::{num::NonZeroUsize, time::Duration};

use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, RedirectPolicy, RequestTimeouts, RetryPolicy};

fn build() -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v152_tls())
        .with_http2(chromium::v152_http2());
    let timeouts = RequestTimeouts::new()
        .connect(Duration::from_secs(10))
        .response_head(Duration::from_secs(20))
        .read_idle(Duration::from_secs(30))
        .total(Duration::from_secs(60));

    let client = Client::builder(profile)
        .redirect_policy(RedirectPolicy::limited(
            NonZeroUsize::new(5).expect("five is nonzero"),
        ))
        .retry_policy(RetryPolicy::connection_failures(
            NonZeroUsize::new(2).expect("two is nonzero"),
            Duration::from_millis(100),
        ))
        .request_timeouts(timeouts)
        .build()?;
    Ok(client)
}
```

Timeouts, redirects, and connection retries are all disabled until you
configure them. Pool and client-hint limits have finite defaults, listed in
[Defaults and limits](../reference/limits.md), that `ClientBuilder` can replace
with any nonzero value. `Client::retry_policy` and `Client::request_timeouts`
return the configured client defaults.

## Choose a protocol

- `get` and `request` select exactly H1, H2, or H3.
- `get_negotiated` and `request_negotiated` perform one direct TLS handshake
  and select H2 for `h2`, or H1 for `http/1.1` or absent ALPN. With bounded
  Alt-Svc enabled, a later negotiated request can select a learned H3 endpoint
  (see [HTTP/3 and Alt-Svc](http3.md)).
- H3 uses a separate QUIC path and accepts direct routes, local-/remote-DNS
  SOCKS5 through RFC 1928 UDP ASSOCIATE, or an RFC 9298 CONNECT-UDP proxy.

Unsupported combinations fail explicitly before another protocol or route is
attempted. The [route matrix](../reference/route-matrix.md) lists every
scheme, protocol, and route combination.

## Send fields, bodies, and trailers

`RequestHeader` preserves field-name spelling, value bytes, duplicates, and
global order. Ordinary methods can carry owned bytes or a pull-driven
`http_body::Body<Data = Bytes>`.

Owned bodies can be replayed where a configured redirect requires it.
Streaming bodies are one-shot. Phantom validates a supplied `Content-Length`;
unknown-length H1 uploads use chunked transfer coding, while H2 and H3 omit the
field.

### Static trailers

Trailers are header fields sent after the body. `RequestBuilder::trailers`
adds an ordered static trailer block after the body completes successfully. It
works with exact H1, H2, and H3 requests and negotiated H1/H2 requests:

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

- Trailer order, duplicate interleaving, and sensitivity are preserved.
- H1 also preserves field-name spelling, uses chunked framing, and generates
  the `Trailer` declaration.
- H2 and H3 require lowercase field names. Negotiated requests must satisfy
  both H1 and H2 rules, so their trailer names must be lowercase too.
- Invalid or forbidden trailers fail before network I/O or body polling.
- A body error suppresses the trailer block.

### Trailers computed while streaming

For values computed while the body streams, use
`RequestBuilder::streaming_body_with_trailers` and declare the exact ordered
name plan with `RequestTrailerName`. The terminal `Frame::trailers` must match
that plan's normalized names and multiplicities. H1 writes the declared casing;
H2 and H3 require lowercase names. Static and body-produced trailers cannot be
combined, and the streaming body remains one-shot across redirects, retries,
and proxy-authentication replays.

### Trailers and redirects

Method-preserving redirects replay owned static trailers with the body. A
redirect that rewrites the request to GET clears both, and a cross-origin
redirect removes credential-bearing header and trailer fields before the next
attempt. See [Redirects](connections-and-state.md#redirects).

## Timeouts

Timeouts are disabled by default. `RequestTimeouts` can bound five phases:

| Phase | Builder method | Bounds |
| --- | --- | --- |
| Pool admission | `pool_admission` | Waiting for a connection slot |
| Connect | `connect` | Connection setup |
| Response head | `response_head` | Waiting for the status line and fields |
| Read idle | `read_idle` | Inactivity while reading the body |
| Total | `total` | The whole operation |

The total deadline spans redirects, retry delays, connection attempts, and
bounded replays. Phase limits restart for each attempt; the total deadline does
not. Errors identify the phase and selected protocol, and
`RequestError::timeout_phase` returns the matching `TimeoutPhase`.
`RequestBuilder::timeouts` replaces the client policy for one request.

An SSE event source applies these timeouts per attempt and stops the read-idle
and total timers once a stream is established (see [SSE](sse.md)). WebSocket
connects apply none of them (see [WebSocket](websocket.md#timeouts-and-retries)).

## Read the response

Every successful request returns `http::Response<ResponseBody>`. Its extensions
include `ResponseInfo` and `OrderedResponseHeaders`.

- `OrderedResponseHeaders` preserves duplicate interleaving on every protocol
  and original field-name spelling on H1.
- `ResponseInfo` reports the effective URI, the selected protocol,
  `redirects_followed`, and `decoded_content_codings`.
- `ResponseInfo::retries_performed` counts connection-setup retries: each time
  a failed setup was attempted again under `RetryPolicy::connection_failures`,
  summed across every redirect hop of the logical request. A retry is counted
  when it starts, whether or not that attempt succeeds. It excludes redirects,
  status retries, reused-connection and graceful-`GOAWAY` replays, proxy
  authentication replays, and `Critical-CH` retries.

The body is streaming and backpressured. Consume it to completion when you want
the connection to remain eligible for reuse.

`ResponseBody` implements `http_body::Body<Data = Bytes>`. Body errors use the
same `RequestError` type as request establishment. Dropping an incomplete H1
body may retire that connection; dropping an H2 or H3 body cancels its stream.

`ResponseBody::collect_with_limit` consumes the stream with an inclusive byte
cap. It returns `RequestErrorKind::ResponseBodyLimit` before retaining a chunk
that would exceed the cap. This convenience operation consumes and discards
trailers.

Response data is the encoded wire body by default. To decompress it, see
[Content decoding](content-decoding.md).

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

- Confirm the [distribution constraints](../getting-started.md#distribution-status)
  are acceptable.
- Select only profile components listed in [Coverage](../reference/coverage.md).
- Run inside Tokio with I/O and time enabled.
- Configure route, origin trust, and proxy trust explicitly.
- Choose redirect, connection-retry, and timeout policy; none is inferred from
  a browser name. A redirect policy makes `http://` requests fail, and
  WebSocket connects apply none of these policies (see
  [WebSocket](websocket.md#timeouts-and-retries)).
- Treat streaming request bodies as one-shot and consume response bodies when
  reuse matters.
- Handle non-exhaustive error categories and avoid logging sensitive inputs.
- Enable cookies, SSE, or WebSocket only when the matching Cargo feature and
  lifecycle are required.
