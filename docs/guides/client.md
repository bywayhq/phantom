# Using the client

A `Client` holds your configuration and connections; each request you build
from it picks a protocol and adds its own fields and body. Read
[Getting started](../getting-started.md) first. Topics with their own guides:
[routes and proxies](routes-and-proxies.md), [retries](retries.md),
[connections, redirects, and cookies](connections-and-state.md),
[HTTP/3 and Alt-Svc](http3.md), [content decoding](content-decoding.md), and
[browser profiles](profiles.md).

## Key terms

- **H1, H2, H3**: HTTP/1.1, HTTP/2, and HTTP/3.
- **Profile**: the fixed description of what the client puts on the wire, such
  as the TLS ClientHello, HTTP/2 and HTTP/3 settings, QUIC transport
  parameters, and client hints. See [Browser profiles](profiles.md).
- **Recipe**: a built-in profile component, such as `chromium::v154_tls()`.
  Most come from browser captures; TCP recipes come from browser source.
- **Exact protocol**: the request uses the protocol you chose or fails. It
  never falls back to another one.
- **Negotiated**: one TLS handshake in which the server picks H1 or H2 through
  ALPN, the TLS extension that selects an application protocol.
- **Route**: how the client reaches the server: directly, or through an HTTP,
  SOCKS5, or CONNECT-UDP proxy.
- **Origin**: the scheme, host, and port of a URL.

## What each layer controls

| Layer | Controls |
| --- | --- |
| Profile | TLS, HTTP/2, HTTP/3, QUIC, and client-hint wire settings. Immutable. |
| Client | Pools, route defaults, trust, limits, redirects, connection retries, cookies, learned hints and alternatives, and TLS sessions |
| Request | Method, URL, ordered fields and trailers, body, protocol, and per-request overrides |

Built-in and custom profiles use the same types. A recipe's name records which
browser it was captured from. The runtime never branches on that name or on
the host operating system.

## Configure the client

Client settings are fixed once `build` returns. A request can override the
route, timeouts, and retry policy, and can opt into content decoding. Nothing
else changes per request.

```rust
use std::{num::NonZeroUsize, time::Duration};

use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, RedirectPolicy, RequestTimeouts, RetryPolicy};

fn build() -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2());
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

Timeouts, redirects, and connection retries are off until you configure them.
Pool and client-hint limits start at the finite defaults listed in
[Defaults and limits](../reference/limits.md); `ClientBuilder` accepts any
nonzero replacement. `Client::retry_policy` and `Client::request_timeouts`
return the client's configured defaults.

## Choose a protocol

- `get` and `request` use exactly H1, H2, or H3.
- `get_negotiated` and `request_negotiated` make one TLS handshake, direct or
  through a SOCKS5 tunnel. The request uses H2 if the server selects `h2`, and
  H1 if it selects `http/1.1` or sends no ALPN. With Alt-Svc enabled, a later
  negotiated request on the same route can move to a learned H3 endpoint; see
  [HTTP/3 and Alt-Svc](http3.md). HTTP proxy and CONNECT-UDP routes reject
  negotiated requests before any I/O.
- H3 runs over QUIC on a separate path. It works directly, through SOCKS5 with
  local or remote DNS (RFC 1928 UDP ASSOCIATE), or through an RFC 9298
  CONNECT-UDP proxy.

A combination Phantom does not support fails with an error before any other
protocol or route is tried. The [route matrix](../reference/route-matrix.md)
lists every combination of scheme, protocol, and route.

## Send fields, bodies, and trailers

`RequestHeader` keeps each field exactly as you wrote it: name spelling, value
bytes, duplicates, and position in the overall order. A body can be owned
bytes or a pull-driven `http_body::Body<Data = Bytes>`.

Phantom adds no browser fields such as `User-Agent`, `Accept`, or
`Sec-Fetch-*` by itself. To send them in the order a browser does, apply a
captured [request template](profiles.md#request-templates) with
`RequestBuilder::template`. A template also rejects a `User-Agent` or
`sec-ch-ua` that names a different browser or version.

- An owned body can be sent again when a redirect requires it. A streaming body
  is sent at most once.
- Phantom checks any `Content-Length` you supply against the body.
- A streaming body of unknown length uses chunked transfer coding on H1. H2 and
  H3 omit `Content-Length` for it.

### Static trailers

Trailers are header fields sent after the body. `RequestBuilder::trailers`
sends an ordered list of them once the body completes successfully. They work
on exact H1, H2, and H3 requests and on negotiated requests.

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

- Order, interleaved duplicates, and sensitivity are kept on every protocol.
- H1 also keeps field-name spelling, uses chunked framing, and writes the
  `Trailer` field that declares the names.
- H2 and H3 require lowercase names. A negotiated request can end up on
  either H1 or H2, so its trailer names must be lowercase too.
- An invalid or forbidden trailer fails before any network I/O and before the
  body is read.
- If the body fails, no trailers are sent.

### Trailers computed while streaming

When trailer values depend on the streamed body, use
`RequestBuilder::streaming_body_with_trailers` and declare the trailer names in
order with `RequestTrailerName`. The body's final `Frame::trailers` must
contain exactly those names, with the same number of each, compared after
normalization. H1 writes the names with the declared casing; H2 and H3 require
lowercase. You cannot combine these with static trailers. The body is still
sent at most once, including across redirects, retries, and proxy
authentication.

### Trailers and redirects

A redirect that keeps the method sends the owned body and static trailers
again. A redirect that changes the request to GET drops both. A cross-origin
redirect removes header and trailer fields that carry credentials before the
next request. See [Redirects](connections-and-state.md#redirects).

## Set timeouts

Timeouts are off by default. `RequestTimeouts` can limit five phases:

| Phase | Builder method | Limits |
| --- | --- | --- |
| Pool admission | `pool_admission` | Waiting for a free connection slot |
| Connect | `connect` | Connection setup: DNS, proxy, transport, TLS, and protocol setup |
| Response head | `response_head` | Sending the request, including its body, and waiting for the status line and fields |
| Read idle | `read_idle` | Time without data while reading the response body |
| Total | `total` | The whole operation |

Each phase limit restarts for every redirect, retry, and internal replay. The
total limit is one deadline shared by all attempts, retry delays, and the
final response body. A timeout error names the phase and the protocol, and
`RequestError::timeout_phase` returns the `TimeoutPhase`.
`RequestBuilder::timeouts` replaces the client's timeouts for one request.

An SSE event source applies these timeouts to each attempt and stops the
read-idle and total timers once the stream is open (see [SSE](sse.md)).
WebSocket connects apply none of them (see
[WebSocket](websocket.md#timeouts-and-retries)).

## Read the response

A successful request returns `http::Response<ResponseBody>`. Two values in its
extensions describe what happened on the wire:

- `OrderedResponseHeaders` keeps the response fields in wire order, with
  duplicates interleaved as received, on every protocol. On H1 it also keeps
  the original name spelling.
- `ResponseInfo` reports the effective URL, the protocol used,
  `redirects_followed`, `retries_performed`, and `decoded_content_codings`.

`ResponseInfo::retries_performed` counts connection-setup retries made under
`RetryPolicy::connection_failures`, summed over every redirect hop. Each retry
counts when it starts, whether or not it succeeds. The count excludes
redirects, status retries, replays after a reused connection closed or a
graceful `GOAWAY`, proxy-authentication replays, and `Critical-CH` retries.

The body streams with backpressure: data arrives only as fast as you read it.
`ResponseBody` implements `http_body::Body<Data = Bytes>`, and body errors use
the same `RequestError` type as the request.

- Read the body to the end if you want the connection reused. Dropping an
  unfinished H1 body can close that connection; dropping an H2 or H3 body
  cancels its stream.
- `ResponseBody::collect_with_limit` reads the whole body up to an inclusive
  byte limit. It fails with `RequestErrorKind::ResponseBodyLimit` before
  keeping a chunk that would go over the limit. It discards trailers.

The body is returned as sent by the server, compressed or not. To decompress
it, see [Content decoding](content-decoding.md).

## Handle errors

`BuildError::kind` and `RequestError::kind` return stable categories. The
enums are non-exhaustive, so always include a fallback arm. Request errors also
report the protocol and timeout phase when known.

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

Error messages and debug output leave out credentials, cookies, payloads, and
endpoint details. For deeper investigation, use bounded tracing or protocol
diagnostics.

## Before you ship

- Accept the [pre-1.0 distribution terms](../getting-started.md#distribution-status).
- Use only profile components listed in [Coverage](../reference/coverage.md).
- Run inside a Tokio runtime with I/O and time enabled.
- Set the route, origin trust, and proxy trust explicitly.
- Choose redirect, connection-retry, and timeout policies. None is implied by
  a browser name. A client with a redirect policy rejects `http://` requests,
  and WebSocket connects ignore all three (see
  [WebSocket](websocket.md#timeouts-and-retries)).
- Treat streaming request bodies as single-use, and read response bodies to
  the end when connection reuse matters.
- Handle non-exhaustive error categories, and do not log sensitive inputs.
- Enable the cookie, SSE, or WebSocket Cargo features only when you need them.
