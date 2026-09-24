# Using the client

Build a `Client`, send requests on the protocol you choose, and read what
comes back.

> For builders who have read [Getting started](../getting-started.md).

A [profile](../reference/glossary.md#profile) fixes what the client puts on
the wire. The `Client` holds that profile with your policies, connections,
and state. Each request adds its method, URL, ordered fields, body, and
protocol. Topics with their own guides: [browser profiles](profiles.md),
[routes and proxies](routes-and-proxies.md), [retries](retries.md),
[connections, redirects, and cookies](connections-and-state.md),
[HTTP/3 and Alt-Svc](http3.md), and [content decoding](content-decoding.md).

## Configure the client

Build a client with the profile, redirect, retry, and timeout policies it
will use for every request.

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

- Client settings are fixed once `build` returns. A request can override only
  the route, timeouts, and retry policy, and can opt into content decoding.
- Timeouts, redirects, and connection retries are off until you set them.
  Pool and client-hint bounds start at the finite defaults in
  [Defaults and limits](../reference/limits.md); `ClientBuilder` accepts any
  nonzero replacement.
- `Client::retry_policy` and `Client::request_timeouts` return the client's
  configured defaults.

## Choose a protocol for a request

Send a request on exactly one protocol, or let the TLS handshake choose
between HTTP/1.1 and HTTP/2.

```rust
use phantom::{Client, HttpProtocol, ResponseInfo};

async fn fetch(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    // Exactly HTTP/2, or an error.
    let exact = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .send()
        .await?;
    drop(exact);

    // One TLS handshake; the server's ALPN choice decides H1 or H2.
    let negotiated = client.get_negotiated("https://example.com/")?.send().await?;
    if let Some(info) = negotiated.extensions().get::<ResponseInfo>() {
        println!("negotiated {:?}", info.protocol());
    }
    Ok(())
}
```

- `get` and `request` use the [exact protocol](../reference/glossary.md#exact-protocol)
  you pass: H1, H2, or H3 (HTTP/1.1, HTTP/2, HTTP/3).
- `get_negotiated` and `request_negotiated` are
  [negotiated](../reference/glossary.md#negotiated-protocol): one TLS
  handshake, direct or through a SOCKS5 tunnel. The request uses H2 if the
  server selects `h2`, and H1 if it selects `http/1.1` or sends no ALPN. With
  [Alt-Svc](../reference/glossary.md#alt-svc) enabled, a later negotiated
  request on the same route can move to a learned H3 endpoint (see
  [HTTP/3 and Alt-Svc](http3.md)).
- H3 runs over QUIC: directly, through SOCKS5 with local or remote DNS
  (RFC 1928 UDP ASSOCIATE), or through an RFC 9298 CONNECT-UDP proxy.
- A combination Phantom does not support fails with an error before any other
  protocol or [route](../reference/glossary.md#route) is tried. The
  [route matrix](../reference/route-matrix.md) lists every combination.

## Send fields and a body

Send request fields exactly as written, in your order, with an owned or
streaming body.

```rust
use phantom::{Client, HttpProtocol, Method, RequestHeader};

async fn post(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .request(HttpProtocol::Http1, Method::POST, "https://example.com/items")?
        .header(RequestHeader::new("Content-Type", "application/json"))
        .header(RequestHeader::new("X-Request-Id", "42"))
        .body(r#"{"name":"widget"}"#)
        .send()
        .await?;
    println!("{}", response.status());
    Ok(())
}
```

- `RequestHeader` keeps the name spelling, value bytes, duplicates, and
  position of each field. Phantom adds no browser fields such as
  `User-Agent`, `Accept`, or `Sec-Fetch-*`; to send them in a browser's order,
  [apply a captured request template](profiles.md#apply-a-captured-request-template).
- An owned body can be sent again when a redirect or replay requires it. A
  streaming body (`RequestBuilder::streaming_body`, any
  `http_body::Body<Data = Bytes>`) is sent at most once.
- Phantom checks any `Content-Length` you supply against the body. A
  streaming body of unknown length uses chunked transfer coding on H1; H2 and
  H3 omit `Content-Length` for it.

## Send trailers after the body

Send an ordered list of header fields once the body completes.

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

- Trailers work on exact H1, H2, and H3 and on negotiated requests. Order,
  interleaved duplicates, and sensitivity are kept on every protocol. H1 also
  keeps name spelling, uses chunked framing, and writes the `Trailer` field.
- H2 and H3 require lowercase names, and so does a negotiated request, which
  can end up on either H1 or H2.
- When trailer values depend on the streamed body, use
  `RequestBuilder::streaming_body_with_trailers` and declare the names in order
  with `RequestTrailerName`. The body's final `Frame::trailers` must contain
  exactly those names, with the same count of each. It cannot be combined
  with static trailers.
- A redirect that keeps the method sends the owned body and static trailers
  again; one that changes the request to GET drops both (see
  [Follow redirects](connections-and-state.md#follow-redirects)).

## Set timeouts

Limit how long each phase of a request may take, for the client or for one
request.

```rust
use std::time::Duration;

use phantom::{Client, HttpProtocol, RequestTimeouts};

async fn fetch_with_deadline(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let timeouts = RequestTimeouts::new()
        .pool_admission(Duration::from_secs(2))
        .total(Duration::from_secs(5));
    let response = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .timeouts(timeouts)
        .send()
        .await?;
    drop(response);
    Ok(())
}
```

| Phase | Method | Limits |
| --- | --- | --- |
| Pool admission | `pool_admission` | Waiting for a free connection slot |
| Connect | `connect` | DNS, proxy, transport, TLS, and protocol setup |
| Response head | `response_head` | Sending the request and body, then waiting for the status and fields |
| Read idle | `read_idle` | Time without data while reading the response body |
| Total | `total` | The whole operation |

Each phase limit restarts for every redirect, retry, and internal replay. The
total limit is one deadline over all attempts, retry delays, and the final
response body. `RequestBuilder::timeouts` replaces the client's timeouts for
that request.

## Read the response

Read the status, the fields in wire order, what happened on the wire, and a
bounded body.

```rust
use phantom::{Client, HttpProtocol, OrderedResponseHeaders, ResponseInfo};

async fn read(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.get(HttpProtocol::Http2, "https://example.com/")?.send().await?;

    if let Some(fields) = response.extensions().get::<OrderedResponseHeaders>() {
        for field in fields.iter() {
            println!("{}: {:?}", field.name(), field.value());
        }
    }
    if let Some(info) = response.extensions().get::<ResponseInfo>() {
        println!("{} after {} redirects", info.effective_uri(), info.redirects_followed());
    }

    let body = response.into_body().collect_with_limit(1 << 20).await?;
    println!("{} bytes", body.len());
    Ok(())
}
```

- `OrderedResponseHeaders` keeps the fields in wire order with duplicates
  interleaved, on every protocol; on H1 it also keeps name spelling.
- `ResponseInfo` reports the effective URL, protocol, `redirects_followed`,
  `retries_performed`, and `decoded_content_codings`.
  `retries_performed` counts only connection-setup retries (see
  [Retry when a connection fails to open](retries.md#retry-when-a-connection-fails-to-open)).
- `ResponseBody` implements `http_body::Body<Data = Bytes>` and streams with
  backpressure. `collect_with_limit` fails with
  `RequestErrorKind::ResponseBodyLimit` before keeping a chunk that would pass
  the inclusive limit, and discards trailers.
- Read the body to the end if you want the connection reused. Dropping an
  unfinished H1 body can close its connection; dropping an H2 or H3 body
  cancels its stream.
- The body is returned as the server sent it, compressed or not; see
  [Content decoding](content-decoding.md).

## Handle errors

Sort failures into stable categories.

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

- `BuildError::kind` and `RequestError::kind` return non-exhaustive enums, so
  keep a fallback arm.
- `RequestError::protocol` and `RequestError::timeout_phase` report the
  protocol and the `TimeoutPhase` when known. A timeout error names both.
- Body errors use the same `RequestError` type as the request.
- Error messages and debug output leave out credentials, cookies, payloads,
  and endpoint details. Do not log sensitive inputs yourself; for deeper
  investigation, use bounded tracing or protocol diagnostics.

## Limits

- Accept the [pre-1.0 distribution terms](../getting-started.md#distribution-status)
  and use only profile components listed in
  [Coverage](../reference/coverage.md).
- Phantom runs inside a Tokio runtime with I/O and time enabled.
- No route, trust, redirect, retry, or timeout policy is implied by a browser
  name; set each one. A client with a redirect policy rejects `http://`
  requests.
- WebSocket connects apply none of the client's timeouts, retries, or
  redirects (see [WebSocket](websocket.md#timeouts-and-retries)). An SSE event
  source applies timeouts to each attempt and stops the read-idle and total
  timers once the stream is open (see [SSE](sse.md)).
- HTTP proxy and CONNECT-UDP routes reject negotiated requests before any
  I/O.
- A streaming request body is single-use: a redirect, retry, or replay that
  needs it again fails with `RequestErrorKind::RequestBody`.
- An invalid or forbidden trailer fails before any network I/O and before
  the body is read. If the body fails, no trailers are sent.
- The cookie, SSE, and WebSocket APIs need their Cargo features
  ([Optional features](../getting-started.md#optional-features)).

## Next

- [Browser profiles](profiles.md): choose what the client sends on the wire.
- [Routes and proxies](routes-and-proxies.md): send requests through a proxy.
- [Defaults and limits](../reference/limits.md): every default and bound.
