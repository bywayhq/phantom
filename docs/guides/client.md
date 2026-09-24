# Using the client

Build a `Client` from a [profile](../reference/glossary.md#profile) and your
policies, send requests on the protocol you choose, and read what comes back.

> For builders who have read [Getting started](../getting-started.md).

## Configure the client

Build a client with the profile and the redirect, retry, and timeout policies
every request will use.

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

- `RequestTimeouts` limits five phases: pool admission, connect, response
  head, read idle, and total ([timeout phases](../reference/limits.md#timeouts)).
- Client settings are fixed once `build` returns. A request can override only
  the route, timeouts (`RequestBuilder::timeouts`), and retry policy, and can
  opt into content decoding.
- Timeouts, redirects, and retries are off until you set them. Each phase
  limit restarts for every redirect, retry, and replay; the total limit is one
  deadline over all attempts, delays, and the final response body.
- `Client::retry_policy` and `Client::request_timeouts` return the defaults.
  Pool bounds are in [Defaults and limits](../reference/limits.md).

## Choose a protocol for a request

Send a request on exactly one protocol, or let the TLS handshake choose
between HTTP/1.1 and HTTP/2.

```rust
use phantom::{Client, HttpProtocol, ResponseInfo};

async fn fetch(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    // Exactly HTTP/2, or an error.
    let exact = client.get(HttpProtocol::Http2, "https://example.com/")?.send().await?;
    drop(exact);

    // One TLS handshake; the server's ALPN choice decides H1 or H2.
    let negotiated = client.get_negotiated("https://example.com/")?.send().await?;
    if let Some(info) = negotiated.extensions().get::<ResponseInfo>() {
        println!("negotiated {:?}", info.protocol());
    }
    Ok(())
}
```

- `get` and `request` use the
  [exact protocol](../reference/glossary.md#exact-protocol) you pass: H1, H2,
  or H3 (HTTP/1.1, HTTP/2, HTTP/3).
- `get_negotiated` and `request_negotiated` are
  [negotiated](../reference/glossary.md#negotiated-protocol): one TLS
  handshake, direct or through a SOCKS5 tunnel. The server's `h2` selects H2;
  `http/1.1` or no ALPN selects H1. With
  [Alt-Svc](../reference/glossary.md#alt-svc) enabled, a later negotiated
  request on the same route can move to a learned H3 endpoint
  ([HTTP/3 and Alt-Svc](http3.md)).
- An unsupported combination fails before any other protocol or
  [route](../reference/glossary.md#route) is tried. The
  [route matrix](../reference/route-matrix.md) lists every combination.

## Send fields, a body, and trailers

Send request fields exactly as written, a body, and ordered trailers after
the body.

```rust
use phantom::{Client, HttpProtocol, Method, RequestHeader};

async fn upload(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .request(HttpProtocol::Http2, Method::POST, "https://example.com/upload")?
        .header(RequestHeader::new("content-type", "text/plain"))
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

- `RequestHeader` keeps name spelling, value bytes, duplicates, and position.
  Phantom adds no browser fields such as `User-Agent` or `Sec-Fetch-*`; to
  send them in a browser's order,
  [apply a captured request template](profiles.md#apply-a-captured-request-template).
- An owned body can be sent again for a redirect or replay. A streaming body
  (`streaming_body`, any `http_body::Body<Data = Bytes>`) is sent at most
  once. Phantom checks a `Content-Length` you supply against the body; an
  unknown-length streaming body is chunked on H1 and has no `Content-Length`
  on H2 and H3.
- Trailers keep order, interleaved duplicates, and sensitivity on every
  protocol; H1 also keeps name spelling and writes the `Trailer` field. H2,
  H3, and negotiated requests require lowercase trailer names.
- For trailers computed from the body, `streaming_body_with_trailers` takes
  the names in order as `RequestTrailerName`s; the final `Frame::trailers`
  must hold exactly those names, and static trailers cannot be added.

## Read the response

Read the fields in wire order, what happened on the wire, and a bounded body.

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

- `OrderedResponseHeaders` keeps wire order and interleaved duplicates on
  every protocol, and name spelling on H1.
- `ResponseInfo` also reports `protocol`, `decoded_content_codings`, and
  `retries_performed`, which counts connection-setup retries only
  ([Retry when a connection fails to open](retries.md#retry-when-a-connection-fails-to-open)).
- `ResponseBody` is an `http_body::Body<Data = Bytes>` with backpressure,
  undecoded unless you opt in ([Content decoding](content-decoding.md)).
  `collect_with_limit` fails with `RequestErrorKind::ResponseBodyLimit` before
  keeping a chunk past the inclusive limit, and discards trailers.

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

- `BuildError::kind` and `RequestError::kind` return non-exhaustive enums;
  keep a fallback arm. Body errors use `RequestError` too, and
  `RequestError::protocol` and `timeout_phase` report what is known.
- Messages and debug output leave out credentials, cookies, payloads, and
  endpoints. To investigate further, use bounded tracing or diagnostics.

## Limits

- Accept the [pre-1.0 terms](../getting-started.md#distribution-status), use
  only components listed in [Coverage](../reference/coverage.md), and run
  inside a Tokio runtime with I/O and time enabled.
- A browser name implies no route, trust, redirect, retry, or timeout policy.
  A client with a redirect policy rejects `http://` requests.
- WebSocket connects apply none of the client's timeouts, retries, or
  redirects ([WebSocket](websocket.md#bound-a-connect-with-a-timeout)).
- An SSE event source applies timeouts per attempt and stops the read-idle
  and total timers once the stream is open ([SSE](sse.md)).
- A CONNECT-UDP route rejects negotiated requests before I/O. An HTTP proxy
  route carries them but never upgrades them to H3 through Alt-Svc.
- A redirect that keeps the method resends the owned body and static
  trailers; one that changes to GET drops both. A streaming body that must be
  sent again fails with `RequestErrorKind::RequestBody`.
- An invalid or forbidden trailer fails before I/O and before the body is
  read. If the body fails, no trailers are sent.
- Dropping an unfinished H1 body can close its connection; dropping an H2 or
  H3 body cancels its stream.
- The cookie, SSE, and WebSocket APIs need their
  [Cargo features](../getting-started.md#optional-features).

## Next

- [Browser profiles](profiles.md): choose what the client sends on the wire.
- [Connections, redirects, and cookies](connections-and-state.md): state
  that outlives one request.
- [Routes and proxies](routes-and-proxies.md): send requests through a proxy.
