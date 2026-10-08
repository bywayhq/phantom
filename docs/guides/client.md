# Using the client

Set up a `Client` once, then send requests on the protocol you choose, with
your own headers, a body and trailers. You can also give the client a
certificate for servers that ask for one.

> Read [Getting started](../getting-started.md) first.

## Configure the client

Build a client from a profile, plus the redirect, retry and timeout
settings every request will use. A [profile](../reference/glossary.md#profile)
is the browser the client copies on the wire: its handshake, its HTTP/2
settings and so on.

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

Timeouts, redirects and most retries are off by default.
[Retries and replays](retries.md) lists the few repeats that are on.

Each timeout restarts on a redirect or retry. `total` covers the whole
request, body included. [Defaults and limits](../reference/limits.md#timeouts)
describes each timeout.

The client's settings are fixed once `build` returns. A single request can
still change its route, timeouts, retry policy and content decoding.

## Choose a protocol for a request

Pick HTTP/1.1, HTTP/2 or HTTP/3 for each request, or let the server choose
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

`get` and `request` use the protocol you pass. If the server or proxy can't
carry it, the request fails. `get_negotiated` and `request_negotiated` let
the server pick HTTP/1.1 or HTTP/2 during the handshake. Direct `http://`
requests use HTTP/1.1. An [HTTP/2 proxy](routes-and-proxies.md#speak-http2-to-the-proxy)
can forward them over HTTP/2.

Not every protocol works through every proxy. The
[route matrix](../reference/route-matrix.md) lists the combinations.

## Send headers, a body, and trailers

Send headers exactly as you write them, a body, and trailers after the
body.

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

Headers go out in the order you add them, with your spelling and any
duplicates. Phantom adds no `User-Agent` or other browser headers itself.
To send a browser's headers in its order,
[apply a request template](request-templates.md#apply-a-captured-request-template).

A body passed to `body` can be sent again for a redirect or retry. A
streaming body from `streaming_body` is sent once, unless you
[buffer it](redirects.md#send-a-streaming-body-again).

Trailers keep their order on every protocol. HTTP/2 and HTTP/3 need
lowercase trailer names.

## Present a client certificate

Give the client a certificate and its private key for servers that ask for
one. You can set one for every server and another for a single host and
port.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, ClientCertificate};

fn client_with_certificates(
    default: ClientCertificate,
    api: ClientCertificate,
) -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    Ok(Client::builder(profile)
        .client_certificate(default)
        .client_certificate_for("https://api.example:8443", api)
        .build()?)
}
```

Load a certificate with `ClientCertificate::from_pem` or `from_der`. Pass
the certificate first, then any intermediates, then the key.

Adding a certificate doesn't change the handshake. Phantom sends it only
when the server asks for one.

The profile must be able to sign with your key. The built-in recipes sign
with RSA, P-256 and P-384 keys, and Firefox's also with P-521. Another key
type makes `build` fail. The
`ClientCertificate` rustdoc covers the other key formats.

## Limits

- Phantom needs a Tokio runtime with I/O and time enabled. A connection
  stays on the runtime that opened it.
- A WebSocket connect doesn't use the client's timeouts, retries or
  redirects. It has its own
  ([WebSocket](websocket.md#bound-a-connect-with-a-timeout)).
- The cookie, SSE and WebSocket APIs need their
  [Cargo features](../getting-started.md#optional-features).

## Next

- [Responses and errors](responses.md): read what comes back.
- [Browser profiles](profiles.md): pick the browser to copy.
- [Connections and client state](connections-and-state.md): state that
  outlives one request.
