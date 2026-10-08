# HTTP/3 and Alt-Svc

Send requests over HTTP/3, or switch to HTTP/3 when a server says it
supports it. HTTP/3 runs over QUIC, a transport on UDP.

> Read [Getting started](../getting-started.md) first.

## Send a request over HTTP/3

An HTTP/3 connection looks different to a server than an HTTP/2 one
([HTTP/3 fingerprint](../fingerprinting.md#http3)), so the profile needs its
own HTTP/3 settings. A profile is the set of browser settings a client
sends. `Http3ClientSettings` holds the browser's QUIC handshake and HTTP/3
settings. Add it to the profile and ask for `HttpProtocol::Http3`:

```rust
use phantom::profile::{chromium, ClientProfile, Http3ClientSettings};
use phantom::{Client, HttpProtocol};

async fn run_h3() -> Result<(), Box<dyn std::error::Error>> {
    let http3 = Http3ClientSettings::new(
        chromium::v154_http3_tls(),
        chromium::v154_quic(),
        chromium::v154_http3(),
        chromium::v154_http3_request(),
    );
    let profile = ClientProfile::new(chromium::v154_tls()).with_http3(http3);

    let client = Client::builder(profile).build()?;
    let response = client
        .get(HttpProtocol::Http3, "https://example.com/")?
        .send()
        .await?;
    println!("{}", response.status());
    Ok(())
}
```

The request uses HTTP/3 and nothing else. It switches to HTTP/2 only
[if you turn that on](#fall-back-to-http2-when-quic-fails).

- The TLS settings passed to `ClientProfile::new` are for TCP connections.
  HTTP/3 uses the TLS settings inside `Http3ClientSettings`.
- HTTP/3 works directly, through a SOCKS5 proxy, or through a CONNECT-UDP
  proxy. An HTTP proxy can't carry it. See
  [SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md).
- Like a browser, Phantom resumes the TLS session on later HTTP/3
  connections to the same server.

## Turn off early data on resumed connections

A resumed connection sends `GET`, `HEAD` and `OPTIONS` requests before the
handshake finishes, as the browsers Phantom copies do. This is called early
data, or 0-RTT. To turn it off:

```rust
use phantom::profile::ClientProfile;
use phantom::{BuildError, Client};

fn client_without_early_data(profile: ClientProfile) -> Result<Client, BuildError> {
    Client::builder(profile).http3_early_data(false).build()
}
```

Early data can be replayed: someone who records it can send it to the
server again. Turning it off makes resumed connections differ from the
browser's.

## Fall back to HTTP/2 when QUIC fails

Send an HTTP/3 request over HTTP/2 when no QUIC connection can be set up,
the way a browser falls back to TCP.

```rust
use phantom::{Client, HttpProtocol, RetryPolicy};

async fn fetch(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let policy = RetryPolicy::none().with_http2_fallback(true);
    let request = client.get(HttpProtocol::Http3, "https://example.com/")?;
    drop(request.retry_policy(policy).send().await?);
    Ok(())
}
```

Phantom falls back when the QUIC connection is refused, fails, or takes
more than 4 seconds. That one request goes over HTTP/2 with the profile's
HTTP/2 settings, so the profile needs them. The next request tries QUIC
again.

A request that fails after it was sent doesn't fall back. Neither does a
request sent as early data, so build the client with
`http3_early_data(false)` if those requests need the fallback.

## Upgrade to HTTP/3 when the server advertises it

Servers announce HTTP/3 in an `Alt-Svc` response header. Browsers remember
it and use HTTP/3 for later requests to that server. Turn this on with
`ClientBuilder::alt_svc`, which takes how many servers to remember. Then
send negotiated requests, which let Phantom pick the protocol:

```rust
use std::num::NonZeroUsize;

use phantom::profile::{chromium, ClientProfile, Http3ClientSettings};
use phantom::{Client, ResponseInfo};

async fn upgrade() -> Result<(), Box<dyn std::error::Error>> {
    let http3 = Http3ClientSettings::new(
        chromium::v154_http3_tls(),
        chromium::v154_quic(),
        chromium::v154_http3(),
        chromium::v154_http3_request(),
    );
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_http3(http3);
    let client = Client::builder(profile)
        .alt_svc(NonZeroUsize::new(64).expect("64 is nonzero"))
        .build()?;

    // The first negotiated request uses H1 or H2 and may learn an `h3` alternative.
    let first = client.get_negotiated("https://example.com/")?.send().await?;
    first.into_body().collect_with_limit(1 << 20).await?;

    // A later negotiated request may use the learned alternative;
    // `ResponseInfo::protocol` reports which protocol carried it.
    let second = client.get_negotiated("https://example.com/")?.send().await?;
    if let Some(info) = second.extensions().get::<ResponseInfo>() {
        println!("{:?}", info.protocol());
    }
    Ok(())
}
```

If the HTTP/3 server fails, you get the error and Phantom stops using that
server for a while. It doesn't resend the request over HTTP/2. To try both
at once, [race them](http3-discovery.md#race-the-alternative-against-the-origin).
`Client::clear_alt_svc` forgets every server Phantom has learned.

## Limits

- Without the fallback, an HTTP/3 request fails when UDP is blocked
  ([Troubleshooting](troubleshooting.md#an-http3-request-fails-where-a-browser-would-fall-back)).
- The upgrade works on direct and SOCKS5 connections. Through an HTTP
  proxy, negotiated requests stay on HTTP/1.1 or HTTP/2.
- Phantom keeps one HTTP/3 connection per server, as browsers do.
  [Open more than one](performance.md#open-more-than-one-connection-per-origin)
  when the server's stream limit slows you down.

## Next

- [HTTP/3 discovery](http3-discovery.md): race HTTP/3 against HTTP/2, find
  HTTP/3 through DNS, and save what Phantom learned.
- [SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md): proxies that
  carry HTTP/3.
- [Defaults and limits](../reference/limits.md): every timer and cap.
