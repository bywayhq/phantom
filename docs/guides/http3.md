# HTTP/3 and Alt-Svc

Send requests over HTTP/3 (H3), which runs over QUIC on UDP, or upgrade to H3
when a server advertises it with [Alt-Svc](../reference/glossary.md#alt-svc).
An H3 connection has its own [fingerprint](../fingerprinting.md#http3), so
each task needs H3 settings on the profile.

> For builders who have read [Getting started](../getting-started.md).

## Send a request over HTTP/3

`Http3ClientSettings` holds the H3 TLS ClientHello, QUIC transport
parameters, HTTP/3 settings, and request settings. Add it to the profile and
ask for `HttpProtocol::Http3`:

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

- This is an [exact-protocol](../reference/glossary.md#exact-protocol)
  request; it moves to HTTP/2 only
  [if you opt in](#fall-back-to-http2-when-quic-fails).
- The TLS settings passed to `ClientProfile::new` apply only to TCP
  connections. H3 uses the TLS settings inside `Http3ClientSettings`.
- Exact H3 works over direct QUIC, SOCKS5 UDP ASSOCIATE (`socks5://` or
  `socks5h://`), and a CONNECT-UDP (MASQUE) proxy. HTTP forwarding and HTTP
  CONNECT proxies cannot carry QUIC, so Phantom rejects them before any origin
  I/O. See [SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md).
- With every built-in H3 recipe, each of which enables `session_tickets`,
  a later QUIC connection to the same origin over the same route resumes the
  TLS session with a ticket from an earlier one. Tickets are never shared
  between origins or routes; see
  [Session tickets](../internals/http3.md#session-tickets).

## Turn off early data on resumed connections

With every built-in H3 recipe, a resumed QUIC connection offers early
(0-RTT) data in its ClientHello, as those browsers do, and sends replay-safe
requests in 0-RTT packets, as Chrome and Edge send `GET`, `HEAD`, and
`OPTIONS`. Turn early data off on the builder:

```rust
use phantom::profile::ClientProfile;
use phantom::{BuildError, Client};

fn client_without_early_data(profile: ClientProfile) -> Result<Client, BuildError> {
    Client::builder(profile).http3_early_data(false).build()
}
```

- Early data is replayable: an attacker who records it can deliver it to the
  server again, and the server may process each copy. Turning it off changes
  the resumed ClientHello, which then lacks the `early_data` extension the
  captured browsers send.
- `http3_early_data(true)` turns early data on for a profile whose QUIC
  settings leave `early_data` unset. `build` then fails with
  `BuildErrorKind::InvalidPolicy` unless the H3 TLS settings enable
  `session_tickets`.
- A replay-safe request is sent as early data: `GET`, `HEAD`, `OPTIONS`, or
  `TRACE`, with no body and no trailers. Other requests wait for the
  handshake, even on a connection that offered early data; see
  [Session tickets](../internals/http3.md#session-tickets).
- The server must have issued a ticket that permits early data. If it
  rejects the early data, it processed none of it. Phantom sends the request
  again on the same connection once the handshake completes, as Chrome does.
  A handshake that fails after the connection sent early data fails the
  waiting requests, unless they [fall back](#fall-back-to-http2-when-quic-fails).

## Fall back to HTTP/2 when QUIC fails

Send an exact H3 request over the profile's HTTP/2 recipe when no QUIC
connection can be set up, as a browser uses TCP once QUIC fails.

```rust
use phantom::{Client, HttpProtocol, RetryPolicy};

async fn fetch(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let policy = RetryPolicy::none().with_http2_fallback(true);
    let request = client.get(HttpProtocol::Http3, "https://example.com/")?;
    drop(request.retry_policy(policy).send().await?);
    Ok(())
}
```

- It follows a refused, failed, or slow QUIC connection or handshake (past 4
  seconds or the connect timeout), after any setup retries. A failure after
  the request was sent, or a one-shot body, returns the H3 error.
- A replay-safe request on a resumed connection leaves as early data before
  the handshake completes, so it does not fall back; build the client with
  `http3_early_data(false)` for it to.
- The request goes once over TCP with the profile's TLS and HTTP/2 recipes,
  and `ResponseInfo::protocol` reports `Http2`; the next request tries QUIC
  again. Without an HTTP/2 profile or on a CONNECT-UDP route, it fails
  before any I/O.

## Upgrade to HTTP/3 when the server advertises it

Browsers discover H3 through Alt-Svc: an HTTP/1.1 or HTTP/2 response names an
H3 endpoint, and a later request to the same origin uses it. Enable the store
with `ClientBuilder::alt_svc`, which takes the maximum number of entries, and
send [negotiated](../reference/glossary.md#negotiated-protocol) requests:

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

- Only direct and SOCKS5 routes carry the upgrade: they give both a TLS
  stream for ALPN and a UDP path for QUIC. An HTTP proxy carries negotiated
  requests in a CONNECT tunnel, but the tunnel cannot carry QUIC, so Phantom
  learns no alternative there and those requests stay on HTTP/1.1 or HTTP/2.
  On a CONNECT-UDP route, a negotiated request fails with
  `RequestErrorKind::UnsupportedRoute` before any I/O. The store is keyed by
  origin and route, so an alternative learned over one route is used only
  over that route.
- By default a failed alternative returns a typed H3 error and is removed
  from the advertisement, so the next request uses the next alternative the
  field listed, if any; Phantom does not resend over HTTP/1.1 or HTTP/2. A `421`
  response also removes it. `Client::clear_alt_svc` clears the whole store.
- The alternative changes only where QUIC connects. The URI, authority, TLS
  identity, cookies, client hints, and timeouts stay those of the origin.

## Limits

- Without the fallback, an exact H3 request fails when UDP is blocked
  ([Troubleshooting](troubleshooting.md#an-http3-request-fails-where-a-browser-would-fall-back)).
- Only an authenticated, negotiated HTTP/1.1 or HTTP/2 response can advertise
  `h3`. Phantom subtracts the response's `Age` from `ma` (the advertised
  maximum age), replaces the origin's previous alternatives, and keeps up to
  eight fresh `h3` entries in field order, each expiring on its own `ma`. A
  request uses the first one that is not broken.
- A negotiated HTTP/2 response also learns from ALTSVC frames that arrived
  before its final headers: on stream 0 when the frame's origin matches the
  request's canonical origin exactly, and on the request's own stream. Other
  frames are ignored; the per-connection cap is in
  [Defaults and limits](../reference/limits.md#protocol-state).
- A request sent to an alternative carries one `Alt-Used` field, which
  Phantom manages; a caller-supplied `Alt-Used` field or trailer is rejected
  before network I/O. Phantom makes no browser claim about its position.
- One H3 connection per origin, route, and transport location, as browsers
  keep. `ClientBuilder::max_http3_connections_per_origin` allows more when
  the server's stream limit is the bottleneck; see
  [Tune throughput and latency](performance.md#open-more-than-one-connection-per-origin).
- [WebSocket over H3 to your own server](websocket-fields.md#open-a-websocket-over-http3-to-your-own-server).

## Next

- [HTTP/3 discovery](http3-discovery.md): race the alternative, find H3
  through DNS, and keep Alt-Svc state across restarts.
- [SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md): the proxy
  routes that carry H3.
- [HTTP/3 internals](../internals/http3.md): pooling and the QUIC stack.
