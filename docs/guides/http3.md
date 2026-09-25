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
  request: it never falls back to HTTP/1.1 or HTTP/2.
- The TLS settings passed to `ClientProfile::new` apply only to TCP
  connections. H3 uses the TLS settings inside `Http3ClientSettings`.
- Exact H3 works over direct QUIC, SOCKS5 UDP ASSOCIATE (`socks5://` or
  `socks5h://`), and a CONNECT-UDP (MASQUE) proxy. HTTP forwarding and HTTP
  CONNECT proxies cannot carry QUIC, so Phantom rejects them before any origin
  I/O. See [SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md).
- With the Chrome 154 and Edge 153 recipes, which enable `session_tickets`,
  a later QUIC connection to the same origin over the same route resumes the
  TLS session with a ticket from an earlier one. Tickets are never shared
  between origins or routes; see
  [Session tickets](../internals/http3.md#session-tickets).

## Turn off early data on resumed connections

With the Chrome 154 and Edge 153 recipes, a resumed QUIC connection offers
early (0-RTT) data in its ClientHello, as those browsers do, and sends
replay-safe requests in 0-RTT packets, as the browsers send `GET`, `HEAD`,
and `OPTIONS`. Turn early data off on the builder:

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
  handshake, even on a connection that offered early data. Under the
  recipes' dynamic QPACK policy, early requests are encoded with the server
  SETTINGS remembered with the ticket; see
  [Remembered SETTINGS](../internals/http3.md#remembered-settings).
  [QUIC session resumption](../explanation/validation.md#quic-session-resumption)
  gives the Chromium source for this rule.
- Concurrent requests to a resumed origin share one connection while its
  early data is unanswered.
- The server must have issued a ticket that permits early data. If it
  rejects the early data, it processed none of it. Phantom sends the request
  again on the same connection once the handshake completes, as Chrome does.
  A handshake that fails after the connection sent early data fails the
  waiting requests; it is not retried.

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
- By default a failed alternative returns a typed H3 error and evicts the
  advertisement; Phantom does not resend over HTTP/1.1 or HTTP/2. A `421`
  response also evicts it. `Client::clear_alt_svc` clears the whole store.
- The alternative changes only where QUIC connects. The URI, authority, TLS
  identity, cookies, client hints, and timeouts stay those of the origin.

## Limits

- An exact H3 request never falls back to HTTP/1.1 or HTTP/2. When UDP is
  blocked it fails, usually with `RequestErrorKind::Connect` or `Http3`
  ([Troubleshooting](troubleshooting.md#an-http3-request-fails-where-a-browser-would-fall-back)).
- Only an authenticated, negotiated HTTP/1.1 or HTTP/2 response can advertise
  `h3`. Phantom subtracts the response's `Age` from `ma` (the advertised
  maximum age), replaces the origin's previous alternatives, and uses the
  first fresh canonical `h3` entry.
- A negotiated HTTP/2 response also learns from ALTSVC frames that arrived
  before its final headers: on stream 0 when the frame's origin matches the
  request's canonical origin exactly, and on the request's own stream. Other
  frames are ignored; the per-connection cap is in
  [Defaults and limits](../reference/limits.md#protocol-state).
- A request sent to an alternative carries one `Alt-Used` field, which
  Phantom manages; a caller-supplied `Alt-Used` field or trailer is rejected
  before network I/O. Phantom makes no browser claim about its position.
- Not implemented: WebSocket over H3, more than one H3 connection per origin
  and route, and early data on an Alt-Svc racing attempt.

## Next

- [HTTP/3 discovery](http3-discovery.md): race the alternative, find H3
  through DNS, and keep Alt-Svc state across restarts.
- [SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md): the proxy
  routes that carry H3.
- [HTTP/3 internals](../internals/http3.md): pooling and the QUIC stack.
