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
  I/O. See [Routes and proxies](routes-and-proxies.md).
- With the Chrome 154 and Edge 153 recipes, which enable `session_tickets`,
  a later QUIC connection to the same origin over the same route resumes the
  TLS session with a ticket from an earlier one. Tickets are never shared
  between origins or routes; see
  [Session tickets](../internals/http3.md#session-tickets).

## Send a request as early data on a resumed connection

A resumed QUIC connection can carry its first request as early (0-RTT) data,
before the handshake completes. Enable it on the builder:

```rust
use phantom::profile::ClientProfile;
use phantom::{BuildError, Client};

fn early_data_client(profile: ClientProfile) -> Result<Client, BuildError> {
    Client::builder(profile).http3_early_data().build()
}
```

- Early data is replayable: an attacker who records it can deliver it to the
  server again, and the server may process each copy. The option is off by
  default, and no named recipe enables it.
- Only a replay-safe request opens a connection with early data: `GET`,
  `HEAD`, `OPTIONS`, or `TRACE`, with no body and no trailers. This is the
  rule Chromium 154 applies to a request of default idempotency. Other
  requests wait for the handshake.
- The server must have issued a ticket that permits early data. `build`
  fails with `BuildErrorKind::InvalidPolicy` unless the H3 TLS settings
  enable `session_tickets`.
- If the server rejects the early data, it processed none of it. Phantom
  sends the request again after the handshake, over the same route and
  protocol, and does not reuse the rejected connection.

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

## Race the alternative against the origin

To avoid failing when the alternative is unreachable, race it against the
origin, as Chrome does. The request goes to whichever connection is ready
first:

```rust
use std::num::NonZeroUsize;
use std::time::Duration;

use phantom::profile::ClientProfile;
use phantom::{AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, BuildError, Client};

fn racing_client(profile: ClientProfile) -> Result<Client, BuildError> {
    Client::builder(profile)
        .alt_svc(NonZeroUsize::new(64).expect("64 is nonzero"))
        .alt_svc_policy(AltSvcPolicy::race(AltSvcRace::new(
            Duration::from_millis(300),
            AltSvcBrokenBackoff::CHROMIUM_153,
        )))
        .build()
}
```

- QUIC setup to the alternative starts first. Origin setup starts after the
  delay you pass, or at once if the alternative fails first or a reusable
  HTTP/2 connection to the origin is pooled. There is no preset delay; zero
  starts both together.
- The request is sent once, on the winner, and `ResponseInfo` reports the
  winner's protocol. Later retries and replays stay on that protocol.
- An alternative that fails while the origin succeeds is marked broken and
  not raced until the backoff ends. `CHROMIUM_153` is 300 seconds, doubling
  per failure, capped at two days; a successful alternative connection resets
  it. When both fail, Phantom returns the origin's error.
- Racing needs `ClientBuilder::alt_svc` and never applies to a proxy route.

## Keep Alt-Svc state across restarts

Alt-Svc state lives in memory. Export it, store the entries in any format,
and import them into the next client:

```rust
use std::time::SystemTime;

use phantom::{AltSvcSnapshot, AltSvcSnapshotEntry, AltSvcSnapshotError, Client};

type Saved = Vec<(String, String, u16, SystemTime)>;

fn save(client: &Client) -> Saved {
    let snapshot = client.export_alt_svc().unwrap_or_default();
    let fields = |e: &AltSvcSnapshotEntry| {
        let (host, port) = (e.alternative_host().to_owned(), e.alternative_port());
        (e.origin().to_owned(), host, port, e.expires_at())
    };
    snapshot.entries().iter().map(fields).collect()
}

fn restore(client: &Client, saved: Saved) -> Result<(), AltSvcSnapshotError> {
    let entries = saved.into_iter().map(|(origin, host, port, expires)| {
        AltSvcSnapshotEntry::new(origin, host, port, expires)
    });
    client.import_alt_svc(&AltSvcSnapshot::new(entries.collect()))
}
```

- `export_alt_svc` returns `None` when Alt-Svc is disabled. Entries are least
  recently used first; expiry is rounded down to a whole second.
- A snapshot holds direct-route entries only. It never contains brokenness,
  TLS tickets, connections, cookies, or credentials, and its `Debug` output
  omits hosts.
- Import revalidates every entry and rejects the whole snapshot if one is not
  canonical. It drops expired entries, never extends a lifetime, and keeps
  alternatives the client already holds.

## Limits

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
- A raced alternative setup, including name resolution, may run for at most
  4 seconds, less than Chrome allows
  ([racing evidence](../explanation/validation.md#alt-svc-racing-evidence)).
- Not implemented: racing more than one alternative, DNS HTTPS-record
  (`dns_alpn_h3`) jobs, persisting brokenness or clearing it on a network
  change, an RTT-derived racing delay, proxy-route snapshots, WebSocket over
  H3, and early data in a named recipe. Chromium 154 source enables it by
  default, but no retained capture shows Chrome sending it.

## Next

- [Routes and proxies](routes-and-proxies.md): configure SOCKS5 and
  CONNECT-UDP routes for H3.
- [Alt-Svc evidence](../explanation/validation.md#alt-svc-http3-upgrade-evidence)
  and [racing evidence](../explanation/validation.md#alt-svc-racing-evidence):
  the tests and captures behind this page.
- [HTTP/3 internals](../internals/http3.md): pooling and the QUIC stack.
