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
  [Session tickets](../internals/http3.md#session-tickets).
  [QUIC session resumption](../explanation/validation.md#quic-session-resumption)
  gives the Chromium source for this rule.
- Concurrent requests to a resumed origin share one connection while its
  early data is unanswered.
- The server must have issued a ticket that permits early data. If it
  rejects the early data, it processed none of it. Phantom sends the request
  again after a handshake, over the same route and protocol, on a new
  connection. A handshake that fails after the connection sent early data
  fails the waiting requests; it is not retried.

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

## Find HTTP/3 through HTTPS DNS records

An origin can advertise H3 in an [HTTPS DNS record](../reference/glossary.md#https-record),
so the first request to it can use H3 without an earlier Alt-Svc response.
Enable discovery with `ClientBuilder::https_record_discovery`, which needs
`ClientBuilder::alt_svc`. The method and the `phantom::dns` module exist only
with the `https-records` feature, which adds the `hickory-resolver`
dependency:

```rust
use std::num::NonZeroUsize;

use phantom::dns::HttpsRecordResolver;
use phantom::profile::ClientProfile;
use phantom::Client;

fn discovering_client(profile: ClientProfile) -> Result<Client, Box<dyn std::error::Error>> {
    Ok(Client::builder(profile)
        .alt_svc(NonZeroUsize::new(64).expect("64 is nonzero"))
        .https_record_discovery(HttpsRecordResolver::system()?)
        .build()?)
}
```

- The lookup never delays a request. The first negotiated request to an
  origin starts it: a sequential client sends that request to the origin,
  and a racing client starts origin setup at once and H3 setup only if the
  records list `h3`. Later requests use the cached result.
- Only negotiated requests on the direct route with no stored Alt-Svc
  alternative look up records. Proxy routes and IP-literal origins send no
  query.
- The H3 endpoint is the origin's own host and port, so the request carries
  no `Alt-Used` field. If H3 setup fails, the location is marked broken and
  later requests go to the origin until the backoff ends.
- `HttpsRecordResolver::system` queries the nameservers configured on the
  host; `HttpsRecordResolver::with_nameservers` takes explicit ones.

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
- HTTPS records advertise H3 only through a ServiceMode record that lists
  `h3` for the origin's own host and port. As in Chrome 154.0.8037.58, a
  record is ignored when it names another target or port or lists a
  mandatory key Phantom does not support, and all records are ignored when
  any is in AliasMode or every one sets `no-default-alpn`. A timeout,
  `SERVFAIL`, or malformed record counts as no advertisement. Cache bounds
  are in [Defaults and limits](../reference/limits.md#protocol-state).
- Phantom sends HTTPS queries from its own DNS client while the operating
  system resolves addresses, so an observer sees DNS traffic from two
  sources where Chrome shows one
  ([HTTPS record evidence](../explanation/validation.md#https-dns-record-evidence)).
- Not implemented: racing more than one alternative (a stored Alt-Svc
  alternative is used instead of an HTTPS-record one), Encrypted Client
  Hello from a record's `ech` value, persisting brokenness or clearing it on
  a network change, an RTT-derived racing delay, proxy-route snapshots,
  WebSocket over H3, and early data on an Alt-Svc racing attempt.

## Next

- [Routes and proxies](routes-and-proxies.md): configure SOCKS5 and
  CONNECT-UDP routes for H3.
- [Alt-Svc evidence](../explanation/validation.md#alt-svc-http3-upgrade-evidence)
  and [racing evidence](../explanation/validation.md#alt-svc-racing-evidence):
  the tests and captures behind this page.
- [HTTP/3 internals](../internals/http3.md): pooling and the QUIC stack.
