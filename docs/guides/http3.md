# HTTP/3 and Alt-Svc

HTTP/3 (H3) is HTTP over QUIC, a UDP-based transport, instead of TCP.
Phantom offers two ways to use it:

- **Exact H3.** `get(HttpProtocol::Http3, ...)` always uses H3. It never falls
  back to HTTP/1.1 (H1) or HTTP/2 (H2).
- **Alt-Svc upgrade.** An H1 or H2 response can advertise an H3 endpoint in
  its `Alt-Svc` field. With Alt-Svc enabled, a later negotiated request to the
  same origin uses that endpoint. Browsers use Alt-Svc to discover H3.

Both need H3 settings on the profile. Packet-level details are in
[HTTP/3 internals](../internals/http3.md).

## Add HTTP/3 to a profile

A browser's H3 connection looks different from its TCP connection, so H3 has
its own settings. `Http3ClientSettings` groups four of them: the TLS
ClientHello, the QUIC transport parameters, the HTTP/3 connection settings,
and the request settings.

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

The TLS settings passed to `ClientProfile::new` apply only to TCP
connections. H3 connections use only the TLS settings inside
`Http3ClientSettings`.

## Routes for HTTP/3

Exact H3 works over three kinds of route:

- direct QUIC;
- SOCKS5 UDP ASSOCIATE (RFC 1928), with local DNS (`socks5://`) or remote DNS
  (`socks5h://`); and
- a CONNECT-UDP (MASQUE, RFC 9298) proxy.

HTTP forwarding and HTTP CONNECT proxies cannot carry QUIC, so exact H3
rejects them before any origin I/O. See
[Routes and proxies](routes-and-proxies.md) for configuration.

## Alt-Svc

Alt-Svc (RFC 7838) lets an origin say that the same service is also available
over H3 at a given host and port. Phantom's support is opt-in: call
`ClientBuilder::alt_svc` with the maximum number of entries to remember. The
store is keyed by origin **and** route, so one origin learned over two routes
occupies two entries.

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

    // A later negotiated request may use the learned alternative.
    let second = client.get_negotiated("https://example.com/")?.send().await?;
    if let Some(info) = second.extensions().get::<ResponseInfo>() {
        println!("{:?}", info.protocol());
    }
    Ok(())
}
```

`ResponseInfo::protocol` tells you which protocol carried a response.

### Routes that carry the upgrade

The upgrade needs two things from one route: a TLS stream to the origin for
ALPN to select H1 or H2 on, and a UDP path to the advertised alternative
authority. Phantom never falls back, so a route that cannot provide both
rejects a negotiated request before any proxy or origin I/O, with
`RequestErrorKind::UnsupportedRoute`.

| Route | Negotiated HTTPS and Alt-Svc upgrade | Why |
| --- | --- | --- |
| Direct | Yes | TCP for ALPN, UDP for QUIC. |
| SOCKS5 (`socks5://`, `socks5h://`) | Yes | RFC 1928 CONNECT carries the origin TLS stream; RFC 1928 UDP ASSOCIATE carries QUIC to the alternative. |
| HTTP proxy (forwarding or CONNECT, HTTP/1.1 or HTTP/2 transport) | Rejected | A CONNECT tunnel is a TCP byte stream, so an `h3` alternative is unreachable. |
| CONNECT-UDP (MASQUE) | Rejected | The route carries QUIC only, so there is no TLS stream for ALPN to select a protocol on. |

An alternative learned over one route is used only over that route. The store
is keyed by origin **and** route, as the connection pools are, so an
advertisement seen through one proxy is never dialed through another proxy or
directly, and a location that is broken on one route is not broken on another.

Chromium behaves the same way for HTTP and HTTPS proxies. At 153.0.8010.48 it
creates the alternative job even when proxied, then fails it with
`ERR_NO_SUPPORTED_PROXIES` unless every hop of the proxy chain speaks QUIC
(`net/http/http_stream_factory_job.cc` lines 858-868), because "MASQUE defines
mechanisms to carry QUIC traffic over non-QUIC proxies" whose performance
"would be worse than simply using H/1 or H/2 to reach the destination".
Chromium then resumes its main TCP job; Phantom has no such fallback, so it
refuses the route up front instead. Chromium has no SOCKS5 UDP ASSOCIATE at
all (`net/socket/socks5_client_socket.cc` defines only `kTunnelCommand`), so
its SOCKS5 routes never carry QUIC; Phantom's do, as they already do for
exact H3.

### How an alternative is learned and used

Only an authenticated, negotiated H1 or H2 response can advertise `h3`. When
one does, Phantom:

1. subtracts the response's `Age` from `ma`, the advertised maximum age;
2. replaces the origin's previous alternatives; and
3. uses the first fresh canonical `h3` alternative on the next negotiated
   request.

The alternative changes only where the QUIC connection goes. The URI,
authority, TLS identity, cookies, client hints, route key, and timeouts stay
those of the origin.

On a request sent to the alternative, Phantom adds one canonical `Alt-Used`
field that names the alternative with an explicit port. It does not add
`Alt-Used` to exact H3 requests or to ordinary H1 or H2 requests. Phantom
manages this field, so a caller-supplied `Alt-Used` field or trailer is
rejected before network I/O. Phantom makes no browser-specific claim about
where `Alt-Used` sits in the field order.

### HTTP/2 ALTSVC frames

An H2 server can also advertise alternatives with ALTSVC frames (RFC 7838
section 4). A negotiated H2 response learns the frames that arrived before
its final headers, in arrival order, and then its own `Alt-Svc` field.

- A frame on stream 0 applies only when its origin matches the request's
  canonical ASCII origin exactly, such as `https://example.com` or
  `https://example.com:8443`.
- A frame on the request's own stream applies to the request's origin.
- Nothing changes for malformed frames, frames for another origin, frames on
  exact H2 requests, or frames received while Alt-Svc is disabled.
- Each connection keeps at most 16 undelivered frames.

### Persisting Alt-Svc state

Alt-Svc state lives in memory. To keep it across restarts, export it and
import it yourself:

- `Client::export_alt_svc` returns an `AltSvcSnapshot`, or `None` when Alt-Svc
  is disabled. Entries are ordered least recently used first. Each holds only
  the canonical origin, the alternative host and port, and an absolute
  `SystemTime` expiry rounded down to a whole second.
- Phantom provides no serialization format. Store the entries however you
  like, rebuild them with `AltSvcSnapshotEntry::new`, and pass them to
  `Client::import_alt_svc`.
- Import revalidates every entry. If any origin or alternative is not
  canonical, it rejects the whole snapshot with a typed
  `AltSvcSnapshotError`.
- Import drops expired entries and clamps lifetimes without extending them.
  Alternatives the client already holds take precedence, and the most
  recently used entries are kept within the store capacity.

A snapshot carries no route. Exporting therefore keeps the direct-route
entries and omits every proxy-route one, and importing restores direct-route
entries only, so a proxy route's alternatives never cross a snapshot into
another route. A snapshot never contains TLS tickets, connections, routes,
cookies, or credentials, and its `Debug` output omits hosts.

### Pooling

A pool entry for one origin and route keeps connections for up to four QUIC
locations. Exact H3 and Alt-Svc H3 requests to the same origin therefore
reuse their own connections, under the same admission limits, instead of
replacing each other. The route is part of the entry key, so a direct
alternative and the same alternative reached through a SOCKS5 proxy are
separate connections.

### Failures

By default (`AltSvcPolicy::sequential`), Phantom tries only the alternative.
If setup fails, the request returns a typed H3 error and the advertisement is
evicted. Phantom never silently retries over H1 or H2. A `421` (Misdirected
Request) response also evicts the advertisement.
`Client::clear_alt_svc` clears the whole store, including broken state.

### Racing

Racing starts setting up the alternative, starts the origin after a delay you
choose, and sends the request on whichever is ready first. It is modeled on
Chrome 154's captured behavior, with the differences listed below. Enable it with
`ClientBuilder::alt_svc_policy(AltSvcPolicy::race(...))`, which requires
`ClientBuilder::alt_svc`. Racing is a declared choice between two candidates,
not a fallback.

How a race runs:

- Before any I/O, Phantom validates both the H3 and the H1/H2 form of the
  request.
- QUIC setup to the alternative starts first. Origin H1/H2 setup starts after
  the origin delay you set in `AltSvcRace`. It starts at once if the
  alternative fails first or the origin already has a reusable pooled H2
  connection.
- Each candidate holds its own pool admission and makes at most one setup
  attempt.
- The first candidate to finish carries the request, exactly once. The
  request body, including a one-shot stream, is built only for the winner.
  `ResponseInfo` reports the winner's protocol.
- Both candidates keep the request's origin authority, TLS name, and direct
  route. Racing never applies to a proxy route.
- Cancelling the request before a winner cancels both setups. The connect and
  total deadlines bound each setup and the whole race.

Chromium's origin delay depends on QUIC history and measured round-trip time
(RTT), so Phantom has no named delay; you choose one.

#### The 4-second setup limit

An alternative connection attempt may run for at most 4 seconds, or less
under the request's connect and total deadlines. Reaching the limit is a
setup failure.

This follows Chrome 154, which fails an unreachable alternative after
4 seconds: its client QUIC idle timeout before the handshake completes.
Chrome restarts that timer whenever a packet arrives, so it allows a
responsive handshake up to 10 seconds. Phantom cannot see handshake packets
at this layer, so its limit covers the whole attempt, including name
resolution and, on proxy routes, proxy setup. A responsive alternative whose
handshake takes longer than 4 seconds, or a slow resolver or proxy, fails in
Phantom but not in Chrome.

#### When the origin wins

When the alternative wins, a still-connecting origin setup is cancelled.

When the origin wins, an alternative that has begun connecting keeps going in
the background, like Chromium's orphaned alternative job:

- If it connects, the connection is pooled for later requests.
- If it fails, including by hitting the 4-second limit, the alternative is
  marked broken.
- Until it finishes, it keeps its H3 admission permit for the origin and
  route.

A setup still waiting for admission, or for another setup to the same QUIC
location, has done no network work, so it is cancelled instead. The
background setup needs the Tokio runtime that ran the request. If that
runtime is gone, the setup is dropped, nothing is pooled or marked, and the
next request races the alternative again.

Setups for one origin and route run one at a time per QUIC location. A
request to a location waits while another setup connects to that location,
then reuses the connection if that setup succeeded. Exact H3 to the origin's
own location does not wait for a background alternative setup.

#### Broken alternatives

An alternative that fails while the origin succeeds is marked broken for a
period set by `AltSvcBrokenBackoff`, and is not raced during it; requests go
to the origin.

- The first failure lasts `initial`. Each later failure doubles the period,
  up to `maximum`.
- A successful alternative connection clears the history.
- As in Chromium, a failure reported while the alternative is already broken
  counts toward the next period but does not extend the current one.
- `AltSvcBrokenBackoff::CHROMIUM_153` is 300 seconds, doubling, capped at two
  days.
- Brokenness is not part of `AltSvcSnapshot`.

When both candidates fail, Phantom returns the origin's error and marks
nothing. After a winner is chosen, retries and replays within the request
stay on the winner's protocol. A later failure on a winning alternative
evicts it, as in sequential mode.

## Not implemented

- Racing more than one alternative, and DNS HTTPS-record (`dns_alpn_h3`)
  jobs.
- Persisting Alt-Svc brokenness, or clearing it on a network change.
- An RTT-derived racing delay, and keeping a losing origin connection idle.
- Alt-Svc upgrades on proxy routes, and proxy-route snapshots.
- WebSocket over H3.
- QUIC session tickets.

[Alt-Svc evidence](../explanation/validation.md#alt-svc-http3-upgrade-evidence)
and [Alt-Svc racing evidence](../explanation/validation.md#alt-svc-racing-evidence)
list the tests and captures behind this behavior.
