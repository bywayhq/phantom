# HTTP/3 and Alt-Svc

HTTP/3 (H3) runs over QUIC instead of TCP. Phantom offers two ways to use it:

- **Exact H3**: `get(HttpProtocol::Http3, ...)` always uses H3 and never falls
  back to H1 or H2.
- **Alt-Svc upgrade**: a negotiated H1/H2 response can advertise an H3
  endpoint through the `Alt-Svc` field. With Alt-Svc enabled, a later
  negotiated request to the same origin uses it.

Both need H3 settings on the profile. Packet-level details are in
[HTTP/3 internals](../internals/http3.md).

## Add HTTP/3 to a profile

H3 needs its own TLS ClientHello, QUIC transport parameters, HTTP/3 connection
settings, and request settings, grouped as `Http3ClientSettings`:

```rust
use phantom::profile::{chromium, ClientProfile, Http3ClientSettings};
use phantom::{Client, HttpProtocol};

async fn run_h3() -> Result<(), Box<dyn std::error::Error>> {
    let http3 = Http3ClientSettings::new(
        chromium::v152_http3_tls(),
        chromium::v152_quic(),
        chromium::v152_http3(),
        chromium::v152_http3_request(),
    );
    let profile = ClientProfile::new(chromium::v152_tls()).with_http3(http3);

    let client = Client::builder(profile).build()?;
    let response = client
        .get(HttpProtocol::Http3, "https://example.com/")?
        .send()
        .await?;
    println!("{}", response.status());
    Ok(())
}
```

The TCP TLS settings passed to `ClientProfile::new` stay separate from the H3
TLS settings; each protocol uses only its own.

## Routes for HTTP/3

Exact H3 accepts three kinds of route:

- direct QUIC;
- local-DNS `socks5://` or remote-DNS `socks5h://` through RFC 1928 UDP
  ASSOCIATE; and
- an RFC 9298 CONNECT-UDP (MASQUE) proxy.

It rejects HTTP forwarding and HTTP CONNECT before origin I/O. See
[Routes and proxies](routes-and-proxies.md) for configuration.

## Alt-Svc

Alt-Svc lets an origin say "this same service is also available over H3 at
this host and port". Phantom's support is opt-in and bounded.

```rust
use std::num::NonZeroUsize;

use phantom::profile::{chromium, ClientProfile, Http3ClientSettings};
use phantom::{Client, ResponseInfo};

async fn upgrade() -> Result<(), Box<dyn std::error::Error>> {
    let http3 = Http3ClientSettings::new(
        chromium::v152_http3_tls(),
        chromium::v152_quic(),
        chromium::v152_http3(),
        chromium::v152_http3_request(),
    );
    let profile = ClientProfile::new(chromium::v152_tls())
        .with_http2(chromium::v152_http2())
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

### How an alternative is learned and used

An authenticated negotiated H1/H2 response can advertise `h3`. Phantom
applies `Age` to `ma` (the advertised maximum age), replaces the origin's
previous alternatives, and uses the first fresh canonical `h3` alternative on
the next negotiated request.

The alternative changes only the QUIC network location. The URI, authority,
TLS identity, cookies, client hints, route key, and timeouts remain those of
the origin.

On that managed Alt-Svc H3 attempt, Phantom automatically sends one canonical
`Alt-Used` value naming the alternative with an explicit port. It does not add
`Alt-Used` to exact H3 requests or ordinary negotiated H1/H2 requests.
Caller-supplied `Alt-Used` request fields and trailers are reserved and
rejected before network I/O. This support makes no browser-specific
field-order claim.

### HTTP/2 ALTSVC frames

A negotiated H2 response also teaches HTTP/2 ALTSVC frames (RFC 7838 section
4) that arrived before its final headers, in arrival order and before the
response's own `Alt-Svc` field.

- A stream-0 frame applies only when its origin is exactly the request's
  canonical ASCII origin, such as `https://example.com` or
  `https://example.com:8443`.
- A frame on the request's stream applies to the request origin.
- Malformed frames, frames for another origin, frames on exact H2 requests,
  and frames received while Alt-Svc is disabled change nothing.
- Each connection keeps at most 16 undelivered frames.

### Persisting Alt-Svc state

Alt-Svc state stays in memory unless the caller persists it.

- `Client::export_alt_svc` returns an `AltSvcSnapshot`, or `None` when Alt-Svc
  is disabled. Each entry holds only the canonical origin, the alternative
  host and port, and an absolute `SystemTime` expiry rounded down to a whole
  second, least recently used first.
- Phantom provides no serialization format. Rebuild entries with
  `AltSvcSnapshotEntry::new` and pass them to `Client::import_alt_svc`.
- Import revalidates every entry and rejects the whole snapshot with a typed
  `AltSvcSnapshotError` if one origin or alternative is not canonical.
- Import drops expired entries, clamps lifetimes without extending them, gives
  already-held alternatives precedence, and keeps the most recently used
  entries within the store capacity.

The store is keyed by origin for direct routes, so a snapshot describes
direct-route alternatives only. It never contains TLS tickets, connections,
routes, cookies, or credentials, and its `Debug` output omits hosts.

### Pooling

One origin-and-route pool entry keeps connections for up to four transport
locations, so alternating exact H3 and Alt-Svc H3 requests reuse their own
connections under the same admission bounds instead of replacing each other.

### Failures

By default (`AltSvcPolicy::sequential`), alternative setup failure is a typed
H3 failure for that request and evicts the advertisement; it never silently
falls back to H1 or H2. A visible `421` response also evicts it.
`Client::clear_alt_svc` clears the whole store, including broken state.

### Racing

`ClientBuilder::alt_svc_policy(AltSvcPolicy::race(...))` opts into racing and
requires `ClientBuilder::alt_svc`. Racing is a declared two-candidate
connection choice, not a fallback:

- Before any I/O, both the H3 and the H1/H2 forms of the request are
  validated.
- QUIC setup to the alternative starts first. Origin H1/H2 setup starts after
  the caller's `AltSvcRace` origin delay, or at once if the alternative fails
  first or the origin already has a reusable pooled H2 connection. Each
  candidate holds its own pool admission and at most one setup attempt.
- The first candidate to finish carries the request exactly once. The request
  body, including a one-shot stream, is built only for the winner, and
  `ResponseInfo` reports the winner's protocol.
- Both candidates keep the request's origin authority, TLS name, and direct
  route; racing never applies to a proxy route.
- Cancelling the request before a winner cancels both setups. The connect and
  total deadlines bound each setup and the whole race.

An alternative connection attempt may run for at most 4 seconds, or less
under the request's connect and total deadlines. Reaching that limit is a
setup failure. Chrome 153 fails a blackholed alternative after 4 seconds, its
client QUIC idle timeout before the handshake completes. Chrome restarts that
timer whenever a packet arrives and allows a responsive handshake up to 10
seconds. Phantom cannot see handshake packets at this layer, so it limits the
whole attempt, including name resolution and, on proxy routes, proxy setup: a
responsive alternative whose handshake takes longer than 4 seconds, or a slow
resolver or proxy, fails in Phantom but not in Chrome.

When the alternative wins, a still-connecting origin setup is cancelled. When
the origin wins, an alternative that has begun connecting continues in the
background, like Chromium's orphaned alternative job: a finished connection is
pooled for later requests, and a failure, including the 4-second limit, marks
the alternative broken. Until then it keeps its H3 admission permit for the
origin and route. A setup still waiting for admission, or for another setup to
the same QUIC location to finish, has done no network work and is cancelled
instead. The background setup needs the Tokio runtime that ran the request; if
none is available, the setup is dropped, nothing is pooled or marked, and the
next request races the alternative again.

Setups for one origin and route are serialized per QUIC location. A request
to a location waits while another setup connects to that same location and
then reuses its connection if that setup succeeded; exact H3 to the origin's
own location does not wait for a background alternative setup.

An alternative that fails while the origin succeeds is marked broken for
`AltSvcBrokenBackoff`: the first failure lasts `initial`, each later failure
doubles it up to `maximum`, and a successful alternative connection clears the
history. As in Chromium, a failure reported while the alternative is already
broken counts toward the next period but does not extend the current one. A
broken alternative is not raced; the request goes to the origin.
When both candidates fail, the origin's error is returned and nothing is
marked. After a winner is chosen, retries and replays within the request stay
on the winner's protocol, and a later failure on a won alternative evicts it
as in sequential use.

`AltSvcBrokenBackoff::CHROMIUM_153` is 300 seconds, doubling, capped at two
days. Chromium's origin delay depends on QUIC history and measured RTT, so
Phantom has no named delay and the caller chooses one. Brokenness is not part
of `AltSvcSnapshot`.

## Not implemented

- Multiple-alternative racing and DNS HTTPS-record (`dns_alpn_h3`) jobs.
- Persisting Alt-Svc brokenness, or clearing it on a network change.
- An RTT-derived racing delay, and keeping a losing origin connection idle.
- Alt-Svc upgrades on proxy routes, and proxy-route snapshots.
- WebSocket over H3.
- QUIC session tickets.

[Alt-Svc evidence](../explanation/validation.md#alt-svc-http3-upgrade-evidence)
and [Alt-Svc racing evidence](../explanation/validation.md#alt-svc-racing-evidence)
list the tests and captures behind this behavior.
