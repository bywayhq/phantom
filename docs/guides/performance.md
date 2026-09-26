# Tune throughput and latency

Raise the bounds on how many requests one client runs at once and shorten
the waits Phantom copies from browsers, knowing what each change lets a
server see.

> For builders who have read [Connections and client state](connections-and-state.md).

Every default is a browser's value, or a Phantom bound where no browser value
applies. Some changes are invisible on the wire; others make the client look
less like its profile's browser, as the table says. Phantom does not pace or
rate-limit requests: when and how fast to send is scheduling, and it belongs
to your code.

| Knob | Speeds up | A server can observe | Default |
| --- | --- | --- | --- |
| `max_concurrent_http1_requests_per_origin` | Parallel H1 requests to one origin | More simultaneous TCP and TLS connections | Profile's `Http1Settings` (6 in the recipes), else 1 |
| `max_pending_http{1,2,3}_requests_per_origin` | Nothing; it bounds queued requests | Nothing | 100 |
| `max_concurrent_http{2,3}_requests_per_origin` | Streams in flight per origin | Nothing; the peer's stream limit still applies | 100 |
| `max_retained_http{1,2,3}_connections` | Reuse across many origins | Fewer new handshakes | 32 pool entries |
| `max_http2_connections_per_origin` | H2 past the peer's stream limit | Several H2 connections to one origin | 1, as browsers |
| `negotiated_setup_wait_limit` | Requests behind a stalled handshake | A second TLS handshake to an H2 origin | No limit, as Firefox 156 |
| `alt_svc_policy` race, `with_alternative_setup_limit` | First request to an H3 origin | Parallel QUIC and TCP setup; when QUIC setup stops | Sequential; 4 s limit, as Chrome 153 |
| `http3_early_data` | First request on a resumed H3 connection | 0-RTT data | The profile's QUIC `early_data` |
| `https_record_discovery` | H3 without a prior Alt-Svc response | HTTPS queries to your DNS resolver | Off |
| `preemptive_proxy_authentication` | Proxied requests after the first | The proxy sees fewer `407` exchanges | On, as browsers |
| Custom `Http2Settings` windows | Large downloads on a high-latency path | SETTINGS and WINDOW_UPDATE values | The recipe's values |

## Send more requests to one origin at once

Let one origin carry more parallel work over H1 and H2.

```rust
use std::num::NonZeroUsize;

use phantom::profile::{chromium, ClientProfile};
use phantom::Client;

fn parallel_client() -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http1(chromium::v154_http1())
        .with_http2(chromium::v154_http2());
    let bound = |value| NonZeroUsize::new(value).ok_or("zero bound");
    Ok(Client::builder(profile)
        // Chrome opens at most 6 H1 connections per origin.
        .max_concurrent_http1_requests_per_origin(bound(12)?)
        .max_pending_http1_requests_per_origin(bound(1_000)?)
        .max_concurrent_http2_requests_per_origin(bound(200)?)
        .max_pending_http2_requests_per_origin(bound(1_000)?)
        .build()?)
}
```

- Every bound is per [pool key](../reference/glossary.md#pool-key): origin
  plus route. Two proxies to one origin get two sets of connections.
- A request past the waiting bound fails at once with
  `RequestErrorKind::Capacity`, which is how a queue tells you to slow down.
- An H2 server's `SETTINGS_MAX_CONCURRENT_STREAMS` caps streams per
  connection, whatever the local bound says.

## Open more than one HTTP/2 connection per origin

Go past the peer's stream limit by spreading streams over several
connections.

```rust
use std::num::NonZeroUsize;

use phantom::profile::{chromium, ClientProfile};
use phantom::Client;

fn multi_connection_client() -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    let bound = |value| NonZeroUsize::new(value).ok_or("zero bound");
    Ok(Client::builder(profile)
        // Up to 4 connections of 100 streams each, if the server allows 100.
        .max_http2_connections_per_origin(bound(4)?)
        .max_concurrent_http2_requests_per_origin(bound(400)?)
        .build()?)
}
```

- A new connection opens only when every connection to the key has as many
  streams in flight as the lower of the local bound and the server's limit.
  A new stream goes to the connection with the fewest.
- Each connection makes its own handshake and sends the profile's full H2
  preface, so each looks like the browser. Several at once to one origin
  do not: Chrome, Edge, and Firefox keep one.
- It applies to `HttpProtocol::Http2` and to `get_negotiated` requests that
  select H2; `max_http2_proxy_connections_per_route` is the same option for
  HTTP/2 proxy routes. HTTP/3 keeps one connection per origin and route.

## Stop waiting for a stalled handshake

Once an origin has selected H2, a negotiated request waits for another
request's handshake to that origin instead of opening its own. Bound that
wait as Chromium does.

```rust
use std::time::Duration;

use phantom::profile::{chromium, ClientProfile};
use phantom::Client;

fn bounded_wait_client() -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    Ok(Client::builder(profile)
        // Chromium 154's value; Firefox 156 waits without a limit.
        .negotiated_setup_wait_limit(Duration::from_millis(300))
        .build()?)
}
```

After the limit the request opens its own connection. If both select H2, the
later one closes and its requests join the first, unless
`max_http2_connections_per_origin` lets both stay.

## Reach HTTP/3 sooner

Race a learned H3 alternative against the origin, and stop a QUIC attempt
that gets no answer sooner than Chrome's 4 seconds.

```rust
use std::num::NonZeroUsize;
use std::time::Duration;

use phantom::profile::{chromium, ClientProfile, Http3ClientSettings};
use phantom::{AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, Client};

fn racing_client() -> Result<Client, Box<dyn std::error::Error>> {
    let http3 = Http3ClientSettings::new(
        chromium::v154_http3_tls(),
        chromium::v154_quic(),
        chromium::v154_http3(),
        chromium::v154_http3_request(),
    );
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_http3(http3);
    let race = AltSvcRace::new(Duration::from_millis(300), AltSvcBrokenBackoff::CHROMIUM_153)
        .with_alternative_setup_limit(Duration::from_secs(1));
    Ok(Client::builder(profile)
        .alt_svc(NonZeroUsize::new(1_024).ok_or("zero origins")?)
        .alt_svc_policy(AltSvcPolicy::race(race))
        .build()?)
}
```

- A shorter setup limit marks a blocked alternative broken sooner, and also
  gives up on a slow alternative that Chrome would have used.
- Early data and HTTPS-record discovery are in
  [HTTP/3 and Alt-Svc](http3.md). Early data only ever carries a request that
  is safe to replay; that rule is not configurable.

## Skip work and bound waits

Redirects, cookies, content decoding, retries, and timeouts are off by
default, so a client that enables none of them does none of that work.
`RequestTimeouts` frees a slot a slow server holds, and
`RetryPolicy::connection_failures` repeats a failed connection setup
([Using the client](client.md#configure-the-client),
[Retries and replays](retries.md)); the server sees a reset stream or closed
connection, and a new connection per retry. Preemptive proxy authentication
is on, as in browsers; turning it off costs a `407` round trip per tunnel.

## Change flow-control windows

Let one H2 connection receive more before the server must wait, with a
custom profile.

```rust
use phantom::profile::{chromium, ClientProfile};

fn wide_window_profile() -> ClientProfile {
    let mut http2 = chromium::v154_http2();
    // Chrome 154 opens a 15 MiB connection window.
    http2.initial_connection_window_size = 64 << 20;
    ClientProfile::new(chromium::v154_tls()).with_http2(http2)
}
```

The window is part of the H2 fingerprint
([How servers recognize a client](../fingerprinting.md#http2)): the preface's
WINDOW_UPDATE no longer matches Chrome. TCP address racing and keepalive are
fields of `TcpSettings` in the same way.

## Limits

- HTTP/3 keeps one connection per origin, route, and transport location;
  there is no `max_http3_connections_per_origin` yet.
- HTTPS-record lookups use hickory's per-query timeout of 5 seconds and 2
  attempts; `HttpsRecordResolver::from_fn` replaces the resolver entirely.
- Every timer and its source is listed in
  [Defaults and limits](../reference/limits.md#delays-and-timers).

## Next

- [Defaults and limits](../reference/limits.md): every bound and timer.
- [HTTP/3 and Alt-Svc](http3.md): racing, early data, and HTTPS records.
- [Retries and replays](retries.md): what may be sent again.
