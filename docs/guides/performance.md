# Tune throughput and latency

Let one client run more requests at once and wait less, and see what each
change shows a server.

> Read [Connections and client state](connections-and-state.md) first.

Most defaults are the browser's values. Some changes are invisible to
the server. Others make the client look less like the browser, as the
table shows. Phantom doesn't rate-limit requests: when to send is up to
your code.

| Setting | Speeds up | Server sees | Default |
| --- | --- | --- | --- |
| `max_concurrent_http1_requests_per_origin` | Parallel HTTP/1.1 requests | More connections | 6 in the recipes, else 1 |
| `max_pending_http{1,2,3}_requests_per_origin` | Nothing: limits the queue | Nothing | 100 |
| `max_concurrent_http{2,3}_requests_per_origin` | Requests in flight | Nothing | 100 |
| `max_retained_http{1,2,3}_connections` | Reuse across many servers | Fewer handshakes | 32 |
| `max_http2_connections_per_origin` | HTTP/2 past the stream limit | Several HTTP/2 connections | 1 |
| `max_http3_connections_per_origin` | HTTP/3 past the stream limit | Several QUIC connections | 1 |
| `negotiated_setup_wait_limit` | Requests behind a slow handshake | A second handshake | No limit |
| `alt_svc_policy` race | First HTTP/3 request | QUIC and TCP at once | Off |
| `http3_early_data` | First request on a resumed connection | Early data | On in the recipes |
| `https_record_discovery` | HTTP/3 before any `Alt-Svc` header | Extra DNS queries | Off |
| `preemptive_proxy_authentication` | Proxied requests after the first | Fewer `407` responses | On |
| Custom `Http2Settings` windows | Large downloads on slow links | Different HTTP/2 settings | The recipe's |

## Send more requests to one origin at once

Let one server carry more parallel requests over HTTP/1.1 and HTTP/2.

```rust
use std::num::NonZeroUsize;

use phantom::profile::{ClientProfile, browser::chrome};
use phantom::Client;

fn parallel_client() -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http1(chrome::v154_http1())
        .with_http2(chrome::v154_http2());
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

A request that finds the queue full fails at once with
`RequestErrorKind::Capacity`. Treat it as a sign to slow down.

## Open more than one connection per origin

Spread requests over several connections when the server limits how many
each one carries.

```rust
use std::num::NonZeroUsize;

use phantom::profile::{ClientProfile, browser::chrome};
use phantom::Client;

fn multi_connection_client() -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http2(chrome::v154_http2());
    let bound = |value| NonZeroUsize::new(value).ok_or("zero bound");
    Ok(Client::builder(profile)
        // Up to 4 connections of 100 streams each, if the server allows 100.
        .max_http2_connections_per_origin(bound(4)?)
        .max_concurrent_http2_requests_per_origin(bound(400)?)
        .build()?)
}
```

Phantom opens a new connection only when every open one is full.
`max_http3_connections_per_origin` does the same for HTTP/3, up to 8. Chrome,
Edge and Firefox keep one connection per server, so a server can see the
difference.

## Stop waiting for a stalled handshake

Once a server has picked HTTP/2, a negotiated request waits for another
request's handshake instead of opening its own connection. Limit that wait,
as Chromium does:

```rust
use std::time::Duration;

use phantom::profile::{ClientProfile, browser::chrome};
use phantom::Client;

fn bounded_wait_client() -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http2(chrome::v154_http2());
    Ok(Client::builder(profile)
        // Chromium 154's value; Firefox 157 waits without a limit.
        .negotiated_setup_wait_limit(Duration::from_millis(300))
        .build()?)
}
```

After the limit, the request opens its own connection. If both end up on
HTTP/2, Phantom closes the second one and moves its requests to the first,
unless you allow more than one connection per server.

## Reach HTTP/3 sooner

Race HTTP/3 against HTTP/2, and give up on a QUIC attempt sooner than
Phantom's default of 4 seconds.

```rust
use std::num::NonZeroUsize;
use std::time::Duration;

use phantom::profile::{ClientProfile, Http3ClientSettings, browser::chrome};
use phantom::{AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, Client};

fn racing_client() -> Result<Client, Box<dyn std::error::Error>> {
    let http3 = Http3ClientSettings::new(
        chrome::v154_quic_tls(),
        chrome::v154_quic(),
        chrome::v154_http3(),
        chrome::v154_http3_request(),
    );
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_http3(http3);
    let race = AltSvcRace::new(Duration::from_millis(300), AltSvcBrokenBackoff::CHROMIUM_153)
        .with_alternative_setup_limit(Duration::from_secs(1));
    Ok(Client::builder(profile)
        .alt_svc(NonZeroUsize::new(1_024).ok_or("zero origins")?)
        .alt_svc_policy(AltSvcPolicy::race(race))
        .build()?)
}
```

A shorter limit also gives up on slow HTTP/3 servers that Chrome would
have used. [HTTP/3 discovery](http3-discovery.md) covers racing in more
detail.

## Skip work and bound waits

Redirects, cookies, decompression and timeouts are off by default. Most
retries are too; the [retry guide](retries.md) lists the exceptions. Set
`RequestTimeouts` to stop waiting on a slow server
([Using the client](client.md#configure-the-client)). Use
`RetryPolicy::connection_failures` to retry a failed connection
([Retries and replays](retries.md)).

## Change flow-control windows

Let one HTTP/2 connection receive more data before the server has to wait,
with a custom profile.

```rust
use phantom::profile::{ClientProfile, browser::chrome};

fn wide_window_profile() -> ClientProfile {
    let mut http2 = chrome::v154_http2();
    // Chrome 154 opens a 15 MiB connection window.
    http2.initial_connection_window_size = 64 << 20;
    ClientProfile::new(chrome::v154_tcp_tls()).with_http2(http2)
}
```

The window size is part of the
[HTTP/2 fingerprint](../fingerprinting.md#http2), so the client no longer
matches Chrome.

## Next

- [Defaults and limits](../reference/limits.md#delays-and-timers): every
  limit and timer.
- [HTTP/3 discovery](http3-discovery.md): racing and DNS discovery.
- [Retries and replays](retries.md): what Phantom sends again.
