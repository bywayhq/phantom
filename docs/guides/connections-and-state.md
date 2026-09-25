# Connections and client state

Share one client's connections and state between tasks, keep separate
sessions apart, and clear what a client has learned.

> For builders who have read [Using the client](client.md).

A `Client` owns every piece of state that outlives one request: connection
pools, redirect policy, cookies, learned client hints, Alt-Svc
advertisements, TLS session tickets, and resolved host addresses
([Resolve host names](name-resolution.md)). This page calls that state the
client's session. None of it is global to the process,
and every store has a size limit
([Design](../explanation/design.md#state-belongs-to-one-client-and-has-a-bound)).

## Share a client between tasks

Clone one client so tasks reuse its connections and state.

```rust
use phantom::{Client, HttpProtocol};

async fn in_background(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    // The clone shares this client's pools, cookies, and learned state.
    let client = client.clone();
    let task = tokio::spawn(async move {
        client.get(HttpProtocol::Http2, "https://example.com/")?.send().await.map(drop)
    });
    task.await??;
    Ok(())
}
```

- Clones share one session: pools, cookies, and all learned state.
  Separately built clients share nothing
  ([Keep sessions apart](#keep-sessions-apart)).
- H1 connections carry one request at a time, without pipelining; the
  profile decides how many run in parallel
  ([next task](#send-http11-requests-to-one-origin-in-parallel)). H2 and H3
  multiplex requests within the peer's limits and the client's own, on one
  connection per pool key unless you
  [allow more H2 connections](performance.md#open-more-than-one-http2-connection-per-origin).
- A pool key is the origin plus the complete route. Admission and retained
  connections are bounded per key
  ([Defaults and limits](../reference/limits.md#connection-pools)).
- Dropping one H2 or H3 request cancels its stream, not unrelated work.

## Send HTTP/1.1 requests to one origin in parallel

Open several H1 connections to one origin, up to a browser's per-host limit,
with the profile's `Http1Settings`.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol};

async fn in_parallel() -> Result<(), Box<dyn std::error::Error>> {
    // Chromium keeps up to 6 H1 connections to each origin and route.
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http1(chromium::v154_http1());
    let client = Client::builder(profile).build()?;

    let first = client.get(HttpProtocol::Http1, "https://example.com/a")?.send();
    let second = client.get(HttpProtocol::Http1, "https://example.com/b")?.send();
    // Each request runs on its own connection.
    let (first, second) = tokio::join!(first, second);
    println!("{} {}", first?.status(), second?.status());
    Ok(())
}
```

- Idle connections count toward the
  [connection bound](../reference/glossary.md#connection-bound), and a
  request waits once the bound is reached. Without `with_http1` the bound
  is 1; `ClientBuilder::max_concurrent_http1_requests_per_origin` replaces
  it.
- `get_negotiated` requests use the same bound when ALPN selects HTTP/1.1.
  When it selects HTTP/2, they share one connection. Handshake order and
  other rules:
  [HTTP/1.1 connections](../reference/profiles.md#http11-connections).

## Keep sessions apart

Give each identity its own session, the state one client and its clones
share, by building a separate client for it.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{BuildError, Client};

fn two_sessions() -> Result<(Client, Client), BuildError> {
    let profile = || ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    // Each build starts with empty pools and stores of its own.
    let first = Client::builder(profile()).cookies().build()?;
    let second = Client::builder(profile()).cookies().build()?;
    Ok((first, second))
}
```

- A session holds the connection pools, the cookie jar, learned client
  hints, Alt-Svc advertisements and cached HTTPS records, TLS and QUIC
  session tickets, the proxy credentials a proxy has accepted, and the
  address cache. Nothing in it reaches another session.
- Clones of a client are one session. Use a clone to share state between
  tasks, and a new client to keep it apart.
- A session does not change the profile: two sessions built from one profile
  send the same fingerprint.

## Clear what a client has learned

Discard learned client hints, Alt-Svc advertisements, cached addresses, and
cookies without building a new client.

```rust
use phantom::Client;

fn forget(client: &Client) {
    client.clear_client_hints();
    client.clear_alt_svc();
    client.clear_dns_cache();
    if let Some(jar) = client.cookie_jar() {
        jar.clear();
    }
}
```

- Learned `Accept-CH` state is bounded and scoped to the exact secure origin
  ([Send client hints](request-templates.md#send-client-hints)).
- Alt-Svc is off by default. `ClientBuilder::alt_svc` enables a bounded store
  keyed by exact origin for negotiated HTTPS requests; `export_alt_svc` and
  `import_alt_svc` move it through storage you own, and `alt_svc_policy`
  opts into racing ([HTTP/3 and Alt-Svc](http3.md#upgrade-to-http3-when-the-server-advertises-it)).
- Browsers forget cached addresses when the network changes. Phantom does
  not watch the network, so call `clear_dns_cache` after such a change.
- TLS session tickets for H1/H2, and QUIC session tickets for H3, are
  bounded and keyed by exact origin and route. Only QUIC tickets carry early
  data, when the profile or `ClientBuilder::http3_early_data` enables it
  ([HTTP/3 and Alt-Svc](http3.md#turn-off-early-data-on-resumed-connections)).

## Next

- [Cookies](cookies.md): keep, save, and place cookies.
- [Redirects](redirects.md): follow redirects within the route and protocol.
- [Defaults and limits](../reference/limits.md): pool and store bounds.
