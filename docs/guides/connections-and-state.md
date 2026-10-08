# Connections and client state

Share one client between tasks, keep separate sessions apart, choose where
connections leave from, and clear what a client has learned.

> Read [Using the client](client.md) first.

A `Client` keeps everything that outlasts one request: open connections,
cookies, TLS session tickets, cached addresses, and what servers told it
through headers such as `Accept-CH` and `Alt-Svc`. This page calls that
state the client's session. Each store has a size limit, and nothing is
shared across the process.

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

- Clones share one session. Clients you build separately share nothing.
- HTTP/1.1 connections carry one request at a time
  ([send several in parallel](#send-http11-requests-to-one-origin-in-parallel)).
- HTTP/2 and HTTP/3 send many requests over one connection per server.
  [Open more](performance.md#open-more-than-one-connection-per-origin)
  when you need them.
- Dropping a request cancels that request only.

## Send HTTP/1.1 requests to one origin in parallel

Open several HTTP/1.1 connections to one server, up to a browser's limit,
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

Idle connections count toward the limit, and a request waits once it's
reached. Without `with_http1`, the limit is one connection.
`ClientBuilder::max_concurrent_http1_requests_per_origin` sets your own.

## Keep sessions apart

Build a separate client for each identity, so cookies and connections from
one never reach the other.

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

Separate sessions still send the same fingerprint when they're built from
the same profile.

## Send connections from a chosen local address

Make every connection leave from a local address you choose, or from a
network interface.

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use phantom::profile::{chromium, ClientProfile};
use phantom::{BuildError, Client};

fn bound_client() -> Result<Client, BuildError> {
    let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    Client::builder(profile)
        .local_address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        .local_address(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)))
        .build()
}
```

- Call `local_address` once for IPv4 and once for IPv6. With only one, the
  client connects to addresses of that family only, like curl's
  `--interface`.
- `interface("eth0")` binds to a named interface on Linux, Android, macOS
  and Windows.
- The binding covers TCP and UDP connections to servers and proxies. DNS
  lookups aren't bound.

## Clear what a client has learned

Forget learned client hints, Alt-Svc entries, cached addresses and cookies
without building a new client.

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

Browsers forget cached addresses when the network changes. Phantom doesn't
watch the network, so call `clear_dns_cache` after a change.

## Limits

- Browsers keep separate TLS session tickets for each site a page runs
  under. For each server and route, a Phantom client shares tickets across
  its requests.
- On Linux kernels before 5.7, `interface` needs `CAP_NET_RAW`.
- Phantom doesn't check that a `local_address` belongs to the `interface`
  you also set.

## Next

- [Cookies](cookies.md): keep, save, and place cookies.
- [Redirects](redirects.md): follow redirects.
- [Defaults and limits](../reference/limits.md#connection-pools): pool and
  store sizes.
