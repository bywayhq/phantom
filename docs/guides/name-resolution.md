# Resolve host names

Choose how a client turns host names into addresses: cache the answers,
send a name to addresses you pick, or resolve names with your own resolver.

> For builders who have read [Connections and client state](connections-and-state.md).

A client resolves a name itself only when it opens the connection to that
name: the origin host on a direct route, every proxy host, and the target of
a `socks5://` route. A `socks5h://` proxy, an HTTP proxy, or a CONNECT-UDP
proxy receives the target by name and resolves it, so nothing on this page
applies to that target
([SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md)).

## Resolve each host once

Reuse the addresses a host resolved to for later connections, as a browser
does, instead of resolving it for every new connection.

```rust
use std::time::Duration;

use phantom::profile::{chromium, ClientProfile, DnsCacheSettings};
use phantom::{BuildError, Client};

fn build() -> Result<Client, BuildError> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_dns_cache(chromium::v154_dns_cache());
    // Keep answers for five minutes instead of the recipe's 60 seconds.
    let longer = DnsCacheSettings {
        ttl: Duration::from_secs(300),
        ..chromium::v154_dns_cache()
    };
    Client::builder(profile).dns_cache(longer).build()
}
```

- Without `with_dns_cache` or `ClientBuilder::dns_cache`, every new
  connection resolves its host. `ClientBuilder::no_dns_cache` turns off the
  profile's cache.
- Concurrent connections to one host share one lookup, and the resolver's
  address order is kept. Bounds and recipe values are in
  [Address cache](../reference/profiles.md#address-cache).
- Clones share the cache, and each session starts with an empty one.
  `Client::clear_dns_cache` forgets every answer.

## Send a host name to addresses you choose

Connect to fixed addresses for one name, such as a staging server or one
edge of a CDN, while TLS and HTTP still carry the name.

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use phantom::profile::{chromium, ClientProfile};
use phantom::{BuildError, Client};

fn pinned() -> Result<Client, BuildError> {
    let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    Client::builder(profile)
        // Tried in this order; the port still comes from each URL.
        .resolve(
            "example.com",
            [
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            ],
        )
        .build()
}
```

- The TLS server name, the certificate check, `Host` or `:authority`,
  cookies, and pool keys all use `example.com`. Only the TCP or QUIC
  connection goes to the addresses.
- An override skips the address resolver and the address cache. Names match
  without regard to ASCII case; `example.com.` with a trailing dot is a
  different name.
- An empty list makes the name fail to resolve. Calling `resolve` again for
  a name replaces its addresses. An IP literal cannot be overridden, and
  `build` fails with `BuildErrorKind::InvalidPolicy` if you try.

## Resolve names with your own resolver

Answer every name the client resolves itself with an async function, such
as a DNS library pointed at nameservers you choose.

```rust
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use phantom::profile::{chromium, ClientProfile};
use phantom::{AddressResolver, BuildError, Client};

fn with_resolver() -> Result<Client, BuildError> {
    let resolver = AddressResolver::from_fn(|host: String| async move {
        // Replace this match with a lookup in the DNS library you use.
        match host.as_str() {
            "example.com" => Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "unknown host")),
        }
    });
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_dns_cache(chromium::v154_dns_cache());
    Client::builder(profile).dns_resolver(resolver).build()
}
```

- The function receives the name in ASCII lowercase, never an IP literal or
  a name with an override. Return addresses in the order to try them; the
  port comes from the URL.
- With an address cache, as here, the function runs once per name per cache
  lifetime, as a task on the Tokio runtime of the request that asked first.
  Without one, it runs inside every new connection attempt.
- A returned error fails the request with the kind a failed system lookup
  gets on that path: `Resolve` for an HTTP/3 origin, a `socks5://` target,
  or a CONNECT-UDP proxy host; `Proxy` for another proxy host; `Connect` for
  a TCP origin. The `io::Error` stays in the error's source chain.

## Limits

- Overrides and the resolver cover address lookups only. The HTTPS DNS
  record lookup of the `https-records` feature still queries the record for
  the original name through its own `HttpsRecordResolver`
  ([HTTP/3 discovery](http3-discovery.md)).
- Addresses are `IpAddr` values, so an IPv6 link-local address cannot carry
  a scope ID. Leave such a name to the operating system resolver.
- Phantom does not bound the work your resolver does. A lookup that never
  answers holds each request that waits for it until its connect timeout,
  if you set one ([Timeouts](../reference/limits.md#timeouts)). With a
  cache, later requests for the name join that same lookup until it ends.
- A resolver that sends its own DNS queries changes the client's DNS
  traffic, which no longer comes from the operating system's resolver as a
  browser's does. The connections keep the profile's fingerprint.

## Next

- [Connections and client state](connections-and-state.md): the other
  state a client keeps.
- [Defaults and limits](../reference/limits.md): address cache bounds and
  lifetimes.
