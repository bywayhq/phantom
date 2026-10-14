# Resolve host names

Choose how a client looks up the addresses of the servers it connects to.
You can cache lookups, point a name at addresses you pick, plug in your own
resolver, or have Phantom send DNS queries itself, as Chrome does.

> Read [Connections and client state](connections-and-state.md) first.

Phantom looks up a name only when it connects to that name itself. Through a
`socks5h://`, HTTP or CONNECT-UDP proxy, the proxy looks up the server's
name, so this page applies only to the proxy's own name
([SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md)).

## Resolve each host once

Reuse a host's addresses for later connections, as a browser does, instead
of looking the host up for every new connection.

```rust
use std::time::Duration;

use phantom::profile::{ClientProfile, DnsCacheSettings, browser::chrome};
use phantom::{BuildError, Client};

fn build() -> Result<Client, BuildError> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_dns_cache(chrome::v154_dns_cache());
    // Keep answers for five minutes instead of the recipe's 60 seconds.
    let longer = DnsCacheSettings {
        ttl: Duration::from_secs(300),
        ..chrome::v154_dns_cache()
    };
    Client::builder(profile).dns_cache(longer).build()
}
```

Without a cache, every new connection looks up its host. Clones of a client
share the cache, and `Client::clear_dns_cache` empties it. The recipe values
are in [Address cache](../reference/profiles.md#address-cache).

## Send a host name to addresses you choose

Connect to fixed addresses for one name, such as a staging server or one
CDN edge. TLS and HTTP still use the name.

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use phantom::profile::{ClientProfile, browser::chrome};
use phantom::{BuildError, Client};

fn pinned() -> Result<Client, BuildError> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http2(chrome::v154_http2());
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

The certificate check, the `Host` header and cookies all use
`example.com`. Only the connection goes to the addresses. `example.com.`, with a
trailing dot, counts as a different name.

## Resolve names with your own resolver

Answer every lookup with an async function, such as a DNS library pointed
at servers you choose.

```rust
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use phantom::profile::{ClientProfile, browser::chrome};
use phantom::{AddressResolver, BuildError, Client};

fn with_resolver() -> Result<Client, BuildError> {
    let resolver = AddressResolver::from_fn(|host: String| async move {
        // Replace this match with a lookup in the DNS library you use.
        match host.as_str() {
            "example.com" => Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "unknown host")),
        }
    });
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_dns_cache(chrome::v154_dns_cache());
    Client::builder(profile).dns_resolver(resolver).build()
}
```

The function gets the host name in lowercase ASCII. Return addresses in the
order to try them. With an address cache, as here, the function runs once
per name until the answer expires.

If your resolver reports DNS lifetimes, use `AddressResolver::from_answer_fn`
and return an `AddressAnswer`. Its cache never extends that lifetime. Return
`AddressAnswer::negative` for a validated, complete negative lookup. Errors
from the callback fail the request and are never cached.

## Resolve names with Phantom's own DNS queries

Have Phantom send DNS queries itself, as Chromium's built-in DNS client does,
and cache each answer for as long as the DNS record allows.

```rust
use std::error::Error;

use phantom::profile::{ClientProfile, browser::chrome};
use phantom::{AddressResolver, Client};

fn own_queries() -> Result<Client, Box<dyn Error>> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_udp(chrome::v154_udp())
        .with_dns_cache(chrome::v154_dns_cache());
    let resolver = AddressResolver::system_nameservers()?;
    Ok(Client::builder(profile).dns_resolver(resolver).build()?)
}
```

- This needs the `https-records` feature.
- `system_nameservers` reads the host's DNS servers and hosts file once,
  when you call it. `AddressResolver::with_nameservers` takes servers you
  choose.
- Phantom answers `localhost` and names in the hosts file without a
  query. Names without a dot go to the operating system, as do lookups
  that fail.

## Resolve names over HTTPS

Use an explicit DNS-over-HTTPS endpoint with the `https-records` feature.
Supply its addresses so the resolver can connect without another DNS lookup.

```rust
use std::{error::Error, net::Ipv4Addr, num::NonZeroUsize, time::Duration};
use phantom::{Client, dns::{DnsOverHttps, DohConfiguration,
    DohMethod, DohAddressFamilies}, profile::browser::chrome};

fn over_https() -> Result<Client, Box<dyn Error>> {
    let profile = chrome::v154_windows();
    let config = DohConfiguration::new(
        "https://dns.example/dns-query",
        [Ipv4Addr::new(192, 0, 2, 53).into()],
        DohMethod::Post,
        DohAddressFamilies::DualIpv6First,
        Duration::from_secs(3),
        NonZeroUsize::MIN,
    );
    let doh = DnsOverHttps::builder(profile.clone(), config)?.build()?;
    Ok(Client::builder(profile)
        .dns_resolver(doh.address_resolver())
        .https_record_discovery(doh.https_record_resolver())
        .build()?)
}
```

The endpoint uses a separate direct HTTP/2 client with certificate checks.
It keeps the URL's TLS identity and shares no application cookies or headers.
It refuses redirects and protocol fallback. GET is also available through
`DohMethod::Get`.

Answers keep their DNS lifetime after HTTP age and lookup time are deducted.
With an address cache, expired answers and transport errors are not stored.
The configured deadline and lookup limit bound work shared by resolver clones.
The example also enables HTTPS record discovery through the same endpoint.
Both resolvers preserve expiry across CNAME replies and cache publication.

## Limits

- Address overrides do not replace the HTTPS record resolver. Enable
  [HTTP/3 discovery](http3-discovery.md) with a resolver you choose.
- An IPv6 link-local address can't carry a scope ID. Leave such names to
  the operating system.
- On Windows, `system_nameservers` asks the DNS servers of every active
  network adapter. Chrome asks only the first one's.

## Next

- [Connections and client state](connections-and-state.md): the other
  state a client keeps.
- [Defaults and limits](../reference/limits.md): address cache sizes and
  lifetimes.
