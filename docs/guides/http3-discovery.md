# HTTP/3 discovery

Try HTTP/3 and HTTP/2 at the same time, discover HTTP/3 through DNS, and
keep learned server addresses across restarts.

> Read [HTTP/3 and Alt-Svc](http3.md) first.

## Race the alternative against the origin

When a server advertises HTTP/3 in `Alt-Svc`, the HTTP/3 address is called
the alternative, and the server's usual address is the origin. Race the two,
as Chrome does, so an unreachable alternative doesn't fail your request.
The request goes over whichever connection is ready first:

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

- The QUIC connection starts first. The connection to the origin starts
  after the delay you pass, here 300 ms. A zero delay starts both together.
- If the alternative fails but another connection succeeds, Phantom stops
  racing the failed address for a while. With `CHROMIUM_153` that's 300
  seconds, doubling after each failure, up to two days.
- When both fail, you get the origin's error.
- Racing doesn't apply through a proxy.

To send an HTTP/3 request to an alternative you already know, see
[Reach a known alternative service](socks-and-connect-udp.md#reach-a-known-alternative-service).

## Find HTTP/3 through HTTPS DNS records

A server can announce HTTP/3 in an HTTPS DNS record. Phantom looks up the
record in the background and uses it on later requests. Turn on the
`https-records` feature, then call `ClientBuilder::https_record_discovery`
together with `ClientBuilder::alt_svc`:

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

- The DNS lookup doesn't delay the first request. Later requests use the
  result.
- With a Chromium-family recipe, a direct connection waits up to 50 ms for
  the record. If the record holds an Encrypted Client Hello key, the
  handshake uses it, as those browsers do.
- `HttpsRecordResolver::system` asks the host's configured DNS servers.
  `HttpsRecordResolver::with_nameservers` takes servers you choose.

## Keep Alt-Svc state across restarts

Phantom keeps the servers it learned in memory. Export them, store them in
any format, and import them into the next client:

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

A snapshot holds server addresses and expiry times for direct connections.
It doesn't hold TLS tickets, cookies or the list of broken servers.
`import_alt_svc` rejects the whole snapshot if one entry is invalid, and
drops expired entries.

## Limits

- A raced QUIC connection gets at most 4 seconds, less than Chrome allows.
- Phantom sends HTTPS record queries from its own DNS client, while the
  operating system looks up addresses. An observer sees DNS traffic from
  two sources where Chrome shows one.
- If the server rejects the Encrypted Client Hello key from DNS on an
  HTTP/3 connection, the request fails. A racing client sends it over TCP
  instead, as Chrome does.
- Phantom doesn't save the list of broken servers, or clear it when the
  network changes.

## Next

- [Tune throughput and latency](performance.md): what racing and discovery
  let a server see.
- [Validation](../explanation/validation.md#alt-svc-racing-evidence): how
  racing was compared with Chrome.
- [Defaults and limits](../reference/limits.md#protocol-state): cache sizes
  and lifetimes.
