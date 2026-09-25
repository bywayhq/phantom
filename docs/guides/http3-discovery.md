# HTTP/3 discovery

Race a learned HTTP/3 (H3) alternative against the origin, find H3 through
an HTTPS DNS record before any [Alt-Svc](../reference/glossary.md#alt-svc)
response, and keep Alt-Svc state across restarts.

> For builders who have read [HTTP/3 and Alt-Svc](http3.md).

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

- The lookup does not hold back the request: the first negotiated request
  to an origin starts it, a sequential client sends that request to the
  origin, and a racing client starts origin setup at once and H3 setup only
  if the records list `h3`. Later requests use the cached result. With the
  Chrome 154, Edge 153, or Brave 154 recipe, whose `ech_from_https_records`
  is set, a direct TLS handshake to the origin waits up to 50 ms after address
  resolution for the lookup and encrypts its ClientHello with the record's
  `ech`, as those browsers do.
- Only negotiated requests on the direct route with no stored Alt-Svc
  alternative look up records for H3. With those recipes, every direct TLS
  connection over TCP also looks them up for its `ech`,
  including those of exact-protocol requests and `wss://` openings. Proxy
  routes and IP-literal origins send no query.
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
- Encrypted Client Hello from a record's `ech` value covers direct
  HTTP/1.1 and HTTP/2 connections, negotiated or exact, and `wss://`
  openings, but not H3
  ([Real ECH evidence](../explanation/validation.md#real-ech-evidence)).
- Not implemented: racing more than one alternative (a stored Alt-Svc
  alternative is used instead of an HTTPS-record one), persisting
  brokenness or clearing it on a network change, an RTT-derived racing
  delay, and proxy-route snapshots.

## Next

- [Tune throughput and latency](performance.md): what racing and discovery
  let a server observe.
- [Alt-Svc evidence](../explanation/validation.md#alt-svc-http3-upgrade-evidence)
  and [racing evidence](../explanation/validation.md#alt-svc-racing-evidence):
  the tests and captures behind this page.
- [HTTP/3 internals](../internals/http3.md): pooling and the QUIC stack.
