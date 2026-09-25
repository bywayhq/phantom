# Connections, redirects, and cookies

Share one client's connections and state, follow redirects, keep cookies,
and clear what a client has learned.

> For builders who have read [Using the client](client.md).

A `Client` owns every piece of state that outlives one request: connection
pools, redirect policy, cookies, learned client hints, Alt-Svc
advertisements, and TLS session tickets. None of it is global to the process,
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

- Clones share pools, cookies, learned hints, Alt-Svc state, and TLS
  tickets. Separately built clients share nothing.
- H1 connections carry one request at a time, without pipelining; the
  profile decides how many run in parallel
  ([next task](#send-http11-requests-to-one-origin-in-parallel)). H2 and H3
  multiplex requests within the peer's limits and the client's own.
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

## Follow redirects

Follow a bounded number of redirects and see where the response came from.

```rust
use std::num::NonZeroUsize;

use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, RedirectPolicy, ResponseInfo};

async fn follow() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2());
    let client = Client::builder(profile)
        .redirect_policy(RedirectPolicy::limited(
            NonZeroUsize::new(5).expect("five is nonzero"),
        ))
        .build()?;

    let response = client.get(HttpProtocol::Http2, "https://example.com/old")?.send().await?;
    if let Some(info) = response.extensions().get::<ResponseInfo>() {
        println!("{} after {} redirects", info.effective_uri(), info.redirects_followed());
    }
    Ok(())
}
```

- `RedirectPolicy::none()`, the default, returns redirect responses to you.
- Only 301, 302, 303, 307, and 308 with a `Location` are followed, between
  `http://` and `https://` URLs in either direction. A redirect without
  `Location` is returned unchanged.
- 301 and 302 rewrite POST to GET, and 303 rewrites every method except GET
  and HEAD, dropping the body, static trailers, and body-describing fields.
  307 and 308 keep the method and resend an owned body.
- A cross-origin hop removes `Authorization`, `Cookie`, `Cookie2`, and
  `Proxy-Authorization` fields and trailers, and rebuilds client hints. A
  change between `http://` and `https://` on the same host is cross-origin.
  Every hop keeps the route and protocol rule, one total timeout, and one
  retry budget.

## Keep cookies between requests

Store `Set-Cookie` responses and send matching cookies on later requests,
with the `cookies` Cargo feature.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol};

async fn with_cookies() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_cookie_placement(chromium::v154_cookie_placement());
    let client = Client::builder(profile).cookies().build()?;

    if let Some(jar) = client.cookie_jar() {
        jar.set_cookie("https://example.com/", "session=abc; Secure; HttpOnly")?;
    }
    // Sends the cookie, and stores any `Set-Cookie` from the response.
    let response = client.get(HttpProtocol::Http2, "https://example.com/account")?.send().await?;
    drop(response);
    Ok(())
}
```

- `ClientBuilder::cookies` enables a bounded in-memory jar;
  `ClientBuilder::cookie_jar` installs one you built, for example with
  `CookieJar::with_limits`. `Client::cookie_jar` returns the active jar, and
  its `set_cookie`, `request_value`, `clear`, and `len` act on the state
  requests use.
- The jar applies domain, path, expiry, `Secure`, `HttpOnly`, public-suffix,
  `__Secure-` and `__Host-` prefix, `SameSite`, and `Partitioned` rules, with
  deterministic ordering ([rules](../reference/cookies.md)).
- A `Cookie` field you supply keeps its own position and suppresses the
  jar's field; the response still updates the jar.
- `Client::export_cookies` and `Client::import_cookies` move the jar through
  storage you own ([next task](#save-and-restore-cookies)).

## Save and restore cookies

Copy a client's cookies into another client, or rebuild them from your own
storage, with a [snapshot](../reference/glossary.md#snapshot) (`CookieSnapshot`).

```rust
use phantom::{Client, CookieSnapshot, CookieSnapshotEntry, CookieSnapshotError, CookieSourceScheme};

fn copy_cookies(from: &Client, to: &Client) -> Result<(), CookieSnapshotError> {
    // `None` means `from` was built without a cookie jar.
    if let Some(snapshot) = from.export_cookies() {
        to.import_cookies(&snapshot)?;
    }
    Ok(())
}

fn restore_session(client: &Client, value: &str) -> Result<(), CookieSnapshotError> {
    // A cookie your storage kept, as a response from https://example.com set it.
    let entry =
        CookieSnapshotEntry::new(CookieSourceScheme::Https, "session", value, "example.com", "/")
            .with_secure(true)
            .with_http_only(true);
    client.import_cookies(&CookieSnapshot::new(vec![entry]))
}
```

- An export holds the jar's unexpired cookies in creation order, session
  cookies included. Phantom picks no file format: persist each
  `CookieSnapshotEntry`'s accessor values, or enable the `serde` Cargo
  feature to serialize the snapshot.
- A snapshot holds cookie values, which are often session credentials. Store
  it as you would a password.
- Import checks each entry as the `Set-Cookie` field a response from its
  scheme and domain would send. One refused entry rejects the whole snapshot
  and leaves the jar unchanged; `CookieSnapshotError::entry_index` names it.
- Import merges with what the jar holds
  ([merge rules](../reference/cookies.md#merge-rules)).

## Place the cookie field where a browser does

Put the jar's cookie field at the position a browser uses, with the profile's
`CookiePlacement`.

The field is named `Cookie` on HTTP/1.1 and `cookie` on H2 and H3. By default
it goes last. `CookiePlacement::before_fields` names the fields it precedes:
it goes before the first of them present, or last if none is. It positions
the field among your fields or a
[request template's](profiles.md#apply-a-captured-request-template) fields.

| Recipe | Goes before |
| --- | --- |
| `chromium::v154_cookie_placement` | `priority` |
| `firefox::v156_cookie_placement` | `Upgrade-Insecure-Requests`, `Sec-Fetch-*`, `Priority`, `Pragma`, `Cache-Control`, `te` |

- The H1 positions match Chrome 154 and Firefox 156 EventSource reconnect
  captures. No retained H2 or H3 capture carries a cookie; those positions
  come from browser source ([Coverage](../reference/coverage.md#browser-profiles)).
- Chrome's H2 and H3 encoders and Firefox's H2 encoder split `cookie` into
  one field per cookie (quiche `HpackEncoder::CookieToCrumbs` and
  `ValueSplittingHeaderList`, Firefox `Http2Compressor`). Phantom sends one
  field.
- WebSocket openings ignore the placement. They put the jar's value at the
  template's `client_cookies` placeholder (`WebSocketField::client_cookies`
  in a profile, `WebSocketHeader::client_cookies` in a caller template), and
  send no jar cookie without one.

## Clear what a client has learned

Discard learned client hints, Alt-Svc advertisements, and cookies without
building a new client.

```rust
use phantom::Client;

fn forget(client: &Client) {
    client.clear_client_hints();
    client.clear_alt_svc();
    if let Some(jar) = client.cookie_jar() {
        jar.clear();
    }
}
```

- Learned `Accept-CH` state is bounded and scoped to the exact secure origin
  ([Send client hints](profiles.md#send-client-hints)).
- Alt-Svc is off by default. `ClientBuilder::alt_svc` enables a bounded store
  keyed by exact origin for negotiated HTTPS requests; `export_alt_svc` and
  `import_alt_svc` move it through storage you own, and `alt_svc_policy`
  opts into racing ([HTTP/3 and Alt-Svc](http3.md#upgrade-to-http3-when-the-server-advertises-it)).
- TLS session tickets for H1/H2, and QUIC session tickets for H3, are
  bounded and keyed by exact origin and route. Only QUIC tickets carry early
  data, when the profile or `ClientBuilder::http3_early_data` enables it
  ([HTTP/3 and Alt-Svc](http3.md#turn-off-early-data-on-resumed-connections)).

## Limits

- Each hop is checked against the request's protocol and route before it is
  sent. A hop they cannot carry fails with that combination's error, for
  example `RequestErrorKind::UnsupportedScheme` for an exact H2 request
  redirected to `http://`. Phantom does not switch protocol or route to
  follow it.
- A redirect target that is not `http://` or `https://`, more than one
  `Location`, an invalid location, or running out of redirects fails with
  `RequestErrorKind::Redirect`; the redirect response is not returned. A 307
  or 308 with a one-shot streaming body fails with
  `RequestErrorKind::RequestBody`.
- The jar treats every request and redirect hop as a user-initiated
  top-level navigation and ignores the fields you send. To emulate a
  cross-site request, supply your own `Cookie` field.
- The jar rejects insecure `SameSite=None` and `Partitioned` cookies, and
  `Secure` or prefixed cookies from an origin that is not potentially
  trustworthy. Over its count limits it evicts the least recently used
  cookies. The full rules are in [Cookie jar rules](../reference/cookies.md).

## Next

- [Retries and replays](retries.md): what may repeat on a pooled connection.
- [HTTP/3 and Alt-Svc](http3.md): learn and use HTTP/3 alternatives.
- [Defaults and limits](../reference/limits.md): pool and cookie bounds.
