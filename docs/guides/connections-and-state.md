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
- H1 connections carry one request at a time, without pipelining. H2 and H3
  multiplex requests within the peer's limits and the client's own.
- A pool key is the origin plus the complete route. Admission and retained
  connections are bounded per key
  ([Defaults and limits](../reference/limits.md#connection-pools)).
- Dropping one H2 or H3 request cancels its stream, not unrelated work.

## Follow redirects

Follow a bounded number of HTTPS redirects and see where the response came
from.

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
- Only 301, 302, 303, 307, and 308 with a `Location` are followed, and only
  from `https://` to `https://`. A redirect without `Location` is returned
  unchanged.
- 301 and 302 rewrite POST to GET, and 303 rewrites every method except GET
  and HEAD, dropping the body, static trailers, and body-describing fields.
  307 and 308 keep the method and resend an owned body.
- A cross-origin hop removes `Authorization`, `Cookie`, `Cookie2`, and
  `Proxy-Authorization` fields and trailers, and rebuilds client hints.
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
  deterministic ordering ([limits](../reference/limits.md#cookies)).
- A `Cookie` field you supply keeps its own position and suppresses the
  jar's field; the response still updates the jar.

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
- TLS session tickets for H1/H2 are bounded, keyed by exact origin and
  route, and never used for early data.

## Limits

- A client with a redirect policy rejects every `http://` request with
  `RequestErrorKind::Redirect` before I/O. Use a separate client without a
  redirect policy for plaintext origins.
- A redirect target that is not `https://`, more than one `Location`, an
  invalid location, or running out of redirects fails with
  `RequestErrorKind::Redirect`; the redirect response is not returned. A 307
  or 308 with a one-shot streaming body fails with
  `RequestErrorKind::RequestBody`.
- The jar treats every request and redirect hop as a user-initiated
  top-level navigation. It does not read `Sec-Fetch-Site`, `Referer`, or any
  other field you send. To emulate a cross-site request, supply your own
  `Cookie` field.

### Cookie request context

- `SameSite`: a navigation without an initiator is same-site. Chromium's
  `ComputeSameSiteContext` gives it `SAME_SITE_STRICT` on every hop, because
  `kCookieSameSiteConsidersRedirectChain` is disabled by default. The jar
  stores and sends matching `Strict`, `Lax`, `None`, and unmarked cookies on
  every request, whatever the method.
- `Partitioned` (CHIPS): a `Partitioned` cookie is keyed to the schemeful
  site (scheme and registrable domain) of the URL that set it, and sent only
  to URLs with that site. A partitioned and an unpartitioned cookie with the
  same name, domain, and path are two cookies, as in Chromium. The jar never
  sends a partition other than the request's own site.

### Trustworthy origins

A URL may set and receive `Secure`, `__Secure-`, and `__Host-` cookies when
its origin is potentially trustworthy: any `https://` URL, or an `http://`
URL whose host is a loopback IP literal (`127.0.0.0/8` or exactly `::1`),
`localhost`, or a `.localhost` subdomain, ignoring case and one trailing dot.
`http://127.0.0.1:8080` and `http://app.localhost` qualify;
`http://[::ffff:127.0.0.1]`, `http://localhost.test`, and
`http://example.test` do not. This is Chromium's
`cookie_util::ProvisionalAccessScheme` over `net::IsLocalhost`, applied to
setting, sending, and overwriting a `Secure` cookie. A trustworthy origin
does not let a `SameSite=None` or `Partitioned` cookie omit `Secure`.

### Cookies the jar rejects

- `SameSite=None` or `Partitioned` without `Secure`;
- a `Secure`, `__Secure-`, or `__Host-` cookie from a URL that is not a
  [potentially trustworthy origin](#trustworthy-origins);
- a `Domain` that is a public suffix, including private registries such as
  `github.io` and unlisted labels such as `corp` or `lan`, unless it equals
  the request host (then the cookie becomes host-only); and
- a `Set-Cookie` longer than the byte limit.

A rejected `Set-Cookie` is ignored and recorded as a debug event.
`CookieJar::set_cookie` returns `CookieErrorKind::UnsupportedPolicy`,
`PublicSuffix`, `InvalidPrefix`, or `CookieTooLarge`.

### Eviction

Count limits evict rather than reject. After a cookie is stored, a
registrable domain over its limit loses its least recently used cookies,
non-`Secure` first, down to five sixths of the limit (150 of 180); then a jar
over its total limit does the same down to ten elevenths (3,000 of 3,300).
Storing or sending a cookie counts as a use; `CookieJar::request_value` does
not. This follows Chromium's `CookieMonster::GarbageCollect`, except that the
`Priority` attribute is ignored, the total purge does not spare cookies used
in the last 30 days, and partitioned cookies share the ordinary limits
instead of per-partition ones.

## Next

- [Retries and replays](retries.md): what may repeat on a pooled connection.
- [HTTP/3 and Alt-Svc](http3.md): learn and use HTTP/3 alternatives.
- [Defaults and limits](../reference/limits.md): pool and cookie bounds.
