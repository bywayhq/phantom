# Connections, redirects, and cookies

A `Client` owns every piece of state that outlives one request: connection
pools, redirect policy, cookies, learned client hints, Alt-Svc
advertisements, and TLS session tickets.

None of this state is global to the process. Two separately built clients
never see each other's cookies or connections, so the identity one client
presents to a server cannot leak into another. Every store has a size limit,
so a long-running service keeps bounded memory.

## Sharing a client

`Client` is cheap to clone. Clones share the same bounded state; separately
built clients do not. There is no process-global cache.

## Connection pools

- An H1 connection carries one request at a time, without pipelining. Each
  origin and route keeps up to the profile's H1 connection bound, idle
  connections included; see [HTTP/1.1 connections](profiles.md#http11-connections).
  A request reuses an idle connection before it opens another and waits in
  arrival order once the bound is reached.
  `ClientBuilder::max_concurrent_http1_requests_per_origin` replaces the
  profile's bound.
- H2 and H3 multiplex requests within the peer's limits and the client's own.
- Pool admission and retained connections are bounded per origin and route.
- Dropping one H2 or H3 request cancels its stream, not unrelated work.

A pool key is the origin plus the complete route. The default bounds, and how
the least recently used entry is evicted, are listed in
[Defaults and limits](../reference/limits.md#connection-pools).

The client also keeps a bounded set of TLS session tickets to resume H1/H2
connections. Tickets are keyed by exact origin and route and are never used
for early data.

## Redirects

Redirects are off until you set a finite policy with
`ClientBuilder::redirect_policy`. `RedirectPolicy::limited(n)` follows at most
`n` redirect responses per logical request. `RedirectPolicy::none()`, the
default, returns redirect responses to you.

Only HTTPS redirects are followed:

- The request must use `https://`. While a client has a redirect policy,
  every `http://` request fails with `RequestErrorKind::Redirect` before I/O,
  even if the response would not redirect. Use a separate client without a
  redirect policy for plaintext origins.
- Only 301, 302, 303, 307, and 308 with a `Location` field are followed. A
  redirect without `Location` is returned unchanged.
- The resolved target must also be `https://`. A target with another scheme,
  more than one `Location` field, an invalid location, or running out of
  redirects fails with `RequestErrorKind::Redirect`; the redirect response is
  not returned.

Methods and bodies change as they do in browsers:

- 301 and 302 rewrite POST to GET, and 303 rewrites every method except GET
  and HEAD. A rewrite drops the body, static trailers, and body-describing
  fields.
- 307 and 308 keep the method and replay an owned body. A one-shot streaming
  body fails with `RequestErrorKind::RequestBody`.
- A cross-origin hop removes `Authorization`, `Cookie`, `Cookie2`, and
  `Proxy-Authorization` fields and trailers, and rebuilds client hints for
  the new origin. Cookies from the jar are recomputed for every hop.
- Every hop keeps the request's route and exact protocol or negotiated
  selection rule. One total timeout and one retry budget cover all hops.

On the final response, `ResponseInfo::effective_uri` returns the URL that
produced it, and `ResponseInfo::redirects_followed` returns the number of
redirects followed.

## Cookies

Cookies require the `cookies` Cargo feature, and you turn the jar on in the
builder:

- `ClientBuilder::cookies` enables a bounded in-memory jar.
- `ClientBuilder::cookie_jar` installs a `CookieJar` you built, for example
  with `CookieJar::with_limits`.
- `Client::cookie_jar` returns the active jar. Its `set_cookie`,
  `request_value`, `clear`, and `len` methods act on the same state that
  requests use.
- `Client::export_cookies` and `Client::import_cookies` move the jar through
  storage you own; see [Saving and restoring cookies](#saving-and-restoring-cookies).

The jar applies domain, path, expiry, `Secure`, `HttpOnly`, public-suffix,
`__Secure-` and `__Host-` prefix, `SameSite`, `Partitioned`, and
deterministic ordering rules. Its default limits are listed in
[Defaults and limits](../reference/limits.md#cookies).

### Cookie field position

Browsers put the cookie field at a fixed position among the request fields,
and that position is part of what a server can observe. The jar's field is
named `Cookie` on HTTP/1.1 and `cookie` on H2 and H3. The profile's
`CookiePlacement`, set with `ClientProfile::with_cookie_placement`, positions
it among your fields or among a
[request template's](profiles.md#request-templates) expanded fields. By
default it goes last. `CookiePlacement::before_fields` names the fields it
precedes: the cookie field goes before the first of them that is present, or
last if none is.

| Recipe | Goes before | Evidence |
| --- | --- | --- |
| `chromium::v154_cookie_placement` | `priority` | Chrome 154 H1 capture (last); Chromium source for the H2 and H3 `priority` field |
| `firefox::v156_cookie_placement` | `Upgrade-Insecure-Requests`, `Sec-Fetch-*`, `Priority`, `Pragma`, `Cache-Control`, `te` | Firefox 156 H1 capture (after `Referer`, before `Sec-Fetch-Dest`); Firefox source for the rest |

The captures are the EventSource reconnect requests in
`fixtures/sse/*/windows-11-26200/set-cookie-then-close.txt`. No retained H2
or H3 capture carries a cookie, so those positions are unverified on the
wire. Chrome's H2 and H3 encoders and Firefox's H2 encoder also split
`cookie` into one field per cookie (quiche `HpackEncoder::CookieToCrumbs` and
`ValueSplittingHeaderList`, Firefox `Http2Compressor`); Phantom sends one
field.

A `Cookie` field you supply keeps its own position and suppresses the jar's
field.

The placement covers HTTP requests, including event-source requests, but not
WebSocket opening requests. Those place the jar's value where the WebSocket
template has its `client_cookies` placeholder (`WebSocketField::client_cookies`
in a profile, `WebSocketHeader::client_cookies` in a caller template), and
send no jar cookie when the template has no placeholder.

### Request context

The jar treats every request as a user-initiated top-level navigation to the
request URL, as if the URL were typed into a browser's address bar. It does
not read `Sec-Fetch-Site`, `Referer`, or any other field you send. Redirect
hops are treated the same way.

`SameSite`: a navigation without an initiator is a same-site context.
Chromium's `ComputeSameSiteContext` gives it `SAME_SITE_STRICT` for every hop,
because `kCookieSameSiteConsidersRedirectChain` is disabled by default. The
jar therefore stores and sends matching `SameSite=Strict`, `SameSite=Lax`, and
`SameSite=None` cookies on every request, whatever the method. Cookies
without `SameSite` are sent the same way.

`Partitioned` (CHIPS, Cookies Having Independent Partitioned State): a
top-level request is its own top-level site, so a `Partitioned` cookie is
keyed to the schemeful site (scheme and registrable domain) of the URL that
set it. It is sent only to URLs with the same site. A cookie's domain always
shares the setting host's registrable domain, so that is every URL the
cookie domain-matches. A partitioned and an unpartitioned cookie with the
same name, domain, and path are kept as two cookies, as in Chromium. The jar
has no embedded or cross-site context, so it never sends a partition other
than the request's own site.

To emulate a cross-site subresource request, where a browser would withhold
`SameSite=Strict` or `SameSite=Lax` cookies or use another partition, supply
your own `Cookie` field. It suppresses the jar's field, and the response still
updates the jar.

### Trustworthy origins

`Secure` cookies are not tied to `https://`. A URL may set and receive them
when its origin is *potentially trustworthy*, which for the HTTP and HTTPS URLs
the jar accepts means:

- any `https://` URL; or
- an `http://` URL whose host is a loopback IP literal (anything in
  `127.0.0.0/8`, or exactly `::1`), or the name `localhost` or a `.localhost`
  subdomain such as `app.localhost`, ignoring case and one trailing dot.

Nothing else qualifies. `http://127.0.0.1:8080` and `http://app.localhost` are
trustworthy; `http://[::ffff:127.0.0.1]`, `http://localhost.test`, and
`http://example.test` are not.

This is Chromium's rule, `cookie_util::ProvisionalAccessScheme` over
`net::IsLocalhost`, which it applies to setting a cookie and to sending one
alike, so a local development server over plain HTTP keeps its `Secure`,
`__Secure-`, and `__Host-` cookies. The same test decides whether a cookie may
overwrite an existing `Secure` cookie of the same name.

The `Secure` attribute itself is still required where a rule asks for it: a
trustworthy origin does not let a `SameSite=None` or `Partitioned` cookie omit
`Secure`.

### Cookies the jar rejects

The jar rejects, as Chromium does:

- `SameSite=None` without `Secure`;
- `Partitioned` without `Secure`;
- any `Secure` or `__Secure-`/`__Host-` cookie set by a URL that is not a
  [potentially trustworthy origin](#trustworthy-origins);
- a `Domain` that is a public suffix, including a private registry such as
  `github.io` and an unlisted top-level label such as `corp` or `lan`, unless
  it equals the request host (then the cookie becomes host-only); and
- a `Set-Cookie` field longer than the byte limit.

A rejected `Set-Cookie` from a response is ignored and recorded only as a
debug event. `CookieJar::set_cookie` returns
`CookieErrorKind::UnsupportedPolicy`, `PublicSuffix`, `InvalidPrefix`, or
`CookieTooLarge`.

### Eviction

The count limits evict cookies rather than reject them. After a cookie is
stored:

1. If its registrable domain holds more than the per-domain limit, the least
   recently used cookies of that domain are evicted, non-`Secure` ones first,
   down to five sixths of the limit (150 of 180 by default).
2. If the jar then holds more than the total limit, the least recently used
   cookies anywhere are evicted, non-`Secure` ones first, down to ten
   elevenths of it (3,000 of 3,300).

Storing a cookie or sending it in a request counts as a use. Inspecting the
jar with `CookieJar::request_value` does not.

This follows Chromium's `CookieMonster::GarbageCollect` with three
differences:

- The `Priority` attribute is ignored; every cookie has Chromium's default
  medium priority.
- The total purge does not spare cookies used in the last 30 days, so the
  total limit is a hard bound.
- Partitioned cookies count toward the same limits as other cookies. Chromium
  gives each partition its own per-domain limits.

### Saving and restoring cookies

`Client::export_cookies` returns a `CookieSnapshot` of the jar's unexpired
cookies, or `None` when the client has no jar. `Client::import_cookies` loads
one into another client. Phantom picks no file format: persist the accessor
values of each `CookieSnapshotEntry` and rebuild entries with
`CookieSnapshotEntry::new` and its `with_` methods, or enable the `serde`
Cargo feature. A snapshot holds cookie values, which are often session
credentials.

Each entry keeps the cookie's name, value, domain, host-only flag, path,
`Secure`, `HttpOnly`, `SameSite`, partition key (such as
`https://example.com`), the scheme of the URL that set it, and its expiry
rounded down to a whole second. Session cookies are exported with no expiry.
Entries are in creation order, and an import keeps that order, so a restored
jar builds the same `Cookie` field.

Import rebuilds each entry as the `Set-Cookie` field a response from its
scheme and domain would send, and applies the jar's storage rules and byte
limit to it, as listed in [Cookies the jar rejects](#cookies-the-jar-rejects).
The domain must be the canonical lowercase host, the name, value, and path
must survive as a `Set-Cookie` field unchanged, and a partition key must be
the schemeful site of the scheme and domain. One refused entry rejects the
whole snapshot and leaves the jar unchanged;
`CookieSnapshotError::entry_index` names it.

A valid snapshot merges without removing held cookies. Expired entries are
skipped and expiry is never extended. A later entry with the same name,
domain, path, host-only flag, and partitioned flag replaces an earlier one. A
held cookie with the same key wins, as does a held `Secure` cookie that an
entry from an untrustworthy origin would overlay. Imported cookies rank as
older than every held cookie for ordering and eviction. The count limits
admit imported cookies up to each limit instead of evicting.

## Client hints

Learned `Accept-CH` state is bounded and scoped to the exact secure origin.
`Client::clear_client_hints` discards learned `Accept-CH` selections. See
[Client hints](profiles.md#client-hints) for the full lifecycle.

## Alt-Svc

Alt-Svc lets a server advertise another endpoint, such as HTTP/3, for later
requests. It is off by default.

- `ClientBuilder::alt_svc` enables a bounded, in-memory store, keyed by exact
  origin, for negotiated HTTPS requests.
- `Client::clear_alt_svc` clears it.
- `Client::export_alt_svc` and `Client::import_alt_svc` move it through
  storage you own.
- `ClientBuilder::alt_svc_policy` opts into racing a learned alternative
  against the origin, with backoff for broken alternatives.

See [HTTP/3 and Alt-Svc](http3.md#alt-svc).
