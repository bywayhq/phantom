# Connections, redirects, and cookies

A `Client` owns every piece of state that outlives one request: connection
pools, redirect policy, cookies, learned client hints, Alt-Svc
advertisements, and TLS session tickets. This guide explains how that state
behaves.

## Sharing a client

`Client` is cheap to clone. Clones share bounded state; independently built
clients do not. There is no process-global cache.

## Connection pools

- H1 connections are reused sequentially without pipelining.
- H2 and H3 multiplex requests within peer and local limits.
- Pool admission and retained connections are bounded per origin and route.
- Dropping one H2 or H3 request cancels its stream, not unrelated work.

A pool key is the origin plus the complete route. The default bounds, and how
the least recently used entry is evicted, are listed in
[Defaults and limits](../reference/limits.md#connection-pools).

The client also retains bounded TLS session tickets for H1/H2 resumption,
keyed by exact origin and route and never used for early data.

## Redirects

Redirects are disabled until a finite policy is configured.
`RedirectPolicy::limited(n)` follows at most `n` redirect responses per
logical request; `RedirectPolicy::none()`, the default, returns them to the
caller.

Following is HTTPS-only:

- The request must use `https://`. While a client has a redirect policy,
  every `http://` request fails with `RequestErrorKind::Redirect` before I/O,
  even if the response would not redirect. Use a separate client without a
  redirect policy for plaintext origins.
- Only 301, 302, 303, 307, and 308 with a `Location` field are followed. A
  redirect without `Location` is returned unchanged.
- The resolved target must also be `https://`. A target with another scheme,
  more than one `Location` field, an invalid location, or exhaustion of the
  limit fails with `RequestErrorKind::Redirect`; the redirect response is not
  returned.

Methods and bodies change as in browsers:

- 301 and 302 rewrite POST to GET, and 303 rewrites everything except GET and
  HEAD. A rewrite drops the body, static trailers, and body-describing fields.
- 307 and 308 preserve the method and replay an owned body, while a one-shot
  streaming body fails with `RequestErrorKind::RequestBody`.
- A cross-origin hop removes `Authorization`, `Cookie`, `Cookie2`, and
  `Proxy-Authorization` fields and trailers and rebuilds client hints for the
  new origin. Cookies from the jar are recomputed for every hop.
- Every hop keeps the request's route and exact protocol or negotiated
  selection rule, and one total timeout and retry budget span all hops.

`ResponseInfo::effective_uri` and `ResponseInfo::redirects_followed` describe
the final hop.

## Cookies

Cookies require the `cookies` Cargo feature and explicit builder activation.

- `ClientBuilder::cookies` enables a bounded in-memory jar.
- `ClientBuilder::cookie_jar` installs a caller-built `CookieJar`, for example
  one made with `CookieJar::with_limits`.
- `Client::cookie_jar` returns the active jar. Its `set_cookie`,
  `request_value`, `clear`, and `len` methods operate on the same state
  requests use.

The jar applies domain, path, expiry, `Secure`, `HttpOnly`, public-suffix,
`__Secure-`/`__Host-` prefix, `SameSite`, `Partitioned`, and deterministic
ordering rules. Its default limits are listed in
[Defaults and limits](../reference/limits.md#cookies).

### Cookie field position

The jar's field is named `Cookie` on HTTP/1.1 and `cookie` on H2 and H3, and
the profile's `CookiePlacement` positions it among the caller's fields. By
default it goes last. `CookiePlacement::before_fields` names the fields it
precedes: the field goes before the first of them present, else last.

| Recipe | Goes before | Evidence |
| --- | --- | --- |
| `chromium::v153_cookie_placement` | `priority` | Chrome 153 H1 capture (last); Chromium source for the H2 and H3 `priority` field |
| `firefox::v156_cookie_placement` | `Upgrade-Insecure-Requests`, `Sec-Fetch-*`, `Priority`, `Pragma`, `Cache-Control`, `te` | Firefox 156 H1 capture (after `Referer`, before `Sec-Fetch-Dest`); Firefox source for the rest |

The captures are the EventSource reconnect requests in
`fixtures/sse/*/windows-11-26200/set-cookie-then-close.txt`. No retained H2 or
H3 capture carries a cookie, so those positions are unverified on the wire.
Chrome's H2 and H3 encoders and Firefox's H2 encoder also split `cookie` into
one field per cookie (quiche `HpackEncoder::CookieToCrumbs` and
`ValueSplittingHeaderList`, Firefox `Http2Compressor`); Phantom sends one
field. A caller-supplied `Cookie` field keeps its
own position and suppresses the jar's field.

Set it with `ClientProfile::with_cookie_placement`.

The placement covers HTTP requests, including event-source requests, but not
WebSocket opening requests. Those place the jar's value where the WebSocket
template has its `client_cookies` placeholder (`WebSocketField::client_cookies`
in a profile, `WebSocketHeader::client_cookies` in a caller template), and send
no jar cookie when the template has no placeholder.

### Request context

The jar treats every request as a user-initiated top-level navigation to the
request URL, as if the URL were typed into a browser's address bar. It does not
read `Sec-Fetch-Site`, `Referer`, or any other caller field. Redirect hops are
treated the same way.

- **SameSite.** A navigation without an initiator is a same-site context.
  Chromium's `ComputeSameSiteContext` gives it `SAME_SITE_STRICT` for every
  hop, because `kCookieSameSiteConsidersRedirectChain` is disabled by default.
  The jar therefore stores and sends matching `SameSite=Strict`,
  `SameSite=Lax`, and `SameSite=None` cookies on every request, whatever the
  method. Cookies without `SameSite` are sent the same way.
- **Partitioned (CHIPS).** A top-level request is its own top-level site, so a
  `Partitioned` cookie is keyed to the schemeful site (scheme and registrable
  domain) of the URL that set it. It is sent only to URLs with the same site.
  Because a cookie's domain always shares the setting host's registrable
  domain, that is every URL the cookie domain-matches. A partitioned and an
  unpartitioned cookie with the same name, domain, and path are kept as two
  cookies, as in Chromium. There is no embedded or cross-site context, so the
  jar never sends a partition other than the request's own site.

A caller emulating a cross-site subresource request, where a browser would
withhold `SameSite=Strict` or `SameSite=Lax` cookies or use another partition,
should supply its own `Cookie` field. A caller-supplied `Cookie` suppresses
the jar's field, and the response still updates the jar.

### Cookies the jar rejects

The jar rejects, as Chromium does:

- `SameSite=None` without `Secure`;
- `Partitioned` without `Secure`;
- any `Secure` cookie set by an `http://` URL;
- a `Domain` that is a public suffix, including a private registry such as
  `github.io` and an unlisted top-level label such as `corp` or `lan`, unless
  it equals the request host (then the cookie becomes host-only); and
- a `Set-Cookie` field longer than the byte limit.

From a response, a rejected `Set-Cookie` is ignored and recorded only as a
debug event. `CookieJar::set_cookie` returns `CookieErrorKind::UnsupportedPolicy`,
`PublicSuffix`, `InvalidPrefix`, or `CookieTooLarge`.

### Eviction

The count limits evict rather than reject. After a cookie is stored, if its
registrable domain holds more than the per-domain limit, the least recently
used cookies of that domain are evicted, non-`Secure` ones first, down to five
sixths of the limit (150 of 180 by default). If the jar then holds more than
the total limit, the least recently used cookies anywhere are evicted,
non-`Secure` ones first, down to ten elevenths of it (3,000 of 3,300). Storing
a cookie or sending it in a request counts as a use; inspecting the jar with
`CookieJar::request_value` does not.

This follows Chromium's `CookieMonster::GarbageCollect` with three
differences:

- The `Priority` attribute is ignored; every cookie has Chromium's default
  medium priority.
- The total purge does not spare cookies used in the last 30 days, so the
  total limit is a hard bound.
- Partitioned cookies count toward the same limits as other cookies. Chromium
  gives each partition its own per-domain limits.

## Client hints

Learned `Accept-CH` state is bounded and scoped to the exact secure origin.
`Client::clear_client_hints` discards learned `Accept-CH` selections. See
[Client hints](profiles.md#client-hints) for the full lifecycle.

## Alt-Svc

Alt-Svc is disabled by default. `ClientBuilder::alt_svc` enables a bounded,
in-memory exact-origin store for negotiated HTTPS requests,
`Client::clear_alt_svc` clears it, and `Client::export_alt_svc` and
`Client::import_alt_svc` move it through caller-owned storage.
`ClientBuilder::alt_svc_policy` opts into racing a learned alternative against
the origin, with broken-alternative backoff. See
[HTTP/3 and Alt-Svc](http3.md#alt-svc).
