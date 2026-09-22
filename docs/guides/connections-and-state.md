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
`__Secure-`/`__Host-` prefix, and deterministic ordering rules. Its default
size limits are listed in [Defaults and limits](../reference/limits.md#cookies).

### Cookies the jar rejects

The jar has no request-site or top-level-site context, so it rejects rather
than stores cookies whose semantics depend on it:

- `SameSite=Lax` and `SameSite=Strict`;
- `Partitioned` (CHIPS) cookies;
- `SameSite=None` without `Secure`; and
- any `Secure` cookie set by an `http://` URL.

From a response, a rejected `Set-Cookie` is ignored and recorded only as a
debug event. `CookieJar::set_cookie` returns `CookieErrorKind::UnsupportedPolicy`
(or `InvalidPrefix` for prefix violations). Such cookies are therefore never
sent back, which differs from a browser.

## Client hints

Learned `Accept-CH` state is bounded and scoped to the exact secure origin.
`Client::clear_client_hints` discards learned `Accept-CH` selections. See
[Client hints](profiles.md#client-hints) for the full lifecycle.

## Alt-Svc

Alt-Svc is disabled by default. `ClientBuilder::alt_svc` enables a bounded,
in-memory exact-origin store for negotiated HTTPS requests,
`Client::clear_alt_svc` clears it, and `Client::export_alt_svc` and
`Client::import_alt_svc` move it through caller-owned storage. See
[HTTP/3 and Alt-Svc](http3.md#alt-svc).
