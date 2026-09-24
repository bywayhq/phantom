# Cookie jar rules

The rules the optional cookie jar applies when it stores and sends cookies:
request context, trustworthy origins, rejections, and eviction.

> For builders looking up a cookie rule. Setup is in
> [Keep cookies between requests](../guides/connections-and-state.md#keep-cookies-between-requests).

The count and size limits are in
[Defaults and limits](limits.md#cookies). Chromium behavior the jar does not
model is listed in [Coverage](coverage.md#cross-request-state).

## Request context

The jar treats every request and redirect hop as a user-initiated top-level
navigation. It does not read `Sec-Fetch-Site`, `Referer`, or any other field
you send. To emulate a cross-site request, supply your own `Cookie` field.

| Attribute | Rule |
| --- | --- |
| `SameSite` | A navigation without an initiator is same-site. Chromium's `ComputeSameSiteContext` gives it `SAME_SITE_STRICT` on every hop, because `kCookieSameSiteConsidersRedirectChain` is disabled by default. The jar stores and sends matching `Strict`, `Lax`, `None`, and unmarked cookies on every request, whatever the method. |
| `Partitioned` (CHIPS) | A `Partitioned` cookie is keyed to the schemeful site (scheme and registrable domain) of the URL that set it, and sent only to URLs with that site. A partitioned and an unpartitioned cookie with the same name, domain, and path are two cookies, as in Chromium. The jar never sends a partition other than the request's own site. |

## Trustworthy origins

A URL may set and receive `Secure`, `__Secure-`, and `__Host-` cookies when
its origin is potentially trustworthy: any `https://` URL, or an `http://`
URL whose host is a loopback IP literal (`127.0.0.0/8` or exactly `::1`),
`localhost`, or a `.localhost` subdomain, ignoring case and one trailing dot.

| URL | Trustworthy |
| --- | --- |
| `http://127.0.0.1:8080`, `http://app.localhost` | Yes |
| `http://[::ffff:127.0.0.1]`, `http://localhost.test`, `http://example.test` | No |

This is Chromium's `cookie_util::ProvisionalAccessScheme` over
`net::IsLocalhost`, applied to setting, sending, and overwriting a `Secure`
cookie. A trustworthy origin does not let a `SameSite=None` or `Partitioned`
cookie omit `Secure`.

## Cookies the jar rejects

| Cookie | `CookieJar::set_cookie` error |
| --- | --- |
| `SameSite=None` or `Partitioned` without `Secure` | `CookieErrorKind::UnsupportedPolicy` |
| A `Secure` cookie from a URL that is not a [trustworthy origin](#trustworthy-origins) | `CookieErrorKind::UnsupportedPolicy` |
| A `__Secure-` or `__Host-` cookie without `Secure` or from a URL that is not trustworthy, or a `__Host-` cookie with a `Domain` or a `Path` other than `/` | `CookieErrorKind::InvalidPrefix` |
| A `Domain` that is a public suffix, including private registries such as `github.io` and unlisted labels such as `corp` or `lan`, unless it equals the request host (then the cookie becomes host-only) | `CookieErrorKind::PublicSuffix` |
| A `Set-Cookie` longer than the byte limit | `CookieErrorKind::CookieTooLarge` |

A rejected `Set-Cookie` in a response is ignored and recorded as a debug
event.

## Eviction

Count limits evict rather than reject. After a cookie is stored:

1. A registrable domain over its limit loses its least recently used cookies,
   non-`Secure` first, down to five sixths of the limit (150 of 180).
2. A jar over its total limit does the same, down to ten elevenths of the
   limit (3,000 of 3,300).

Storing or sending a cookie counts as a use; `CookieJar::request_value` does
not.

This follows Chromium's `CookieMonster::GarbageCollect`, which purges to the
same 150 and 3,000, with three differences:

- the `Priority` attribute is ignored;
- the total purge does not spare cookies used in the last 30 days; and
- partitioned cookies share the ordinary limits instead of per-partition ones.

## Next

- [Connections, redirects, and cookies](../guides/connections-and-state.md):
  enable the jar and place its field.
- [Defaults and limits](limits.md#cookies): the jar's size and count limits.
- [Coverage](coverage.md#cross-request-state): cookie behavior not modeled.
