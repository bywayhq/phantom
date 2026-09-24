# Cookie jar rules

The rules the optional cookie jar applies when it stores and sends cookies:
request context, trustworthy origins, rejections, eviction, and snapshots.

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

## Snapshots

`Client::export_cookies` returns a `CookieSnapshot` of the jar's unexpired
cookies, or `None` when the client has no jar. `Client::import_cookies` loads
one into a client. Setup is in
[Save and restore cookies](../guides/connections-and-state.md#save-and-restore-cookies).

### What an entry holds

Each `CookieSnapshotEntry` keeps the cookie's name, value, domain, host-only
flag, path, `Secure`, `HttpOnly`, `SameSite`, partition key (such as
`https://example.com`), the scheme of the URL that set it
(`CookieSourceScheme`), and its expiry rounded down to a whole second.

- Session cookies are exported with no expiry.
- Entries are in creation order, and an import keeps that order, so a
  restored jar builds the same `Cookie` field.
- A snapshot holds no connection, TLS ticket, route, or Alt-Svc state.
- `CookieSnapshotEntry::new` builds a host-only session cookie with no
  attributes; its `with_` methods set the rest.
- With the `serde` feature, `CookieSnapshot` and its entries implement
  `Serialize` and `Deserialize`. `Debug` output omits names, values,
  domains, paths, and partition keys.

### Import checks

Import rebuilds each entry as the `Set-Cookie` field a response from its
scheme and domain would send, and applies the jar's storage rules and byte
limit to it, as listed in [Cookies the jar rejects](#cookies-the-jar-rejects).
An import can therefore store only a cookie a response could have stored.

| Entry | `CookieSnapshotErrorKind` |
| --- | --- |
| (The client has no cookie jar) | `Disabled` |
| Domain not the canonical lowercase host, or a name, value, path, or attribute that does not survive as a `Set-Cookie` field unchanged | `InvalidCookie` |
| `Set-Cookie` field over the jar's byte limit | `CookieTooLarge` |
| Domain cookie on a public suffix | `PublicSuffix` |
| `__Secure-` or `__Host-` requirement not met | `InvalidPrefix` |
| `Secure` from an origin that is not potentially trustworthy, or `SameSite=None` or `Partitioned` without `Secure` | `UnsupportedPolicy` |
| Partition key other than the schemeful site of the scheme and domain, or on a cookie the jar would not partition | `InvalidPartitionKey` |

One refused entry rejects the whole snapshot and leaves the jar unchanged.
`CookieSnapshotError::entry_index` names the entry.

### Merge rules

A valid snapshot merges without removing held cookies.

- Expired entries are skipped, and expiry is never extended.
- A later entry with the same name, domain, path, host-only flag, and
  partitioned flag replaces an earlier one.
- A held cookie with the same key wins, as does a held `Secure` cookie that
  an entry from an untrustworthy origin would overlay.
- Imported cookies rank as older than every held cookie for ordering and
  eviction.
- The count limits admit imported cookies up to each limit instead of
  evicting, so the jar keeps every held cookie and then the newest snapshot
  entries.

## Next

- [Connections, redirects, and cookies](../guides/connections-and-state.md):
  enable the jar and place its field.
- [Defaults and limits](limits.md#cookies): the jar's size and count limits.
- [Coverage](coverage.md#cross-request-state): cookie behavior not modeled.
