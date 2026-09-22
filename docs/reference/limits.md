# Defaults and limits

Phantom bounds every piece of state it keeps. This page lists those bounds
and their defaults. Policies that stay off until you enable them, such as
timeouts, redirects, and retries, come first.

## Off by default

| Policy | Default | Enable with |
| --- | --- | --- |
| Timeouts | None | `ClientBuilder::request_timeouts`, `RequestBuilder::timeouts` |
| Redirects | Not followed | `RedirectPolicy::limited` |
| Connection-setup retries | None | `RetryPolicy::connection_failures` |
| Reused-connection, unprocessed-request, and status retries | None | See [Retries and replays](../guides/retries.md) |
| Cookies | No jar | `cookies` feature, then `ClientBuilder::cookies` or `cookie_jar` |
| Alt-Svc | Disabled | `ClientBuilder::alt_svc(maximum_origins)` |
| Content decoding | Wire body | `ContentDecoding::advertised(max)` |
| Cargo features | None | See [Getting started](../getting-started.md#optional-features) |

## Connection pools

`ClientBuilder` can set each bound to any nonzero value. A pool key is the
origin plus the complete route.

| Bound | Default | Builder method |
| --- | --- | --- |
| Retained H1 pool entries | 32 | `max_retained_http1_connections` |
| Waiting H1 requests per pool key | 100 | `max_pending_http1_requests_per_origin` |
| Retained H2 pool entries | 32 | `max_retained_http2_connections` |
| Active H2 requests per pool key | 100 | `max_concurrent_http2_requests_per_origin` |
| Waiting H2 requests per pool key | 100 | `max_pending_http2_requests_per_origin` |
| Retained H3 pool entries | 32 | `max_retained_http3_connections` |
| Active H3 requests per pool key | 100 | `max_concurrent_http3_requests_per_origin` |
| Waiting H3 requests per pool key | 100 | `max_pending_http3_requests_per_origin` |
| Origins with learned `Accept-CH` state | 64 | `max_client_hint_origins` |
| Origins with Alt-Svc state | disabled | `alt_svc(maximum_origins)` |

- Each retained entry holds one pool key's connection state. When the limit
  is reached, the least recently used entry is evicted.
- An H3 entry keeps connections for up to four transport locations, so exact
  H3 and Alt-Svc H3 do not replace each other.
- The negotiated H1/H2 pool retains at most the lower of the H1 and H2
  retention limits. Before ALPN selects a protocol, its admission uses the
  larger of their active and waiting limits.
- The peer's stream limit also caps active H2 and H3 work.

## Cookies

The optional cookie jar (`CookieLimits`) defaults to:

- 4,096 bytes per `Set-Cookie` field, above which a cookie is rejected;
- 180 cookies per registrable domain; and
- 3,300 cookies in total.

The two count limits are Chromium's `kDomainMaxCookies` and `kMaxCookies`
(`net/cookies/cookie_monster.cc`). Exceeding a count limit evicts cookies
instead of rejecting the new one. The least recently used cookies go first,
non-`Secure` before `Secure`, until the domain is down to five sixths of its
limit (150) or the jar to ten elevenths of its limit (3,000). Chromium purges
to the same 150 and 3,000. See
[Eviction](../guides/connections-and-state.md#eviction) for the differences.

## Protocol state

| Limit | Value |
| --- | --- |
| Undelivered HTTP/2 ALTSVC frames per connection | 16 |
| Empty non-final HTTP/2 DATA frames per connection | 100 |
| Unread small HTTP/2 DATA frame overhead per connection | Half the initial connection window, at least 25,600 bytes |
| Distinct ALPS `ACCEPT_CH` origins per connection | 1,024 |
| Informational (1xx) responses before the final head (H1, H2, and H3) | 8 |
| Decoded H3 response field section (headers or trailers) | 256 KiB, or the profile's lower `SETTINGS_MAX_FIELD_SECTION_SIZE` |
| Decoded HTTP/2 response header list | Lower of the profile's `SETTINGS_MAX_HEADER_LIST_SIZE` and 393,216 bytes (not advertised) |
| Stacked content codings | 3 |
| zstd window | 8 MiB |
| Decoded data frame size | 16 KiB |
| TCP keepalive idle time and interval | Whole seconds, 1 to 32,767 |
| TCP address-racing fallback delay | Nonzero, at most 10 seconds |
| Concurrent TCP attempts per connection with address racing | 2 |

H3 field-section size is measured as RFC 9114 Section 4.2.2 defines it: each
field line counts its name and value lengths plus 32 bytes. The 256 KiB
ceiling applies even when a profile omits `SETTINGS_MAX_FIELD_SECTION_SIZE`,
and Phantom never adds that setting to the SETTINGS frame. A larger response
section fails that request with `Http3ErrorKind::Protocol` and cancels its
stream. The connection stays usable.

The HTTP/2 header-list ceiling counts the decoded size that RFC 9113 Section
6.5.2 defines: each name and value plus 32 bytes per field. The value 393,216
is the default of Firefox's `network.http.max_response_header_size`. Firefox
applies it to encoded header-block bytes and to its own decoded
serialization, so the two ceilings match only approximately.

The cap of 8 informational responses is Phantom's own bound, not a browser
value. It applies to every profile on H1, H2, and H3.

## Server-sent events

| Limit | Default | Configure with |
| --- | --- | --- |
| Line length | 64 KiB | `SseLimits` |
| Event block size | 1 MiB | `SseLimits` |
| Initial reconnect delay | 3 seconds | `initial_retry` |
| Reconnect requests | 3 | `max_reconnects` |
| Minimum retry delay | Unset | `min_retry` |
| Idle timeout | Disabled | `idle_timeout` |

## WebSocket

| Limit | Default | Configure with |
| --- | --- | --- |
| Frame size | 16 MiB | `WebSocketLimits` |
| Reassembled message size | 64 MiB | `WebSocketLimits` |
| Data frames per message | 131,072 | `WebSocketLimits` |

## CONNECT-UDP

| Limit | Value |
| --- | --- |
| Received datagram queue per stream | 256 payloads |
| Queued outbound capsules (H2 and H1 legs) | 256 |
| Outer path MTU (H3 leg) | 1,252 bytes |
| Context ID 0 payload | 65,527 bytes |
| DATAGRAM capsule | 65,535 bytes |

Details are in [HTTP/3 internals](../internals/http3.md#connect-udp-masque).
