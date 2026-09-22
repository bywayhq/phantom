# Defaults and limits

Phantom bounds every piece of state it keeps. This page lists the defaults in
one place. Policies that are off by default, such as timeouts, redirects, and
retries, are listed first.

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

`ClientBuilder` can replace each bound with any nonzero value.

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

- A pool key is the origin plus the complete route. Each retained entry holds
  that key's connection state, and the least recently used entry is evicted
  when the limit is reached.
- An H3 entry keeps connections for up to four transport locations so exact
  and Alt-Svc H3 do not replace each other.
- The negotiated H1/H2 pool retains at most the lower of the H1 and H2
  retention limits. Its pre-selection admission uses the larger of their
  active and waiting limits.
- H2 and H3 active work is also limited by the peer's stream limit.

## Cookies

The optional cookie jar (`CookieLimits`) defaults to:

- 4,096 bytes per cookie;
- 180 cookies per domain; and
- 3,000 cookies in total.

## Protocol state

| Limit | Value |
| --- | --- |
| Undelivered HTTP/2 ALTSVC frames per connection | 16 |
| Distinct ALPS `ACCEPT_CH` origins per connection | 1,024 |
| Informational (1xx) responses before the final head (H1 and H3) | 8 |
| Stacked content codings | 3 |
| zstd window | 8 MiB |
| Decoded data frame size | 16 KiB |

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
