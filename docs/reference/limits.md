# Defaults and limits

Look up every bound on the state Phantom keeps, with its default, and the
policies that stay off until you enable them.

> For builders looking up a default. [Design](../explanation/design.md#state-belongs-to-one-client-and-has-a-bound)
> explains why every piece of state has a bound.

## Off by default

| Policy | Default | Enable with |
| --- | --- | --- |
| Timeouts | None | `ClientBuilder::request_timeouts`, `RequestBuilder::timeouts` |
| Redirects | Not followed | `RedirectPolicy::limited` |
| Connection-setup retries | None | `RetryPolicy::connection_failures` |
| Reused-connection, unprocessed-request, and status retries | None | See [Retries and replays](../guides/retries.md) |
| Cookies | No jar | `cookies` feature, then `ClientBuilder::cookies` or `cookie_jar` |
| Alt-Svc | Disabled | `ClientBuilder::alt_svc(maximum_origins)` |
| HTTP/3 early (0-RTT) data | As the profile's QUIC `early_data`; the Chrome 154 and Edge 153 recipes offer it | `ClientBuilder::http3_early_data(bool)` overrides the profile |
| HTTPS DNS record discovery | Off | `https-records` feature, then `ClientBuilder::https_record_discovery` |
| Address cache | As the profile's `DnsCacheSettings`; off without one | `ClientProfile::with_dns_cache` or `ClientBuilder::dns_cache`; `ClientBuilder::no_dns_cache` turns it off |
| Content decoding | Wire body | `ContentDecoding::advertised(max)` |
| More than one H2 connection per pool key | One connection | `ClientBuilder::max_http2_connections_per_origin` |
| Limit on waiting for another negotiated handshake | Waits until it ends | `ClientBuilder::negotiated_setup_wait_limit` |
| Cargo features | None | See [Getting started](../getting-started.md#optional-features) |

## Timeouts

`RequestTimeouts` sets each phase; none is set by default.

| Timeout phase | Method | Limits |
| --- | --- | --- |
| Pool admission | `pool_admission` | Waiting for a free connection slot |
| Connect | `connect` | DNS, proxy, transport, TLS, and protocol setup, including a negotiated request's wait for another request's TLS handshake to the same pool key |
| Response head | `response_head` | Sending the request and body, then waiting for the status and fields |
| Read idle | `read_idle` | Time without data while reading the response body |
| Total | `total` | The whole operation |

Each phase limit restarts for every redirect, retry, and replay. The total
limit is one deadline over all attempts, delays, and the final response body.

## Connection pools

`ClientBuilder` can set each bound to any nonzero value. A
[pool key](glossary.md#pool-key) is the origin plus the complete route.

| Bound | Default | Builder method |
| --- | --- | --- |
| Retained H1 pool entries | 32 | `max_retained_http1_connections` |
| Active H1 requests, and so H1 connections, per pool key, exact or negotiated | The profile's `Http1Settings`, otherwise 1 | `max_concurrent_http1_requests_per_origin` |
| Waiting H1 requests per pool key | 100 | `max_pending_http1_requests_per_origin` |
| Retained H2 pool entries | 32 | `max_retained_http2_connections` |
| Active H2 requests per pool key | 100 | `max_concurrent_http2_requests_per_origin` |
| Waiting H2 requests per pool key | 100 | `max_pending_http2_requests_per_origin` |
| H2 connections per pool key, exact or negotiated | 1 | `max_http2_connections_per_origin` |
| Retained H3 pool entries | 32 | `max_retained_http3_connections` |
| Active H3 requests per pool key | 100 | `max_concurrent_http3_requests_per_origin` |
| Waiting H3 requests per pool key | 100 | `max_pending_http3_requests_per_origin` |
| Origins with learned `Accept-CH` state | 64 | `max_client_hint_origins` |
| Origins with Alt-Svc state | disabled | `alt_svc(maximum_origins)` |

- Each retained entry holds one pool key's connection state. When the limit
  is reached, the least recently used entry is evicted.
- An H1 connection carries one request at a time, so an H1 entry keeps up to
  its active bound of connections, idle ones included. A request reuses the
  most recently used idle connection before it opens another. The
  `chromium::v154_http1` and `firefox::v156_http1` recipes set 6, the
  browsers' per-host limit; a profile without `Http1Settings` keeps one
  connection.
- The negotiated H1/H2 pool applies the same bound to each pool key.
  Connections that selected H1 and connections still in their TLS handshake
  count toward it. A pool key whose connection selected H2 keeps that one
  connection for all its requests, under the H2 active and waiting bounds.
  Until a connection to the key has selected H1, a request that finds every
  connection slot in a handshake waits for a handshake to finish instead of
  counting against the H1 waiting bound. Once one has, the H1 waiting bound
  applies. The handshake rules are in
  [HTTP/1.1 connections](profiles.md#http11-connections).
- The bound and the H2 memory below are per pool key, so each route to one
  origin has its own. Twenty routes to one origin can keep 20 times the
  bound of H1 connections, idle ones included, and a route's first burst to
  an H2 origin can open up to the bound of TLS handshakes, all but one of
  which close.
- An H3 entry keeps connections for up to four transport locations, so exact
  H3 and Alt-Svc H3 do not replace each other.
- The negotiated H1/H2 pool retains at most the lower of the H1 and H2
  retention limits. Before ALPN selects a protocol, its admission uses the
  larger of their active and waiting limits.
- The peer's stream limit also caps active H2 and H3 work.
- With more than one H2 connection allowed, a request opens another only
  when every connection to the key carries as many streams as the lower of
  the active bound and the peer's `SETTINGS_MAX_CONCURRENT_STREAMS`. The
  active and waiting bounds still count all of the key's connections. H3
  keeps one connection per transport location.
- [Tune throughput and latency](../guides/performance.md) says what a server
  can observe when you raise these bounds.

## Delays and timers

Every timer Phantom runs, with its default and where it comes from. A server
can observe a change to any timer that decides when a connection opens,
closes, or sends; the last column says which.

| Delay | Default | Source | Set with | A server sees a change |
| --- | --- | --- | --- | --- |
| Request phase and total timeouts | None | Phantom | `RequestTimeouts` | Yes: reset or closed connection |
| Connection-setup retry delay | No retries | Phantom | `RetryPolicy::connection_failures` | Yes: timing of the new connection |
| Status retry delay, `Retry-After` cap | No retries | Phantom | `StatusRetry` | Yes: timing of the repeat |
| Wait for another handshake to a known-H2 negotiated key | None (waits until it ends) | Firefox 156; Chromium 154 uses 300 ms | `negotiated_setup_wait_limit` | Yes: a second handshake |
| Alt-Svc race origin delay | None (sequential) | Chromium computes it per request | `AltSvcRace::new` | Yes: when TCP setup starts |
| Raced alternative setup limit | 4 seconds | Chrome 153 source and capture | `AltSvcRace::with_alternative_setup_limit` | Yes: when QUIC setup stops |
| Broken alternative period | 300 seconds, doubling to 2 days | Chrome 153 NetLog and source | `AltSvcBrokenBackoff` | Yes: when QUIC is tried again |
| Alt-Svc lifetime without `ma` | 24 hours | RFC 7838 | Server's `ma` | No |
| HTTPS record result lifetime | Answer TTL, at most 1 day; 60 seconds without one | Phantom | Not configurable | Resolver only |
| HTTPS record query timeout and attempts | 5 seconds, 2 attempts | hickory-resolver default | `HttpsRecordResolver::from_fn` replaces the resolver | Resolver only |
| Early data answer wait | Until the handshake ends | QUIC | Connect timeout | No |
| TCP address-racing fallback delay | 300 ms in `chromium::v154_tcp`; Firefox recipe tries addresses in order | Chromium 154 source | `TcpSettings::address_racing` | Yes |
| TCP keepalive idle and interval | 45 seconds in `chromium::v154_tcp`; unset for Firefox | Chromium 154 source | `TcpSettings::keepalive` | Yes |
| QUIC idle timeout | Profile's `max_idle_timeout` (30 seconds for Chrome 154) | Chrome capture | `QuicTransportSettings` | Yes: transport parameter |
| HTTP/2 idle PING | None sent | Phantom | Not configurable | No |
| SSE reconnect delay | 3 seconds, or the server's `retry` | Phantom | `initial_retry`, `min_retry` | Yes |
| Resend after a stale keep-alive connection closes | Immediate, when enabled | Chrome | `RetryPolicy::with_reused_connection_replay` | Yes |
| H2 and H3 driver shutdown after the last handle drops | 1 second | Phantom | Not configurable | Yes: close timing |
| Queued CONNECT-UDP datagram lifetime | 10 ms to 1 second | Phantom | Not configurable | No |

The pools have no sleeps of their own: a request waits only for an admission
slot, a connection another request is setting up, or the timers above.

## Cookies

The optional cookie jar (`CookieLimits`) defaults to:

- 4,096 bytes per `Set-Cookie` field, above which a cookie is rejected;
- 180 cookies per registrable domain; and
- 3,300 cookies in total.

The two count limits are Chromium's `kDomainMaxCookies` and `kMaxCookies`
(`net/cookies/cookie_monster.cc`). Exceeding a count limit evicts cookies
instead of rejecting the new one; [Eviction](cookies.md#eviction) gives the
order and the differences from Chromium.

## Protocol state

| Limit | Value |
| --- | --- |
| Undelivered HTTP/2 ALTSVC frames per connection | 16 |
| Raced Alt-Svc alternative setup, including name resolution | 4 seconds, or `AltSvcRace::with_alternative_setup_limit` |
| Origins with a cached HTTPS DNS record result, per client | The `maximum_origins` given to `ClientBuilder::alt_svc`, least recently used evicted |
| Lifetime of an HTTPS DNS record result | Lowest answer TTL, at most 1 day; a negative answer's SOA TTL; 60 seconds with no TTL or after a failed lookup |
| QUIC session tickets per H3 pool entry, and per CONNECT-UDP outer connection | 4, least recently stored evicted |
| HTTP proxy and credential pairs remembered for Basic authentication, per client | 128, least recently used evicted |
| Host names with cached addresses, per client | `DnsCacheSettings::max_entries`: 1,000 in `chromium::v154_dns_cache`, 1,600 in `firefox::v156_dns_cache`; an expired name, then the one that expires soonest, evicted |
| Lifetime of cached addresses | `DnsCacheSettings::ttl`: 60 seconds in both recipes |
| Lifetime of a cached failed lookup | `DnsCacheSettings::negative_ttl`: not kept in `chromium::v154_dns_cache`, 60 seconds in `firefox::v156_dns_cache` |
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
| Pool keys remembered as having selected HTTP/2 through negotiation, per client | 500, least recently used evicted |

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
value, and applies to every profile.

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
| Outbound write buffer | Message limit plus 128 KiB plus 14 bytes | Follows the message limit |
| `permessage-deflate` client window | 15 bits | `PerMessageDeflate::client_max_window_bits` |
| `permessage-deflate` compression level | 6 | `PerMessageDeflate::compression_level` |

- The frame count includes the first text or binary frame and every
  continuation, including empty ones. Interleaved Ping, Pong, and Close
  frames do not count.
- A message with too many frames fails with `WebSocketErrorKind::Capacity`
  and closes the transport. The check runs before decompression or
  reassembly, so many tiny or empty frames cannot cause unbounded work.
- Decompressed bytes count against the message limit as they expand, so an
  oversized compressed message stops early.
- On a pooled H2 session, a WebSocket holds one of the origin's
  `max_concurrent_http2_requests_per_origin` slots for its life.

## CONNECT-UDP

| Limit | Value |
| --- | --- |
| Received datagram queue per stream | 256 payloads |
| Queued outbound capsules (H2 and H1 legs) | 256 |
| Outer path MTU (H3 leg) | 1,252 bytes |
| Context ID 0 payload | 65,527 bytes |
| DATAGRAM capsule | 65,535 bytes |

Details are in [HTTP/3 internals](../internals/http3.md#connect-udp-masque).

## Next

- [Coverage](coverage.md): what each layer supports.
- [Connections, redirects, and cookies](../guides/connections-and-state.md):
  how the pools and the cookie jar behave.
- [Tune throughput and latency](../guides/performance.md): which bounds to
  raise, and what a server sees.
