# Defaults and limits

Look up defaults, size limits, and policies you must enable.
[Design](../explanation/design.md#state-belongs-to-one-client-and-has-a-bound)
explains how Phantom limits the state a client keeps.

## Off by default

| Policy | Default | Enable with |
| --- | --- | --- |
| Timeouts | None | `ClientBuilder::request_timeouts`, `RequestBuilder::timeouts` |
| Base URL | Absolute request URLs required | `ClientBuilder::base_url` |
| Header hooks | None | `ClientBuilder::header_hook`, `RequestBuilder::header_hook` |
| Environment proxies | Ignored | `ClientBuilder::environment_proxies(EnvironmentProxies::from_env()?)` |
| Redirects | Not followed | `RedirectPolicy::limited` |
| Connection-setup retries | None | `RetryPolicy::connection_failures` |
| Reused-connection, unprocessed-request, and status retries | None | See [Retries and replays](../guides/retries.md) |
| HTTP/2 fallback of an exact HTTP/3 request | None | `RetryPolicy::with_http2_fallback` |
| Sending a streaming request body again | Never | `RequestBuilder::buffered_streaming_body`, which keeps up to the bytes you set until `send` returns |
| Waiting for `100 Continue` before a request body | No `Expect` field; the body follows the head | `RequestBuilder::expect_continue(wait)` |
| Exact HTTP/3 to a known alternative service | The origin's own location | `RequestBuilder::alt_svc_alternative` |
| WebSocket connection-setup retries | None | `WebSocketRequestBuilder::retry_policy` |
| Cookies | No jar | `cookies` feature, then `ClientBuilder::cookies` or `cookie_jar` |
| Alt-Svc | Disabled | `ClientBuilder::alt_svc(maximum_origins)` |
| Racing a learned Alt-Svc alternative against the origin | Sequential: the alternative alone | `ClientBuilder::alt_svc_policy(AltSvcPolicy::race(..))`, with `alt_svc` |
| HTTP/3 early (0-RTT) data | As the profile's QUIC `early_data`; every built-in QUIC recipe offers it: `chrome::v154_quic`, which every Chromium-family profile uses, and `firefox::v157_quic` | `ClientBuilder::http3_early_data(bool)` overrides the profile |
| HTTPS DNS record discovery | Off | `https-records` feature, then `ClientBuilder::https_record_discovery` |
| Address cache | As the profile's `DnsCacheSettings`; off without one | `ClientProfile::with_dns_cache` or `ClientBuilder::dns_cache`; `ClientBuilder::no_dns_cache` turns it off |
| Host-to-address overrides | None | `ClientBuilder::resolve` |
| Address resolver | The operating system's | `ClientBuilder::dns_resolver`; [paired Windows resolvers](../guides/name-resolution.md#resolve-names-with-phantoms-own-dns-queries) or `AddressResolver::system_nameservers` send Phantom's own queries |
| Local source address | The operating system's | `ClientBuilder::local_address`, one per address family |
| Interface binding | None | `ClientBuilder::interface` on Linux, Android, macOS, and Windows |
| TLS client certificate | None; a `CertificateRequest` gets an empty `Certificate` | `ClientBuilder::client_certificate`, `ClientBuilder::client_certificate_for` |
| Disabling origin certificate verification | Certificate chain and hostname verified for H1, H2 and H3 | `danger-disable-verification` feature, then `ClientBuilder::server_authentication(ServerAuthentication::DangerDisabled)` |
| Content decoding | Wire body | `ContentDecoding::advertised(max)` |
| More than one H2 connection per pool key | One connection | `ClientBuilder::max_http2_connections_per_origin` |
| More than one H3 connection per transport location | One connection | `ClientBuilder::max_http3_connections_per_origin` |
| Limit on waiting for another negotiated handshake | Waits until it ends | `ClientBuilder::negotiated_setup_wait_limit` |
| Cargo features | None | See [Getting started](../getting-started.md#optional-features) |

Content decoding limits each stage input to 16 KiB and each pump to eight
passes. A body poll handles at most eight pumps before yielding. Buffered
work that produces no data checks idle and total deadlines when it yields.
Completed bodies still check the total deadline. These quotas bound work
between checks; they cannot interrupt a codec call already running.

Some requests are sent again by default.
[Retries and replays](../guides/retries.md) lists each case. A bodyless HTTP/2
GET refused by `GOAWAY(NO_ERROR)` is always
sent once more. With a Chromium-family HTTP/2 recipe, a request whose
connection closed on an unanswered PING is sent again, any method, up to
twice per redirect hop, unless its body cannot be sent again; set
`Http2Settings::ping_failure_retries` to 0 to turn it off. A profile with
client hints repeats a safe request once when a `Critical-CH` response
names a hint it lacked. Chromium-family WebSocket recipes restart a
refused extended CONNECT opening through profile selection at most twice.
The original handshake timeout covers all attempts
([WebSocket recipes](websocket.md#browser-recipes)).

## Timeouts

`RequestTimeouts` sets the client's limits; none is set by default.
`RequestTimeoutOverrides` changes individual limits for one request or SSE
connection. Unchanged fields inherit the client limit.

| Override | Effect |
| --- | --- |
| `TimeoutOverride::Inherit` | Keep the client limit |
| `TimeoutOverride::Disabled` | Remove that limit |
| `TimeoutOverride::Limit(duration)` | Use this duration, including zero |

| Timeout phase | Method | Limits |
| --- | --- | --- |
| Pool admission | `pool_admission` | Waiting for a free connection slot |
| Connect | `connect` | DNS, proxy, transport, TLS, and protocol setup, including a negotiated request's wait for another request's TLS handshake to the same pool key |
| Response head | `response_head` | Sending the request and body, then waiting for the status and fields |
| Read idle | `read_idle` | Time without data while reading the response body |
| Total | `total` | The whole operation |

Each phase limit restarts for every redirect, retry, and replay. The total
limit is one deadline over all attempts, delays, and the final response body.
Buffered response frames remain subject to the total deadline. A ready
wire frame satisfies the read-idle limit.

`RetryPolicy::with_max_retries(Some(n))` caps caller-enabled retries across
all redirect hops. Connection setup, reused connections, unprocessed
requests, status retries, and explicit HTTP/2 fallback share the cap.
`Some(0)` disables those retries; `None` adds no combined cap. Each kind
keeps its own eligibility and limit. Profile-required replays keep their
separate limits. The cap never makes a one-shot body replayable.

A WebSocket connect applies none of these. It has one handshake timeout,
`WebSocketRequestBuilder::handshake_timeout`, over the whole opening, whose
error names `TimeoutPhase::WebSocketHandshake`
([WebSocket](#websocket)).

## Connection pools

Pool bounds are nonzero. Active and waiting request bounds must also fit
`tokio::sync::Semaphore::MAX_PERMITS`; `build` rejects larger values with
`BuildErrorKind::InvalidPolicy`. H3 connection counts have their separate
ceiling below. A
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
| H3 connections per pool key and transport location, at most 8 | 1 | `max_http3_connections_per_origin` |
| Origins with learned `Accept-CH` state | 64 | `max_client_hint_origins` |
| Origins with Alt-Svc state | disabled | `alt_svc(maximum_origins)` |
| Alt-Svc alternatives per origin and route | 8, in field order | Not configurable |
| Alt-Svc alternatives one race sets up at once, at most 3; each needs its own H3 admission | 1, the first not broken, as Chrome | `AltSvcRace::with_max_alternatives` |
| Alt-Svc failure records, shared by alternatives, HTTPS-record locations, and evicted origins | 9 × `maximum_origins` | Not configurable |

- Each retained entry holds one pool key's connection state. When the limit
  is reached, the least recently used entry is evicted.
- An H1 connection carries one request at a time, so an H1 entry keeps up to
  its active bound of connections, idle ones included. A request reuses the
  most recently used idle connection before it opens another. The
  `chrome::v154_http1` and `firefox::v157_http1` recipes set 6, the
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
  active and waiting bounds still count all of the key's connections.
- With more than one H3 connection allowed, a request opens another to a
  transport location only when every connection to it carries as many
  streams as the lower of the active bound and the server's
  `initial_max_streams_bidi`. One setup runs at a time per location. The
  active and waiting bounds count all of the key's connections, and
  `ClientBuilder::build` rejects a limit above 8 with `InvalidPolicy`.
- HTTP/2 proxy connections belong to a separate pool per session: one
  connection per proxy route, and 32 routes, least recently used first out
  (`MAX_HTTP2_PROXY_POOL_ROUTES`).
  `ClientBuilder::max_http2_proxy_connections_per_route` allows up to 8
  connections per route (`HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING`); a
  route then opens another once each carries 100 tunnels, or the proxy's
  `SETTINGS_MAX_CONCURRENT_STREAMS` when lower
  (`MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION`). See
  [Shared HTTP/2 proxy connections](../explanation/design.md#shared-http2-proxy-connections).
  With an idle limit, the pool retires a connection without another checkout.
  Open tunnels and caller-owned handles keep it alive until released.
- [Tune throughput and latency](../guides/performance.md) says what a server
  can observe when you raise these bounds.

## Delays and timers

These timers affect when connections open, close, or send data.
The last column shows which changes a server can observe.

| Delay | Default | Source | Set with | A server sees a change |
| --- | --- | --- | --- | --- |
| Request phase and total timeouts | None | Phantom | `RequestTimeouts` | Yes: reset or closed connection |
| Connection-setup retry delay | No retries | Phantom | `RetryPolicy::connection_failures` | Yes: timing of the new connection |
| Status retry delay, `Retry-After` cap | No retries | Phantom | `StatusRetry` | Yes: timing of the repeat |
| WebSocket handshake timeout | The recipe's: 240 seconds for Chromium, 20 seconds for Firefox; none without a recipe | Chromium 154 and Firefox 157 source | `WebSocketRequestBuilder::handshake_timeout` | Yes: closed connection, or a stream reset on a pooled H2 session or H3 connection |
| WebSocket setup retry delay | No retries | Phantom | `WebSocketRetryPolicy::connection_failures` | Yes: timing of the new connection |
| Wait for another handshake to a known-H2 negotiated key | None (waits until it ends) | Firefox 157; Chromium 154 uses 300 ms | `negotiated_setup_wait_limit` | Yes: a second handshake |
| Alt-Svc fixed race origin delay | None (sequential) | Caller policy | `AltSvcRace::new` | Yes: when TCP setup starts |
| Alt-Svc RTT race origin delay | Opt-in, additional delay zero | Client-local verified direct QUIC history | `AltSvcRace::with_rtt_delay`, `AltSvcRttDelay` | Yes: when TCP setup starts |
| QUIC attempt limit of an exact HTTP/3 request that may fall back to HTTP/2 | 4 seconds, the raced alternative's limit | Phantom, from Chrome 153's QUIC idle timeout before a handshake; Chromium lets a responsive handshake run longer | Not configurable | Yes: when TCP setup starts |
| Raced alternative setup limit | 4 seconds | Chrome 153 source and capture | `AltSvcRace::with_alternative_setup_limit` | Yes: when QUIC setup stops |
| Broken alternative period | 300 seconds, doubling to 2 days | Chrome 153 NetLog and source | `AltSvcBrokenBackoff` | Yes: when QUIC is tried again |
| Alt-Svc lifetime without `ma` | 24 hours | RFC 7838 | Server's `ma` | No |
| HTTPS record result lifetime | Earliest record or negative SOA expiry, at most 1 day from lookup construction; missing or expired lifetimes are not cached | Phantom | Resolver can shorten expiry | Resolver only |
| HTTPS record lookup failure backoff | 60 seconds for operational failures; configuration failures are not retained | Phantom | Not configurable | Resolver only |
| Explicit DoH lookup deadline and admission | Caller-supplied finite deadline and concurrent lookup limit, shared by address and HTTPS record factories | Phantom | `DohConfiguration` | Yes: cancellation or refused lookup |
| HTTPS record query timeout and attempts | 5 seconds, 2 attempts | hickory-resolver default | `HttpsRecordResolver::from_fn` replaces the resolver | Resolver only |
| Early data answer wait | Until the handshake ends | QUIC | Connect timeout | No |
| TCP second-attempt delay | 300 ms racing in `chrome::v154_tcp`; a 250 ms backup attempt in `firefox::v157_tcp`, IPv4 until the origin's address family is known, then that family with each backup connect limited to 5 seconds | Chromium 154 source; Firefox 157 source and hook logs | `TcpSettings::address_selection` | Yes |
| TCP keepalive idle and interval | 45 seconds and 45 seconds in `chrome::v154_tcp`; 10 seconds, then 600 seconds, with the setup time as interval, in `firefox::v157_tcp` | Chromium 154 source; Firefox 157 hook logs | `TcpSettings::keepalive` | Yes |
| Reuse of an idle HTTP/1.1 connection | Under 300 seconds idle in `chrome::v154_http1`, checked when a request arrives; closed by a timer after 115 seconds idle in `firefox::v157_http1`; no limit without a recipe | Chromium 154 source and hook logs; Firefox 157 source and hook logs | `Http1Settings::idle_timeout` | Yes: a new connection, or a FIN on an idle one |
| QUIC idle timeout | Profile's `max_idle_timeout` (30 seconds for Chrome 154) | Chrome capture | `QuicTransportSettings` | Yes: transport parameter |
| HTTP/2 idle PING | After 58 seconds without a read, failing after 8 more, in `firefox::v157_http2`; none in `chrome::v154_http2` | Firefox 157 source and capture | `Http2Settings::idle_ping_after`, `idle_ping_timeout` | Yes: PING frame |
| Reuse of an idle HTTP/2 connection | Under 170 seconds without response data in `firefox::v157_http2`, then closed with `GOAWAY(NO_ERROR)` within about a second, or when its last stream ends; no limit in `chrome::v154_http2` or without a recipe | Firefox 157 source | [`Http2Settings::idle_timeout`](profiles.md#idle-http2-connections) | Yes: `GOAWAY` and a new connection |
| Wait for `100 Continue` before a request body | None (no `Expect` field) | RFC 9110 | `RequestBuilder::expect_continue` | Yes: when the body is sent |
| SSE reconnect delay | 3 seconds, or the server's `retry` | Phantom | `initial_retry`, `min_retry` | Yes |
| Resend after a stale keep-alive connection closes | Immediate, when enabled | Chrome | `RetryPolicy::with_reused_connection_replay` | Yes |
| H2 and H3 driver shutdown after the last handle drops | 1 second | Phantom | Not configurable | Yes: close timing |
| Queued CONNECT-UDP datagram lifetime | 10 ms to 1 second | Phantom | Not configurable | No |

SSE reconnects use the original request URL after redirects. Selecting a
transport profile does not select a browser EventSource lifecycle policy.
The [SSE comparison](../explanation/validation.md#windows-h2-and-h3-sse-expansion)
records the observed redirect and timing differences.

A request waits only for an admission slot, a connection another request
is setting up, or the timers above. The one pool timer, which a profile
with `Http1IdleTimeout::ClosedOnTimer` such as `firefox::v157_http1`
starts, closes idle HTTP/1.1 connections and ends a remembered address
family once its origin has no connection; no request waits for it. Direct
HTTP/1.1, negotiated, and exact HTTP/2 openings initially offer one selected
ECH configuration across their retained attempts. Exact H2 retains only an
already-connected backup. Its setup sends no request, and the pool admits it
within the configured connection and spread limits. Authenticated ECH
rejection permits one reconnect to that attempt's selected address.
Direct H2 WebSocket openings share these rules. Their dedicated winner is
not an ordinary pool slot. An accepted stream or rejected body keeps its
family owner; a redundant backup closes without CONNECT or other requests.

HTTPS requests using exact H1, exact H2 or negotiated H1/H2 retain quiet
backups through HTTP/1 CONNECT proxies, plaintext or TLS. The spare remains
bound to its proxy endpoint, origin authority, credentials and TLS context.
An HTTPS spare may finish outer TLS before claim. Its original proxy server
name, TLS cache and authentication-cache scope remain bound. The claimant
supplies current CONNECT headers before authentication and origin TLS.
Returning an unpolled claim preserves its original idle age. Cancelling a
polled claim closes its socket. Quiet spares use the HTTP/1 idle policy:
`ClosedOnTimer` prunes them, and `CheckedOnRequest` rejects expired spares
before claim. An active claim is no longer an idle spare.

Negotiated setup follows actual origin ALPN. When H2 wins, redundant quiet
proxy backups close. Exact H2 keeps its existing single setup per key; a
quiet backup becomes claimable after primary failure or cancellation.
Neither path sends speculative CONNECT or origin TLS on a quiet spare.
H2 in these paths is the inner origin protocol. Physical selection for an
outer H2 proxy connection is separate. Its setup uses the configured TCP
selection, progresses a retained raw backup through proxy TLS, and closes it
at verified H2 negotiation, before authentication or CONNECT. The backup sends
no TLS or application bytes. The bounded ordinary pool route remembers the
physical proxy family per endpoint, server name, credentials, connector
settings and runtime. That memory survives slot retirement because forwarding
handles can outlive slots. Route eviction gives a new route fresh memory,
even while an old caller-owned connection survives. Shared CONNECT-UDP H2
setup keeps family memory in its existing bounded outer entry, across
session replacement, authentication retries and pool clears; entry eviction
resets it. Dedicated ordinary and extended H2 calls remember family only
within one operation, including authentication redials.

Exact and profile-policy `wss://` openings use quiet spares through
plaintext CONNECT or an HTTPS proxy using outer H1. H1 Upgrade shares its
request pool's spare and retains the original origin TLS ticket cache while
applying the WebSocket ALPN offer. Inner H2 extended CONNECT retains the
original connector's TLS context, cache and ALPN offer. A new inner H2
opening has a dedicated owner outside ordinary pool slots; an accepted
stream or rejected body keeps that owner. Profile-policy reuse of an
available ordinary origin H2 session remains unchanged. Verified inner H2
activation closes redundant quiet spares before WebSocket HEADERS.

Claims validate the original route and credentials, then apply current
CONNECT authentication, cookies and ordered WebSocket fields. A quiet spare
sends no CONNECT, origin TLS, H2 preface or WebSocket request. An HTTPS
spare may finish outer H1 TLS before claim. This retention extension
excludes plaintext `ws://` and ECH. Outer H2 uses the physical proxy
retirement boundary above, before CONNECT or WebSocket headers.
SOCKS retention has the separate behavior below.

Exact HTTP/1 forwarding of plaintext origins through HTTP and HTTPS proxies
also retains a quiet backup. An HTTPS spare may finish outer TLS without
sending a request. Its claimant supplies current ordered headers, cookies
and credentials. A request that claims an unfinished spare waits for its
outer TLS. Connections keep their existing origin, route, runtime and
credential bounds. Family memory remains per origin and route. Firefox can
share a forwarding connection between origins on one proxy; Phantom keeps
those origins separate. Proxy TLS uses ordinary handshakes. These CONNECT
paths do not add ECH.
Applying TCP backup policy to CONNECT-UDP does not claim Firefox MASQUE parity.
Failed-address history follows the locally cached DNS record, independently
of CONNECT setup.

Ordinary H1 and exact or negotiated H2 requests through SOCKS use complete
SOCKS negotiations as backup attempts. H1 may retain an unfinished sibling;
H2 retains only a completed negotiation. The spare keeps its original
credentials and origin TLS context. It sends application headers and a body
only for its claiming request. Local DNS learns the selected target family
after SOCKS succeeds; remote DNS learns no local target family. Physical
proxy TCP failures may update that proxy's cached DNS record. SOCKS replies,
authentication, origin TLS and cancellation do not mark a target IP failed.
Direct early-data settings do not disable SOCKS backup retention. Origin
TLS over SOCKS uses an ordinary handshake. These paths do not add ECH.

H1 WebSocket openings can claim those quiet SOCKS tunnels through the request
pool. A quiet tunnel completes SOCKS negotiation but sends no origin TLS or
Upgrade request until claim. H2 WebSocket setup retires redundant tunnels
before HEADERS; accepted streams and rejected bodies retain the dedicated
opening owner. Current cookies and ordered WebSocket fields belong to the
claiming handshake. SOCKS authentication keeps the opening's original
credentials. Route checks, configured retries, admission and the
single handshake deadline still apply. These paths preserve local versus
remote target-family rules. Origin TLS uses an ordinary handshake even
when the profile enables direct early data. These paths do not add ECH.

### RTT-based racing

`AltSvcRace::with_rtt_delay` opts into client-local connection timing.
`AltSvcRttDelay::new` sets a nonzero entry capacity and positive maximum age.
The age bounds both samples and the client's recent verified QUIC success.
`with_additional_delay` adds whole microseconds, zero by default.

| Available history | Origin setup delay |
| --- | --- |
| No fresh verified direct success | Zero |
| Fresh success, missing or zero target sample | 300 ms plus additional delay, capped at 3 s |
| Fresh success and target sample | 1.5 times whole-microsecond RTT plus additional delay, capped at 3 s |

Client clones share history. Samples distinguish origin and dial host/port
pairs. Reading a sample never extends its age. Proxy, verification-disabled,
failed and pending handshakes supply no samples. Ordinary connections publish
after verified completion. Early connections publish after a response confirms
settled handshake metadata.

The first eligible alternative selects one origin timer. Pending discovery,
ready HTTP/2, recent QUIC breakage and failure of every alternative keep their
immediate origin behavior. Fixed racing remains unchanged.

`Client::clear_alt_svc_racing_history` retires the history generation. Older
connections cannot reseed it. `Client::clear_alt_svc` also clears this history.
Neither closes existing connections. This history is separate from session
tickets and browser network partitions or persisted network-success state.
See [Choose the delay from connection timing](../guides/http3-discovery.md#choose-the-delay-from-connection-timing).

## Windows DNS configuration

`dns::chromium_windows_resolvers` requires Windows and `https-records`.
Apply both returned resolvers to share their configuration. Profiles do not
select this constructor automatically.

| Policy | Behavior |
| --- | --- |
| Eligible built-in configuration | First active non-loopback adapter with servers, configured search suffixes and devolution |
| System-only configuration | Addresses use the system resolver; HTTPS queries return `HttpsLookupErrorKind::Configuration` before raw DNS I/O |
| Watched change or terminal watcher failure | Invalidates the paired address and HTTPS cache state; affected work fails without an automatic lookup retry |
| Fixed servers, callbacks and DoH | Retain their own resolver and cache behavior; they do not join this watch |
| Final paired resolver drop | Joins the native worker; native cancellation can block |

Name resolution policy, DNS proxy settings, PPP adapters or differing active
adapter servers select system-only mode. PPP is a compatibility heuristic;
it does not identify every VPN. Notifications are not an atomic view of all
Windows settings. A configuration error is neither a negative DNS answer
nor an operational HTTPS lookup backoff.

## Linux DNS configuration

`dns::chromium_linux_resolvers` requires Linux and `https-records`. Apply
both returned resolvers to share watched settings. Profiles do not select
this constructor automatically.

| Policy | Behavior |
| --- | --- |
| Supported host intake | glibc 2.26–2.42; `/etc/resolv.conf`, `/etc/nsswitch.conf`, hostname, interface indices and owner-start environment overrides |
| Built-in queries | Up to three servers, six complete search suffixes within 256 bytes, `ndots` up to 15, attempts up to five, ordered or rotating servers |
| Unsupported intake | OS address resolution; raw HTTPS queries fail with `HttpsLookupErrorKind::Configuration` before query I/O |
| Change observation | File-parent, network-interface/address and hostname notifications share one generation across paired resolvers and UDP clones |
| Watch failure | Retained terminal error; affected work fails without an automatic lookup retry |
| Final paired resolver drop | Joins native workers; cancellation and OS calls can block |

`LOCALDOMAIN` and `RES_OPTIONS` are captured when the pair starts. TCP-only
DNS, unsupported NSS ordering/actions, zero attempts, conflicting interface
scopes, unknown libc versions and invalid or excessive input select OS-only
mode. Missing configuration files use native defaults. Negated options are
accepted from glibc 2.41.

Native workers process notifications asynchronously. Intake fences drain
pending changes, but do not provide an atomic snapshot of OS settings.
Callers must check configuration tokens around their own caches. The query
backend uses a one-second timeout and the configured retry count; its full
retry schedule is not a browser timing guarantee.

## macOS DNS configuration

`dns::chromium_macos_resolvers` requires macOS and `https-records`. Apply
both returned resolvers to share native configuration and invalidation.
Profiles do not select this constructor automatically.

| Policy | Behavior |
| --- | --- |
| Native intake | Selected SDK's libresolv state and optional libSystem dnsinfo witness; ordered servers, search suffixes, ndots, attempts and rotation |
| Unsupported settings | OS address resolution; raw HTTPS queries fail before opening query sockets |
| Change observation | DNS and hostname notifications, watched hosts path and full file contents, actual hostname samples |
| Query interval | Chromium's one-second fallback period replaces native retransmission seconds; no full browser retry-timing guarantee |
| Final resolver drop | Joins workers; native calls and cancellation can block |

More than one native unscoped resolver with nameservers, excluding mDNS
entries, or unsupported libresolv options selects OS-only mode. The witness
does not inspect the separate scoped-resolver list. Missing native watch
support fails pair construction. The
boundary uses optional private libSystem symbols; public SDK declarations
alone do not establish their availability or a distribution policy.

Intake drains native events around reads and resolver preparation. Cache
tokens observe processed generations, including terminal errors. They do
not provide an atomic OS snapshot. Direct kernel hostname changes also have
a one-second idle sampling cadence, subject to native work and scheduling.
Notify cancellation failure can retain two registrations per failed owner;
repeated failed owners have no global retention bound.

## Cookies

The optional cookie jar (`CookieLimits`) defaults to:

- 4,096 bytes per `Set-Cookie` field, above which a cookie is rejected;
- 180 cookies per registrable domain; and
- 3,300 cookies in total.

Exceeding a count limit removes older cookies instead of rejecting the
new one. [Eviction](cookies.md#eviction) gives the order and the differences
from Chromium.

## Protocol state

| Limit | Value |
| --- | --- |
| Undelivered HTTP/2 ALTSVC frames per connection | 16 |
| Generated `Alt-Used` template slots | At most one `RequestField::AltUsed`, in the HTTP/3 list only; without it, the generated field stays last |
| Raced Alt-Svc alternative setup, including name resolution | 4 seconds, or `AltSvcRace::with_alternative_setup_limit` |
| Cached HTTPS queries by host and port, per client | The `maximum_origins` given to `ClientBuilder::alt_svc`, least recently used evicted |
| Lifetime of an HTTPS DNS record result | Earliest record or negative SOA expiry, at most 1 day from lookup construction; missing or expired lifetimes are not cached |
| HTTPS lookup failure backoff | 60 seconds for operational failures; configuration failures are not retained |
| Learned alternative HTTPS lookup | Off by default; `AltSvcHttpsPolicy::Destination` uses a nonzero caller timeout within the connection setup budget |
| TLS session tickets per H1/H2 pool entry | `TlsSettings::session_tickets`: 2 in Chromium-family recipes, 10 in Firefox recipes; enabled limits are 1 through 10; when full, the ticket the recipe's [ticket order](profiles.md#tls-session-ticket-order) names is dropped |
| QUIC session tickets per H3 pool entry, and per CONNECT-UDP outer connection | 4, least recently stored evicted |
| HTTP proxy and credential pairs remembered for Basic authentication, per client | 128, least recently used evicted |
| Digest nonce sessions, per credential owner | 128, least recently used evicted |
| Digest username and password | 1,024 and 4,096 printable ASCII bytes |
| Digest challenges and parameters per challenge | 32 and 64 |
| Digest challenge bytes and empty list entries per field | 32 KiB and 64 |
| Digest stale challenge retries per request or CONNECT | 1 |
| Digest algorithms by default | SHA-256, SHA-512-256 and their session variants |
| Digest quality of protection | `auth` |
| Digest response authentication fields, head and trailers combined | 32 |
| Digest forwarding nonce acceptance | Complete body and verified head/trailers |
| `407` body read so the replay can use the challenged HTTP/1.1 proxy connection | 64 KiB, `phantom_net::proxy::MAX_CHALLENGE_BODY_BYTES`, chunk framing included on CONNECT; a longer body gets a new connection |
| Host names with cached addresses, per client | `DnsCacheSettings::max_entries`: 1,000 in `chrome::v154_dns_cache`, 1,600 in `firefox::v157_dns_cache`; an expired name, then the one that expires soonest, evicted |
| Lifetime of cached addresses | Without a lifetime, `DnsCacheSettings::ttl`: 60 seconds in both recipes. Raw DNS record TTLs use `min_record_ttl`; native or caller-supplied remaining lifetimes are never extended |
| Failed IPs per cached DNS record | `DnsCacheSettings::address_failure_policy`: Firefox desktop uses `Record` with a Phantom cap of 1,600 distinct IPs; Chromium uses `Ignore`. Capacity or allocation failure returns a resource error without discarding history or granting a retry |
| Lifetime of a cached failed lookup or empty answer | `DnsCacheSettings::negative_ttl`: not kept in `chrome::v154_dns_cache`, 60 seconds in `firefox::v157_dns_cache` |
| Caller-reported DNS lifetime | `AddressResolver::from_answer_fn`: remaining lifetime from answer construction, without a profile floor; zero, expired or unrepresentable lifetimes are not stored |
| Caller-reported negative DNS answer | Lesser of its remaining lifetime and `negative_ttl`, both aged from construction; callback errors are never stored |
| Empty non-final HTTP/2 DATA frames per connection | 100 |
| HTTP/2 opening stream receive target | `None`, or the advertised initial stream window through 2,147,483,647 bytes; an equal target emits no update |
| Firefox 157 opening stream receive credit | 131,072 bytes advertised, raised to 12,582,912 bytes after opening headers; subsequent DATA acknowledgment thresholds are not modeled |
| Unread small HTTP/2 DATA frame overhead per connection | Half the initial connection window, at least 25,600 bytes |
| Distinct ALPS `ACCEPT_CH` origins per connection | 1,024 |
| Informational (1xx) responses before the final head (H1, H2, and H3) | 8 |
| Decoded H3 response field section (headers or trailers) | 256 KiB, or the profile's lower `SETTINGS_MAX_FIELD_SECTION_SIZE` |
| Decoded HTTP/2 response header list | Lower of the profile's `SETTINGS_MAX_HEADER_LIST_SIZE` and 393,216 bytes (not advertised) |
| Stacked content codings | 3 |
| zstd window | 8 MiB |
| Decoded data frame size | 16 KiB |
| TCP keepalive idle time and interval | Whole seconds, 1 to 32,767 |
| TCP keepalive schedule short-lived time | Whole seconds, 1 to 300 |
| TCP keepalive schedule probe count | 1 to 127, also used when the socket setter is disabled |
| TCP keepalive schedule socket setters | Required `set_interval` and `set_probe_count` flags; `ClientBuilder::build` rejects unsupported host combinations |
| TCP send buffer size | 1 to 2,147,483,647 bytes |
| TCP racing fallback delay and backup delay | Nonzero, at most 10 seconds |
| TCP backup connect timeout once the address family is known | Whole seconds, 1 to 600 (`MAX_TCP_BACKUP_TIMEOUT_SECONDS`) |
| Concurrent TCP attempts per connection with address racing or a backup | 2 |
| Pool keys remembered as having selected HTTP/2 through negotiation, per client | 500, least recently used evicted |

Automatic client-hint settings cannot generate, position or request a hint
replay for `Alt-Used` on H1, H2 or H3. Other custom hint names retain their
configured behavior. `ValidatedMapping` samples eligibility once per hop;
retries keep that decision. Imported Alt-Svc snapshots start unvalidated.
See [Alt-Used](profiles.md#alt-used-on-http3) for emission and placement.

`Client::clear_session_tickets` returns `Result<usize, SessionTicketError>`.
It removes retained TCP TLS and QUIC tickets, including imported tickets
awaiting first use and pending library publication. It covers live origin
and TLS proxy caches after pool eviction, including shared H2 and H3
CONNECT-UDP outer caches. Clones share these stores. The count excludes
sessions already offered to native handshakes. Allocation or registry failure
leaves the tickets in place. Clearing also forgets saved QUIC RTTs and prevents
older handshakes from restoring or publishing tickets. Existing connections
and already offered sessions continue.

`Client::export_session_tickets` and `import_session_tickets` transfer TCP
TLS and QUIC tickets. Snapshots contain at most 256 owners, 2,560 records
and 16 MiB of encrypted data. Export preserves source tickets. Unsupported
or conflicting owners reject the complete export.

Import authenticates every owner and checks its profile, peer identity,
certificate settings, protocol and receiving route before changing any
cache. Matching live owners are replaced together. Owners without a cache
wait until first use; unmentioned owners keep their state. Failed imports
preserve live and pending tickets. An empty owner clears its matching
cache, but empty credentialed owners are rejected.

The required third argument, `receiving_routes: &[Route]`, supplies explicit
receiving routes. Pass `&[]` for direct connections. Import also considers
the selected client route and matching live owner routes. At most 256 routes
may be supplied. This list never changes request routing. A failure to
install pending tickets before first use fails that request without sending
it and retains the tickets for another attempt.

A stored snapshot and its randomly generated 32-byte key are sensitive
resumption material. Keep them separate. The `PHOWN003` format requires a
compatible library and native TLS backend. Earlier snapshots are rejected;
re-export tickets with the updated library. Profile-policy binding version 5
also rejects older profile bindings, including those without
`DnsCacheSettings::address_failure_policy`, even when their outer format is
`PHOWN003`.

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

The cap of 8 informational responses is Phantom's bound for every profile.

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
| Opening handshake time | 240 seconds in `chrome::v154_websocket`, 20 seconds in `firefox::v157_websocket`, none without a recipe | `WebSocketRequestBuilder::handshake_timeout` |
| Setup retries per connect | None | `WebSocketRetryPolicy::connection_failures` |

- The frame count includes the first text or binary frame and every
  continuation, including empty ones. Interleaved Ping, Pong, and Close
  frames do not count.
- A message with too many frames fails with `WebSocketErrorKind::Capacity`
  and closes the transport. The check runs before decompression or
  reassembly, so many tiny or empty frames cannot cause unbounded work.
- Decompressed bytes count against the message limit as they expand, so an
  oversized compressed message stops early.
- On a pooled H2 session or H3 connection, a WebSocket holds one of the
  origin's `max_concurrent_http2_requests_per_origin` or
  `max_concurrent_http3_requests_per_origin` slots for its life.

## CONNECT-UDP

| Limit | Value |
| --- | --- |
| Received datagram queue per stream | 256 payloads |
| Queued outbound capsules (H2 and H1 legs) | 256 |
| Outer path MTU (shared H3 leg) | 1,259 bytes |
| Outer path MTU (dedicated H3 leg) | 1,252 bytes |
| Retained shared pool keys | 32 |
| Active shared tunnels and setup waits | 100 by default; `with_tunnel_limits` |
| Queued shared tunnel opens | 100 by default; `with_tunnel_limits` |
| Context ID 0 payload | 65,527 bytes |
| DATAGRAM capsule | 65,535 bytes |

Details are in [HTTP/3 internals](../internals/http3.md#connect-udp-masque).

## SOCKS4 and SOCKS4a

| Setting | Limit |
| --- | --- |
| User ID | 255 UTF-8 bytes, no NUL; empty allowed |
| SOCKS4a domain | 253 ASCII bytes after name normalization |
| Target address | IPv4; local DNS selects the first IPv4 answer |
| SOCKS4a marker addresses | `0.0.0.1` through `0.0.0.255` rejected as targets |
| Proxy address | IPv4 or IPv6 |
| Protocols | H1/H2 TCP tunnels; H3 and learned Alt-Svc upgrades unsupported |

The user-ID bound limits resource use. SOCKS4 itself has no user-ID length
field and no password negotiation.

## Custom profile import

The `fingerprint-import` feature loads complete custom settings from JSON.
Import validates settings without building a client or assigning a browser
identity. See [Custom profile import](fingerprint-import.md#errors-and-limits)
for the format and resource bounds.

## Next

- [Coverage](coverage.md): what each layer supports.
- [Connections and client state](../guides/connections-and-state.md):
  how the pools and the cookie jar behave.
- [Tune throughput and latency](../guides/performance.md): which bounds to
  raise, and what a server sees.
