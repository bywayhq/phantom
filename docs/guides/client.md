# Using the client

This guide is for integrators. It explains the public client model and the
choices that affect requests; packet-level details live elsewhere.

## The three layers

| Layer | Owns |
| --- | --- |
| Profile | Immutable TLS, HTTP/2, HTTP/3, QUIC, and client-hint wire settings |
| Client | Pools, route defaults, trust, limits, redirects, connection retries, cookies, learned hints and alternatives, and TLS sessions |
| Request | Method, URL, ordered fields and trailers, body, protocol, route, retry, and timeout overrides |

Built-in and custom profiles use the same typed model. A recipe name records
capture provenance; it does not make the runtime branch on browser family or
host operating system.

## Configure policy once

Client policy is immutable after `build`; request policy can replace only the
documented per-request settings.

```rust
use std::{num::NonZeroUsize, time::Duration};

use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, RedirectPolicy, RequestTimeouts, RetryPolicy};

fn build() -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v152_tls())
        .with_http2(chromium::v152_http2());
    let timeouts = RequestTimeouts::new()
        .connect(Duration::from_secs(10))
        .response_head(Duration::from_secs(20))
        .read_idle(Duration::from_secs(30))
        .total(Duration::from_secs(60));

    let client = Client::builder(profile)
        .redirect_policy(RedirectPolicy::limited(
            NonZeroUsize::new(5).expect("five is nonzero"),
        ))
        .retry_policy(RetryPolicy::connection_failures(
            NonZeroUsize::new(2).expect("two is nonzero"),
            Duration::from_millis(100),
        ))
        .request_timeouts(timeouts)
        .build()?;
    Ok(client)
}
```

Every timeout, redirect, and connection retry is disabled until configured.
Pool and client-hint limits have finite defaults that `ClientBuilder` can
replace with any nonzero value:

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

A pool key is the origin plus the complete route; each retained entry holds
that key's connection state, and the least recently used entry is evicted when
the limit is reached. An H3 entry keeps connections for up to four transport
locations so exact and Alt-Svc H3 do not replace each other. The negotiated
H1/H2 pool retains at most the lower of the H1 and H2 retention limits, and
its pre-selection admission uses the larger of their active and waiting
limits. H2 and H3 active work is also limited by the peer's stream limit. The
optional cookie jar defaults to 4,096 bytes per cookie, 180 cookies per
domain, and 3,000 cookies in total (`CookieLimits`).

`Client::retry_policy` and `Client::request_timeouts` return the configured
client defaults.

## Choose a protocol

- `get` and `request` select exactly H1, H2, or H3.
- `get_negotiated` and `request_negotiated` perform one direct TLS handshake
  and select H2 for `h2`, or H1 for `http/1.1` or absent ALPN. With bounded
  Alt-Svc enabled, a later negotiated request can select a learned H3 endpoint.
- H3 uses a separate QUIC path and accepts direct routes, local-/remote-DNS
  SOCKS5 through RFC 1928 UDP ASSOCIATE, or an RFC 9298 CONNECT-UDP proxy.

Unsupported combinations fail explicitly before another protocol or route is
attempted.

### Supported scheme, protocol, and route combinations

The table lists what each combination does. "Rejected" means a typed error
before any proxy or origin I/O; nothing falls back to another row or column.
"H1 proxy" is an `http://` or `https://` `HttpProxy` in its default HTTP/1.1
mode, "H2 proxy" is an `https://` proxy with `with_http2_transport`, and
SOCKS5 covers both local-DNS `socks5://` and remote-DNS `socks5h://`.
CONNECT-UDP covers an `https://` template over its default H3 leg or an
explicit H2 or H1 leg.

| Request | Direct | H1 proxy | H2 proxy | SOCKS5 | CONNECT-UDP |
| --- | --- | --- | --- | --- | --- |
| `http://`, exact H1 | Plaintext TCP | Absolute-form forwarding | Rejected | Rejected | Rejected |
| `http://`, exact H2 or H3, or negotiated | Rejected | Rejected | Rejected | Rejected | Rejected |
| `https://`, exact H1 or H2 | TLS | CONNECT tunnel | CONNECT stream (one proxy connection per tunnel) | TCP tunnel | Rejected |
| `https://`, negotiated | One TLS handshake, then H1 or H2; optional Alt-Svc H3 | Rejected | Rejected | Rejected | Rejected |
| `https://`, exact H3 | QUIC | Rejected | Rejected | UDP ASSOCIATE | QUIC in HTTP Datagrams (H3 leg) or DATAGRAM capsules (H2 extended CONNECT or H1 Upgrade leg) |
| `ws://`, H1 | Plaintext Upgrade | Absolute-form forwarded Upgrade | Rejected | Plaintext Upgrade in a TCP tunnel | Rejected |
| `wss://`, H1 | TLS Upgrade | CONNECT tunnel | CONNECT stream | TLS Upgrade in a TCP tunnel | Rejected |
| `ws://`, H2 | Rejected | Rejected | Rejected | Rejected | Rejected |
| `wss://`, H2 | Extended CONNECT on a dedicated connection | Extended CONNECT inside a CONNECT tunnel | Extended CONNECT inside a CONNECT stream | Extended CONNECT in a TCP tunnel | Rejected |
| `ws://` or `wss://`, H3 | Rejected | Rejected | Rejected | Rejected | Rejected |

Every supported cell has a public loopback regression. WebSocket and SSE
requests need the matching Cargo feature, and `ws://` or `wss://` over H3
fails when the builder is created. SSE event sources follow the ordinary rows
for their scheme and protocol.

## Preserve request intent

`RequestHeader` preserves field-name spelling, value bytes, duplicates, and
global order. Ordinary methods can carry owned bytes or a pull-driven
`http_body::Body<Data = Bytes>`.

`RequestBuilder::trailers` adds an ordered static trailer block after successful
body completion. It works with exact H1, H2, and H3 requests and negotiated
H1/H2 requests:

```rust
use phantom::{Client, HttpProtocol, Method, RequestHeader};

async fn send(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .request(HttpProtocol::Http2, Method::POST, "https://example.com/upload")?
        .body("payload")
        .trailers(vec![
            RequestHeader::new("x-checksum", "first"),
            RequestHeader::new("x-token", "secret").sensitive(),
            RequestHeader::new("x-checksum", "second"),
        ])
        .send()
        .await?;

    drop(response);
    Ok(())
}
```

Trailer order, duplicate interleaving, and sensitivity are preserved. H1 also
preserves field-name spelling, uses chunked framing, and generates the
`Trailer` declaration; H2 and H3 require lowercase field names. Negotiated
requests must satisfy both H1 and H2 rules, so their trailer names must be
lowercase. Invalid or forbidden trailers fail before network I/O or body
polling. A body error suppresses the trailer block.

For values computed while streaming, use
`RequestBuilder::streaming_body_with_trailers` and declare the exact ordered
name plan with `RequestTrailerName`. The terminal `Frame::trailers` must match
that plan's normalized names and multiplicities. H1 writes the declared casing;
H2 and H3 require lowercase names. Static and body-produced trailers cannot be
combined, and the streaming body remains one-shot across redirects, retries,
and proxy-authentication replays.

Owned bodies can be replayed where a configured redirect requires it.
Streaming bodies are one-shot. Phantom validates a supplied `Content-Length`;
unknown-length H1 uploads use chunked transfer coding, while H2 and H3 omit the
field.

Method-preserving redirects replay owned static trailers with the body. A
redirect that rewrites the request to GET clears both, and a cross-origin
redirect removes credential-bearing header and trailer fields before the next
attempt.

## Connection retries

`RetryPolicy::connection_failures` opts exact H1, H2, and H3 requests and
negotiated H1/H2 requests into a finite number of connection-setup retries with
a constant caller-selected delay. The default is `RetryPolicy::none()`. A
request-level policy replaces the client's default.

The retry boundary is inside the selected protocol pool, after admission and
before origin request dispatch. DNS, direct TCP, forward-proxy TCP, proxy TCP,
SOCKS TCP/local resolution, direct or SOCKS5-carried QUIC setup, and
CONNECT-UDP outer-proxy resolution and connection failures are eligible only
when their typed error proves that dispatch has not begun. TLS, certificate,
ALPN, proxy negotiation/authentication/rejection, timeouts, HTTP responses,
and protocol or post-dispatch failures remain terminal. The route and exact
protocol never change, and exhaustion returns the last original error.

A negotiated request retries only a direct TCP connect failure, before TLS
starts and therefore before ALPN selects H1 or H2; the error reports no
protocol. TLS, certificate, and ALPN failures are terminal. The request first
takes a bounded per-origin pre-selection admission, whose active and waiting
limits are the larger of the H1 and H2 limits, and keeps it across the retry
delay. After ALPN it converts to the selected protocol's admission. A request
beyond the pre-selection bound fails with `RequestErrorKind::Capacity` and no
protocol. The connection lock is released during the delay, so another
request may install a connection that the delayed request then reuses.

Because a setup retry occurs before the body is polled or moved to a protocol
stream, it is safe for every method and for one-shot streaming bodies; Phantom
does not replay request bytes. One retry budget spans redirects, proxy-auth or
client-hint connection attempts, and H2 replacement connections. Each setup
attempt receives a fresh connect-phase timeout, while the total timeout remains
absolute across delays and attempts. Negotiated requests share the same
budget, including across redirects and client-hint replays.

Independently of `RetryPolicy`, a bodyless GET without trailers whose H2
stream is refused by `GOAWAY(NO_ERROR)` is repeated once on a replacement
connection. This applies to exact H2 and to negotiated requests that selected
H2; the negotiated replacement is admitted and selected by ALPN again. The
replay does not consume the setup-retry budget, and any other method, a
request body, trailers, or a second `GOAWAY` returns the typed H2 error.

`RetryPolicy::with_reused_connection_replay(true)` opts into a post-dispatch
replay class, off by default. An HTTP/1.1 request, exact or negotiated, is
sent once more on a fresh connection over the same route when all of these
hold: it was written to a keep-alive connection that had already delivered a
response, that connection closed or was reset before any byte of the new
response arrived, the method is idempotent (RFC 9110, section 9.2.2: GET,
HEAD, OPTIONS, TRACE, PUT, or DELETE), and the body is absent or owned bytes.
Chrome 153 restarts such a request once on a new connection (see
[validation](../explanation/validation.md#sse-browser-reconnect-evidence)). The request may
already have reached the origin, which is why the class is opt-in and limited
to idempotent methods. A request on a fresh connection, a failure after any
response byte, a one-shot streaming body, POST or PATCH, and a second close
return the original typed HTTP/1 error. The replay happens at most once per
redirect hop, adds no delay, and does not consume the setup-retry budget;
`ResponseInfo::retries_performed` still counts only setup retries. The
`client.request` span records the count as `reused_connection_replays`. A
negotiated replay retires the failed H1 generation and is admitted and
selected by ALPN again, like the negotiated `GOAWAY` replay.

`RetryPolicy::with_unprocessed_replay(Some(maximum))` opts into replaying an
H2 or H3 request that the peer reported as not processed. This is caller
policy, off by default and never part of a browser profile. Only these
signals, received before any response head, qualify:

- H2 `RST_STREAM(REFUSED_STREAM)` on the request stream (RFC 9113, section
  8.7);
- an H2 `GOAWAY` with any error code whose last-stream-id is below the
  request's stream, or that arrived before the stream opened (RFC 9113,
  sections 6.8 and 8.7);
- an H3 request stream reset or stopped with `H3_REQUEST_REJECTED` (RFC 9114,
  section 4.1.1);
- an H3 `GOAWAY` received before the request opened its stream, so no request
  byte was sent (RFC 9114, section 5.2).

Because the server did nothing with the request, any method may be replayed,
but the body must be absent or owned bytes: a one-shot streaming body returns
the original typed error without opening another connection. The replay is
sent at once, without a delay, on a fresh or different connection: when the
policy is on, the pool stops reusing a connection that refused a stream. The
route, the exact protocol or negotiated selection rule, and an Alt-Svc
alternative already in use never change. One budget of `maximum` replays spans
every redirect hop and is shared with no other retry class;
`ResponseInfo::retries_performed` still counts only setup retries, and the
`client.request` span records `unprocessed_replays`.

An H2 stream at or below a `GOAWAY` last-stream-id may have been processed.
When the connection then closes, that stream fails with a transport error and
is never replayed. An H3 stream that was already open when `GOAWAY` arrived is
not replayed either, because the H3 backend does not expose the `GOAWAY`
identifier needed to prove it unprocessed; only `H3_REQUEST_REJECTED` covers
it. Without this policy, the one built-in replay above, a bodyless H2 GET
refused by `GOAWAY(NO_ERROR)`, is unchanged, and with it that replay still
runs first without consuming the unprocessed budget.

`RetryPolicy::with_status_retry` opts into repeating a request after a
retryable response status. This is caller policy, off by default and never
part of a browser profile. `StatusRetry::new` takes the statuses to retry,
a request-wide maximum, and a constant delay; it accepts only 408, 425, 429,
500, 502, 503, and 504 and returns `StatusRetryError` for anything else,
including 421, or for an empty list.

```rust
use std::{num::NonZeroUsize, time::Duration};

use http::StatusCode;
use phantom::{RetryPolicy, StatusRetry};

fn policy() -> Result<RetryPolicy, phantom::StatusRetryError> {
    let status_retry = StatusRetry::new(
        &[StatusCode::SERVICE_UNAVAILABLE, StatusCode::TOO_MANY_REQUESTS],
        NonZeroUsize::new(2).expect("two is nonzero"),
        Duration::from_millis(250),
    )?
    .honor_retry_after(Duration::from_secs(10));
    Ok(RetryPolicy::none().with_status_retry(status_retry))
}
```

A response is retried only when its status is listed, the method is
idempotent (RFC 9110, section 9.2.2), and the body is absent or owned bytes;
otherwise, including for a one-shot streaming body, it is returned
unchanged. The check runs after forward-proxy `407` and Critical-CH handling
for the same response, and the intermediate response updates cookies, client
hints, and Alt-Svc exactly as a returned response would. Its body is then
dropped unread, so an incomplete H1 body retires that connection and an H2 or
H3 body cancels its stream. One budget spans every redirect hop, and
exhaustion returns the last response. The retry keeps the route, the exact
protocol or negotiated selection rule, and an Alt-Svc alternative already in
use.

Each retry waits for the constant delay. When a total timeout is set and the
delay, constant or from `Retry-After`, cannot finish before that deadline,
the response is returned immediately and no further request is sent.
`honor_retry_after(maximum)` instead uses a valid `Retry-After` field, either
delta-seconds or an IMF-fixdate converted against the system clock (RFC 9110,
section 10.2.3). A requested delay above `maximum` returns the response
immediately. A missing, repeated, malformed, or obsolete RFC 850 or asctime
value falls back to the constant delay. `ResponseInfo::retries_performed`
still counts only setup retries; the `client.request` span records
`status_retries`, and each retry emits a debug event with its status and
delay.

## Routes and proxies

Set a default route on `ClientBuilder`, or override it on one request. Supported
TCP routes are direct, HTTP/1.1 absolute-form forwarding over a plaintext or
TLS-encrypted proxy, HTTP/HTTPS CONNECT, and SOCKS5 with local or proxy-owned DNS
and optional credentials.

Forwarding is limited to exact HTTP/1.1 requests for `http://` origins. An
`https://` proxy endpoint uses the independent proxy authentication policy,
which verifies the proxy certificate and hostname by default, then carries the
absolute-form request inside that TLS connection; the origin itself is still
plain HTTP. Forwarding never changes to CONNECT, negotiated H1/H2, H2, H3, or a
direct route. Unsupported combinations fail explicitly instead of selecting
another route or protocol.

When Basic credentials are configured, each logical forwarding request begins
without `Proxy-Authorization`. A strict, valid Basic `407` challenge permits
exactly one replay on a fresh connection for the same complete route. The
generated sensitive `Proxy-Authorization` field follows all caller fields and
precedes generated framing fields. Owned bodies and their static trailers are
replayed exactly. A one-shot streaming body cannot be replayed: after a valid
challenge it returns a typed request-body error before opening the retry
connection. A second `407`, or a malformed or unsupported challenge, returns a
typed proxy error. Challenge state is not retained, so the next logical request
starts anonymously again.

An `https://` proxy speaks HTTP/1.1 by default. `HttpProxy::with_http2_transport`
selects HTTP/2 to the proxy instead; it is rejected for `http://` proxies
because Phantom does not speak cleartext h2c. In both modes the proxy-facing
TLS ClientHello offers the profile's ALPN list unchanged, because a browser
offers the same list to an HTTPS proxy and a rewritten list would be a
ClientHello no measured client sends. The selected protocol is then enforced:
the default mode accepts `http/1.1` or no ALPN and rejects `h2`, and the HTTP/2
mode requires `h2` and rejects `http/1.1` or no selection. A mismatch is a typed
proxy error; Phantom never switches proxy protocols. The HTTP/2 mode requires a
profile that offers `h2` and carries HTTP/2 settings, and reports either gap
before proxy I/O.

In HTTP/2 mode each tunnel opens one dedicated proxy connection using the
profile's HTTP/2 SETTINGS, priority, and pseudo-header order; proxy sessions are
not shared between tunnels or pooled separately from the origin connection that
owns them. The CONNECT request follows RFC 9113 section 8.5: only `:method` and
`:authority` pseudo-headers, then the ordered CONNECT fields with HTTP/2
lowercase names. The authority placeholder supplies `:authority`, and
connection-specific fields such as `Proxy-Connection` fail before I/O. The
tunnel is a flow-controlled stream of DATA frames carrying origin TLS for H1 or
H2 origins; closing the origin connection resets only that stream and ends its
proxy connection. Basic `407` challenges follow the same one-replay rule on a
fresh proxy connection. Plaintext `http://` forwarding requires HTTP/1.1 proxy
transport and fails before I/O in HTTP/2 mode.

The complete route participates in pool identity. Proxy failure never falls
back direct. For exact H3, local-DNS `socks5://` resolves the origin locally
and fixes one IP target. Remote-DNS `socks5h://` performs no local origin
lookup and encodes the canonical origin hostname in each SOCKS UDP request.
Both routes open an RFC 1928 UDP ASSOCIATE and keep the TCP control connection
alive for the association lifetime. H3 connections and associations are
retained through the normal route-keyed pool, so compatible requests can reuse
them. Optional username/password authentication uses RFC 1929. Proxy
authentication, negotiation, and rejection failures are typed and are not
address-fallback candidates. Proxy TCP and QUIC connection setup may advance
or retry only through a fresh association on the same configured route, under
the documented exact-H3 setup policy; no failure selects another route or
protocol. Loopback tests retry a refused local-DNS proxy connect and a QUIC
handshake refused through an established association, each through a new
association (see [connection-retry evidence](../explanation/validation.md#connection-retry-evidence)).

An H3 SOCKS5 relay reply must provide a nonzero port. Phantom uses a concrete
IP relay address directly; for an unspecified relay address, it substitutes
only the established TCP proxy peer IP and retains the returned port. Domain
relay addresses are rejected. Remote-DNS replies may identify the target by
the exact canonical domain or by a same-port IP, while Quinn sees one stable
logical peer and authenticates the QUIC connection. Exact H3 rejects HTTP
forwarding and HTTP CONNECT before origin I/O. WebSocket over H3 extended
CONNECT remains planned. Proxy credentials are validated before I/O and
excluded from diagnostics.

`Route::connect_udp` sends exact H3 through an RFC 9298 CONNECT-UDP (MASQUE)
proxy. `ConnectUdpProxy::new` takes an `https` URI template that must contain
`{target_host}` and `{target_port}` and must not contain user information or a
fragment; `.header` appends ordered CONNECT-UDP request fields. Each inner
connection opens its own outer connection to the proxy, authenticated with the
proxy trust roots, and the inner connection keeps origin trust and identity.

The proxy leg is HTTP/3 by default, and its outer profile must support HTTP/3
Datagrams large enough for a full 1200-byte QUIC Initial, or the request fails
before I/O. `with_http2_transport` uses HTTP/2 extended CONNECT, which needs an
extended CONNECT pseudo-header order in the HTTP/2 profile and a proxy that
selects `h2` and enables extended CONNECT. `with_http1_transport` uses an
HTTP/1.1 `Upgrade: connect-udp` request that must receive 101. Both carry
datagrams in capsules on the proxy stream and use the client profile's TLS
offer. The leg is part of route identity; ALPN or capability mismatches are
typed proxy errors and never switch legs. `with_basic_auth` sends Basic
credentials only after a valid 407 challenge, once, on a fresh proxy
connection; a second 407 fails with an authentication error.

HTTP/1.1, HTTP/2, negotiated requests, and WebSocket reject this route before
I/O. Only outer proxy resolution and connection failures are retryable, and a
proxy rejection exposes its status through the typed error source. See
[HTTP/3 internals](../internals/http3.md#connect-udp-masque) for the protocol contract.

```rust
use phantom::{ConnectUdpProxy, RequestHeader, Route};

fn masque_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = ConnectUdpProxy::new(
        "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
    )?
    .header(RequestHeader::new("x-client", "phantom"));
    Ok(Route::connect_udp(proxy))
}

fn masque_over_http2_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = ConnectUdpProxy::new(
        "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
    )?
    .with_http2_transport()
    .with_basic_auth("proxy-user", "proxy-password")?;
    Ok(Route::connect_udp(proxy))
}
```

The credential-bearing route below works for either an HTTPS origin through
CONNECT or an `http://` origin through exact-H1 forwarding. In both cases Basic
credentials are sent only after a valid proxy challenge.

```rust
use phantom::{HttpProxy, Route};

fn route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = HttpProxy::new("https://proxy.example:8443")?
        .with_basic_auth("proxy-user", "proxy-password")?;
    let route = Route::http_proxy(proxy);
    Ok(route)
}
```

For an HTTP/2-only proxy, add `.with_http2_transport()?` to the proxy; that
route then supports HTTPS origins only.

Add private DER roots with `add_root_certificate_der`; use
`add_proxy_root_certificate_der` for an HTTPS proxy, including a TLS-encrypted
forward proxy and the outer connection of a CONNECT-UDP proxy. The proxy and
origin trust stores are independent. Certificate and hostname verification
remain enabled by default. `ClientBuilder::server_authentication` and
`proxy_server_authentication` accept `ServerAuthentication::Disabled` for
controlled conformance work only: origin verification can be disabled for
H1/H2 but not combined with additional roots or H3, and proxy verification
cannot be disabled for a CONNECT-UDP route on any leg.

Other route configuration:

- `HttpProxy::header` appends an ordered CONNECT field after the default
  leading `Host`, `headers` replaces the literal fields, and
  `connect_headers` replaces the whole sequence with `HttpConnectHeader`
  values, including the `Authority` placeholder that controls `Host`
  placement. These fields apply to CONNECT tunnels, not to forwarded
  requests.
- `Route::http_connect` is an older name that builds the same
  `Route::HttpProxy` as `Route::http_proxy`.
- `Socks5Proxy::with_username_password` configures RFC 1929 credentials, and
  `Socks5Proxy::dns_mode` reports whether the URI selected `socks5://`
  (`Socks5DnsMode::Local`) or `socks5h://` (`Socks5DnsMode::Remote`).
  Credentials inside the proxy URI are rejected.
- Proxy, SOCKS5, and CONNECT-UDP configuration errors expose stable
  `ProxyConfigErrorKind`, `Socks5ProxyConfigErrorKind`, and
  `ConnectUdpProxyConfigErrorKind` categories.

## Client-owned state

`Client` is cheap to clone. Clones share bounded state; independently built
clients do not.

- H1 connections are reused sequentially without pipelining.
- H2 and H3 multiplex within peer and local limits.
- Pool admission and retained connections are bounded per origin and route.
- Dropping one H2 or H3 request cancels its stream, not unrelated work.
- Redirects are disabled until a finite policy is configured.
- Connection retries are disabled until a finite policy is configured.
- Cookies require the `cookies` feature and explicit builder activation.
- Learned `Accept-CH` state is bounded and scoped to the exact secure origin.
- Alt-Svc is disabled by default. `ClientBuilder::alt_svc` enables a bounded,
  in-memory exact-origin store for negotiated HTTPS requests,
  `Client::clear_alt_svc` clears it, and `Client::export_alt_svc` and
  `Client::import_alt_svc` move it through caller-owned storage.

`Client::clear_client_hints` discards learned `Accept-CH` selections. The
client also retains bounded TLS session tickets for H1/H2 resumption, keyed by
exact origin and route and never used for early data.

### Redirects

`RedirectPolicy::limited(n)` follows at most `n` redirect responses per
logical request; `RedirectPolicy::none()`, the default, returns them to the
caller. Following is HTTPS-only:

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
- 301 and 302 rewrite POST to GET, and 303 rewrites everything except GET and
  HEAD; a rewrite drops the body, static trailers, and body-describing
  fields. 307 and 308 preserve the method and replay an owned body, while a
  one-shot streaming body fails with `RequestErrorKind::RequestBody`.
- A cross-origin hop removes `Authorization`, `Cookie`, `Cookie2`, and
  `Proxy-Authorization` fields and trailers and rebuilds client hints for the
  new origin. Cookies from the jar are recomputed for every hop.
- Every hop keeps the request's route and exact protocol or negotiated
  selection rule, and one total timeout and retry budget span all hops.

`ResponseInfo::effective_uri` and `ResponseInfo::redirects_followed` describe
the final hop.

### Cookies

With the `cookies` feature, `ClientBuilder::cookies` enables a bounded
in-memory jar and `ClientBuilder::cookie_jar` installs a caller-built
`CookieJar` (for example one made with `CookieJar::with_limits`).
`Client::cookie_jar` returns the active jar, whose `set_cookie`,
`request_value`, `clear`, and `len` methods operate on the same state requests
use. The jar applies domain, path, expiry, `Secure`, `HttpOnly`, public-suffix,
`__Secure-`/`__Host-` prefix, and deterministic ordering rules.

The jar has no request-site or top-level-site context, so it rejects rather
than stores cookies whose semantics depend on it: `SameSite=Lax`,
`SameSite=Strict`, and `Partitioned` (CHIPS) cookies. It also rejects
`SameSite=None` without `Secure` and any `Secure` cookie set by an `http://`
URL. From a response, a rejected `Set-Cookie` is ignored and recorded only as a
debug event; `CookieJar::set_cookie` returns `CookieErrorKind::UnsupportedPolicy`
(or `InvalidPrefix` for prefix violations). Such cookies are therefore never
sent back, which differs from a browser.

### Alt-Svc

An authenticated negotiated H1/H2 response can advertise `h3`. Phantom
applies `Age` to `ma`, replaces the origin's previous alternatives, and uses
the first fresh canonical `h3` alternative on the next negotiated request.
The alternative changes only the QUIC network location: URI, authority, TLS
identity, cookies, client hints, route key, and timeouts remain those of the
origin. On that managed Alt-Svc H3 attempt, Phantom automatically sends one
canonical `Alt-Used` value naming the alternative with an explicit port. It
does not add `Alt-Used` to exact H3 requests or ordinary negotiated H1/H2
requests. Caller-supplied `Alt-Used` request fields and trailers are reserved
and rejected before network I/O. This support makes no browser-specific
field-order claim.

A negotiated H2 response also teaches HTTP/2 ALTSVC frames (RFC 7838 section
4) that arrived before its final headers, in arrival order and before the
response's own `Alt-Svc` field. A stream-0 frame applies only when its origin
is exactly the request's canonical ASCII origin, such as
`https://example.com` or `https://example.com:8443`; a frame on the request's
stream applies to the request origin. Malformed frames, frames for another
origin, frames on exact H2 requests, and frames received while Alt-Svc is
disabled change nothing. Each connection keeps at most 16 undelivered frames.

Alt-Svc state stays in memory unless the caller persists it.
`Client::export_alt_svc` returns an `AltSvcSnapshot`, or `None` when Alt-Svc is
disabled. Each entry holds only the canonical origin, the alternative host and
port, and an absolute `SystemTime` expiry rounded down to a whole second, least
recently used first. Phantom provides no serialization format. Rebuild entries
with `AltSvcSnapshotEntry::new` and pass them to `Client::import_alt_svc`,
which revalidates every entry and rejects the whole snapshot with a typed
`AltSvcSnapshotError` if one origin or alternative is not canonical. Import
drops expired entries, clamps lifetimes without extending them, gives
already-held alternatives precedence, and keeps the most recently used entries
within the store capacity. The store is keyed by origin for direct routes, so
a snapshot describes direct-route alternatives only. It never contains TLS
tickets, connections, routes, cookies, or credentials, and its `Debug` output
omits hosts.

Alternative setup failure is a typed H3 failure for that request and evicts
the advertisement; it never silently falls back. A visible `421` response also
evicts it. Racing, multiple-alternative racing, and proxy-route upgrades are
not implemented.

## Timeouts

Timeouts are disabled by default. Client or request policy can bound pool
admission, connection setup, response head, response-body inactivity, and the
whole operation across redirects, retry delays, connection attempts, and
bounded replays. Phase limits restart for each attempt; the total deadline does
not. Errors identify the phase and selected protocol.

`RequestTimeouts` sets these phases with `pool_admission`, `connect`,
`response_head`, `read_idle`, and `total`; `RequestError::timeout_phase`
returns the matching `TimeoutPhase`. `RequestBuilder::timeouts` replaces the
client policy for one request. An SSE event source applies them per attempt
and stops the read-idle and total timers once a stream is established (see
[SSE](sse.md)). WebSocket connects apply none of them.

## Responses

Every successful request returns `http::Response<ResponseBody>`. Its extensions
include `ResponseInfo` and `OrderedResponseHeaders`. The latter preserves
duplicate interleaving on every protocol and original field-name spelling on
H1. `ResponseInfo` also reports the effective URI, the selected protocol,
`redirects_followed`, and `decoded_content_codings`.
`ResponseInfo::retries_performed` counts connection-setup retries: each time a
failed setup was attempted again under `RetryPolicy::connection_failures`,
summed across every redirect hop of the logical request. A retry is counted
when it starts, whether or not that attempt succeeds. It excludes redirects,
status retries, reused-connection and graceful-`GOAWAY` replays, proxy
authentication replays, and `Critical-CH` retries.

The body is streaming and backpressured. Consume it to completion when you want
the connection to remain eligible for reuse.

`ResponseBody` implements `http_body::Body<Data = Bytes>`. Body errors use the
same `RequestError` type as request establishment. Dropping an incomplete H1
body may retire that connection; dropping an H2 or H3 body cancels its stream.
`ResponseBody::collect_with_limit` consumes the stream with an inclusive byte
cap and returns `RequestErrorKind::ResponseBodyLimit` before retaining a chunk
that would exceed it. Trailers are consumed and discarded by this convenience
operation.

### Content decoding

Response data is the encoded wire body by default. Phantom never inserts,
removes, or moves `Accept-Encoding`: the field's presence and ordered position
belong to the caller or profile.

`RequestBuilder::content_decoding(ContentDecoding::advertised(max))` opts one
request into streaming decoding of `gzip` (and `x-gzip`), `deflate`, `br`, and
`zstd`. Only codings the request's own ordered `Accept-Encoding` fields
advertise are accepted: an explicit member with a nonzero weight, or a nonzero
`*` for a coding without an explicit member. An explicit `q=0` withdraws a
coding. With decoding enabled, a malformed `Accept-Encoding` fails before any
network I/O with `RequestErrorKind::InvalidHeader`. The request head is
byte-identical with and without decoding.

```rust
use phantom::{Client, ContentDecoding, HttpProtocol, RequestError, RequestHeader};

async fn fetch(client: &Client) -> Result<bytes::Bytes, RequestError> {
    let response = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .header(RequestHeader::new("accept-encoding", "gzip, br"))
        .content_decoding(ContentDecoding::advertised(8 << 20))
        .send()
        .await?;
    response.into_body().collect_with_limit(8 << 20).await
}
```

Decoding fails closed with `RequestErrorKind::ContentDecoding` on the first body
poll, with status and fields still visible, for:

- an unknown coding, including `compress`, `dcb`, and `dcz`;
- a supported coding the request did not advertise;
- `identity` mixed with a coding, or more than three stacked codings;
- malformed or truncated coded data, checksum mismatches, or bytes after a
  complete gzip member, zlib/raw DEFLATE stream, or Brotli stream;
- zstd frames that are not RFC 8878 or need a window above 8 MiB.

Stacked codings decode in reverse application order. `deflate` selects zlib
when the first two bytes form a valid zlib header and raw DEFLATE otherwise.
These rules are deliberately stricter than browsers, which pass unknown
chains through or discard trailing bytes.

`max` is an inclusive cap on decoded bytes; exceeding it fails the body with
`RequestErrorKind::ResponseBodyLimit` and cancels the stream.
`collect_with_limit` separately counts the decoded bytes it returns. Decoded
data frames are at most 16 KiB, and the transport is polled only after
buffered input is consumed, preserving backpressure. Decoded frames count as
body activity and are checked against the total deadline.

`ResponseInfo::decoded_content_codings` lists the codings applied, in
`Content-Encoding` order. Response fields remain the wire view:
`Content-Encoding` and `Content-Length` are unchanged, and `Content-Length`
still describes encoded bytes. The size hint becomes unknown while decoding.
Trailers pass through after all decoded data. Only the response returned by
`send` is decoded; intermediate redirect bodies are dropped undecoded. HEAD,
204, 304, and already-empty bodies are never validated or decoded.

## Handle stable error categories

`BuildError::kind` and `RequestError::kind` provide non-exhaustive stable
categories. Request errors also expose the selected protocol and timeout phase
when known. Match the category you need and keep a fallback arm for future
variants.

```rust
use phantom::{RequestError, RequestErrorKind};

fn classify(error: &RequestError) -> &'static str {
    match error.kind() {
        RequestErrorKind::Timeout => "timeout",
        RequestErrorKind::Capacity => "local capacity",
        RequestErrorKind::Proxy => "proxy",
        RequestErrorKind::Tls => "tls",
        _ => "request",
    }
}
```

Errors and debug output intentionally omit credentials, cookies, payloads, and
endpoint details. Use bounded tracing or protocol diagnostics when deeper
evidence is required.

## Integration checklist

- Confirm the [distribution constraints](../getting-started.md#distribution-status)
  are acceptable.
- Select only profile components listed in [Coverage](../reference/coverage.md).
- Run inside Tokio with I/O and time enabled.
- Configure route, origin trust, and proxy trust explicitly.
- Choose redirect, connection-retry, and timeout policy; none is inferred from
  a browser name. A redirect policy makes `http://` requests fail, and
  WebSocket connects apply none of these policies (see
  [WebSocket](websocket.md#timeouts-and-retries)).
- Treat streaming request bodies as one-shot and consume response bodies when
  reuse matters.
- Handle non-exhaustive error categories and avoid logging sensitive inputs.
- Enable cookies, SSE, or WebSocket only when the matching Cargo feature and
  lifecycle are required.

For optional APIs, see [Server-sent events](sse.md) and
[WebSocket](websocket.md). For exhaustive support and planned gaps, see
[Coverage](../reference/coverage.md).
