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
    let profile = ClientProfile::new(chromium::v152_macos_tls())
        .with_http2(chromium::v152_macos_http2());
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
Pool and client-hint limits have finite defaults and can be tightened on
`ClientBuilder`.

## Choose a protocol

- `get` and `request` select exactly H1, H2, or H3.
- `get_negotiated` and `request_negotiated` perform one direct TLS handshake
  and select H2 for `h2`, or H1 for `http/1.1` or absent ALPN. With bounded
  Alt-Svc enabled, a later negotiated request can select a learned H3 endpoint.
- H3 uses a separate QUIC path and accepts direct routes, local-/remote-DNS
  SOCKS5 through RFC 1928 UDP ASSOCIATE, or an RFC 9298 CONNECT-UDP proxy.

Unsupported combinations fail explicitly before another protocol or route is
attempted.

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
SOCKS TCP/local resolution, and direct QUIC setup failures are eligible only
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

`RetryPolicy::with_reused_connection_replay(true)` opts into one post-dispatch
replay class, off by default. An HTTP/1.1 request, exact or negotiated, is
sent once more on a fresh connection over the same route when all of these
hold: it was written to a keep-alive connection that had already delivered a
response, that connection closed or was reset before any byte of the new
response arrived, the method is idempotent (RFC 9110, section 9.2.2: GET,
HEAD, OPTIONS, TRACE, PUT, or DELETE), and the body is absent or owned bytes.
Chrome 153 restarts such a request once on a new connection (see
[validation](validation.md#sse-browser-reconnect-evidence)). The request may
already have reached the origin, which is why the class is opt-in and limited
to idempotent methods. A request on a fresh connection, a failure after any
response byte, a one-shot streaming body, POST or PATCH, and a second close
return the original typed HTTP/1 error. The replay happens at most once per
redirect hop, adds no delay, and does not consume the setup-retry budget;
`ResponseInfo::retries_performed` still counts only setup retries. The
`client.request` span records the count as `reused_connection_replays`. A
negotiated replay retires the failed H1 generation and is admitted and
selected by ALPN again, like the negotiated `GOAWAY` replay.

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
protocol.

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
connection opens its own outer H3 connection to the proxy, authenticated with
the proxy trust roots, and the inner connection keeps origin trust and
identity. The outer profile must support HTTP/3 Datagrams large enough for a
full 1200-byte QUIC Initial, or the request fails before I/O. HTTP/1.1, HTTP/2,
negotiated requests, and WebSocket reject this route before I/O. Only outer
proxy resolution and connection failures are retryable, and a proxy rejection
exposes its status through the typed error source. See
[HTTP/3 internals](http3.md#connect-udp-masque) for the protocol contract.

```rust
use phantom::{ConnectUdpProxy, RequestHeader, Route};

fn masque_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = ConnectUdpProxy::new(
        "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
    )?
    .header(RequestHeader::new("x-client", "phantom"));
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
remain enabled by default.

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

## Responses

Every successful request returns `http::Response<ResponseBody>`. Its extensions
include `ResponseInfo` and `OrderedResponseHeaders`. The latter preserves
duplicate interleaving on every protocol and original field-name spelling on
H1. `ResponseInfo::retries_performed` reports successful connection-setup
retries separately from redirects.

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

- Confirm the [distribution constraints](getting-started.md#distribution-status)
  are acceptable.
- Select only profile components listed in [Coverage](coverage.md).
- Run inside Tokio with I/O and time enabled.
- Configure route, origin trust, and proxy trust explicitly.
- Choose redirect, connection-retry, and timeout policy; none is inferred from
  a browser name.
- Treat streaming request bodies as one-shot and consume response bodies when
  reuse matters.
- Handle non-exhaustive error categories and avoid logging sensitive inputs.
- Enable cookies, SSE, or WebSocket only when the matching Cargo feature and
  lifecycle are required.

For optional APIs, see [Server-sent events](sse.md) and
[WebSocket](websocket.md). For exhaustive support and planned gaps, see
[Coverage](coverage.md).
