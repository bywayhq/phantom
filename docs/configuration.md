# Configuration model

Phantom exposes behavior by ownership, not as one large builder. A setting is
public only when the implementation can validate it before I/O and an
observable test proves what it changes. Built-in recipes and caller-authored
settings use the same concrete types.

```mermaid
flowchart LR
    Profile["Wire profile\nTLS · H1 · H2 · QUIC · H3"]
    State["Client-owned state\npools · cookies · client hints · redirects · tickets"]
    Route["Route policy\ndirect · proxy · DNS · local bind"]
    Request["Request policy\ntimeouts · retry · protocol · ordered headers"]
    Runtime["Runtime services\nTokio · resolver · clock · entropy"]
    Diagnostics["Diagnostics\ntracing · qlog · key log"]
    Validate["Validate and resolve"]
    Attempt["One owned attempt"]

    Profile --> Validate
    State --> Validate
    Route --> Validate
    Request --> Validate
    Runtime --> Validate
    Diagnostics --> Validate
    Validate --> Attempt
```

This keeps unrelated lifetimes separate. A TLS cipher list is immutable
profile data. A learned `Accept-CH` value is mutable client state. Proxy
credentials belong to a route. A per-request timeout does not mutate the
client. The runtime owns connection IDs, entropy, clocks, and task execution;
captured profiles describe their policy but never retain captured random
bytes.

## Public shape

The facade grows through three ordinary levels:

- `ClientBuilder` currently owns one immutable profile, additive origin and
  HTTPS-proxy trust roots, independent authentication policies for those TLS
  legs, a default `Route` (`Direct`, HTTP forwarding or CONNECT, or
  local-/remote-DNS SOCKS5), bounded pool and admission limits, optional
  cookies, client-hint storage, and redirect policy.
- `RequestBuilder` currently owns an exact protocol, an HTTP or HTTPS target,
  ordered fields, and an optional complete timeout-policy override. Plaintext
  HTTP is accepted only for exact H1 forwarding through a plaintext HTTP
  proxy. It may also own a route override; general retry policy remains absent.
- `ClientProfile` owns required TCP TLS, optional H2 settings, optional ordered
  client-hint data, and an optional atomic H3 bundle containing its own TLS,
  QUIC transport, H3 connection, and H3 request settings. Typed values can be
  cloned and edited before the client is built.

`Client` reuses eligible H1, H2, and H3 connections; independently built
clients do not share them. The facade synthesizes the H1
`Host` field from the URI, uses the URI authority for H2 and H3, and rejects a
caller-supplied origin `Host` field. An HTTP or HTTPS CONNECT route has a
separate ordered field sequence with one typed destination-authority
placeholder. Optional HTTP Basic credentials add a second typed placeholder;
the first CONNECT omits it, and one valid Basic challenge permits one retry on
a fresh connection with the generated field in that exact position. HTTPS
authenticates the proxy before CONNECT using an independent trust store, then
authenticates the origin inside the tunnel. Request, credential, and CONNECT
validation happen before proxy I/O; failures never trigger a direct retry. A
`socks5://` resolves domain origins locally and `socks5h://` resolves them at
the proxy. Both apply to H1, H2, client-owned H1/H2 reuse, and H1 WebSocket.
Selecting H2 or H3 without the
corresponding profile settings also fails before network I/O. H3 currently
supports only `Route::Direct`; pairing it with either TCP-only proxy route is
rejected before either proxy TCP or origin UDP is opened. The response body
implements `http_body::Body` and retains the existing protocol cancellation
behavior when dropped.

For an HTTP origin and a plaintext `HttpProxy`, the H1 request instead uses an
absolute-form target on the proxy connection. The same canonical URI authority
produces the leading `Host` field. Forwarding is reusable only for the same
origin and route. Direct HTTP, proxy TLS,
forwarding credentials, redirects, H2/H3, and negotiated H1/H2 are rejected
before I/O. Plaintext responses neither receive generated Client Hints nor
seed the client's `Accept-CH` state.

Absolute request, WebSocket, HTTP-proxy, and SOCKS5-proxy URIs pass through one
WHATWG host parser before endpoint construction. The resulting ASCII authority
is shared by DNS, SNI and certificate-name verification, `Host` or
`:authority`, CONNECT, remote-DNS SOCKS5, pool identity, cookies, and
client-hint origin keys. Explicit ports and the original request path/query
bytes are retained; malformed hosts fail before I/O.

There is no global mutable profile registry, environment-only configuration,
browser-family switch inside a transport, or callback invoked while a pool
key is being computed. Resolved configuration is owned so a live connection
cannot change identity underneath the pool.

## Request timeout policy

`ClientBuilder::request_timeouts` installs a `RequestTimeouts` default shared
by client clones. `RequestBuilder::timeouts` replaces that entire policy for
one operation; `RequestTimeouts::default()` is therefore an explicit way to
disable a client's limits for one request. Every limit is disabled unless the
caller enables it.

The named limits are pool admission, connection setup, response head,
response-body read inactivity, and total operation time. Connection setup
includes DNS, proxy, TLS or QUIC, and protocol startup. Response-head time
includes sending the current owned byte body. The total deadline spans
redirects, bounded internal replays, and the final ordinary body. Errors expose
both `RequestErrorKind::Timeout` and the exact `TimeoutPhase`; unrepresentable
durations fail before network I/O.

Configuration follows these rules:

1. Defaults are useful but never imply browser parity.
2. Exact protocol selection does not fall back.
3. Per-request overrides cannot weaken the route accidentally; proxy failure
   never retries direct.
4. Ordered wire fields remain ordered values rather than maps.
5. Unknown or contradictory settings return a typed error before network I/O.
6. A diagnostic switch cannot alter wire behavior except for the protocol's
   documented diagnostic output, such as qlog or a key log.

## TLS profile and connection policy

A TLS profile is an ordered wire offer, not a security grade. Captured clients
may advertise legacy versions or suites. A connection policy constrains what a
deployment accepts without silently rewriting that offer.
`ClientBuilder::server_authentication` defaults to WebPKI certificate-chain and
hostname verification. Its explicit disabled mode is limited to controlled
TCP TLS conformance, cannot be combined with additional roots or HTTP/3, and
does not change the profile's wire offer.

Profile-policy conflicts will fail before network I/O. This keeps packet
differentials honest and prevents a pool from treating two different wire
identities as equivalent. The complete boundary and threat-review checklist
are documented in [TLS security boundary](tls-security-boundary.md).

## HTTP/3 QPACK policy

HTTP/3 TLS is a separate profile component rather than an adaptation of the
TCP offer. The connector requires TLS 1.3, exact `h3` ALPN, QUIC-compatible
cipher suites, and no ticket behavior that the current QUIC path cannot
represent. Two retained Chrome H3 ClientHellos define the distinct built-in
offer, including H3 ALPS (`0x44cd`). The current local offer is empty; a custom
nonempty offer is rejected until it can be correlated with local H3 and QPACK
state. Authenticated peer settings preserve absent, empty, and nonempty states.
A nonempty peer value may contain at most one valid H3 SETTINGS frame, which is
applied before requests can start. Unknown ALPS frames are ignored, while
known-forbidden frames are rejected. A later control-stream SETTINGS may
repeat compatible values or increase limits when it is the stream's first
frame, but cannot reduce or conflict with the ALPS state. Caller-authored H3
TLS uses the same typed validation path without silently inheriting the TCP
ClientHello.

`Http3Settings::qpack_encoding` chooses `Stateless` or `Dynamic` request-field
encoding for a connection. Dynamic mode is profile data because it changes
the encoder stream and HEADERS bytes. The engine owns the mutable table,
settings synchronization, backpressure, and cancellation; callers do not
receive low-level table controls. Stateless remains available for custom or
uncaptured stacks and never silently replaces a requested dynamic mode.

`Http3Settings::qpack_decoder_stream` independently controls when the local
decoder stream becomes visible. `Eager` writes its stream type during
connection startup. `OnFeedback` reserves the same critical stream but writes
its type only when any decoder feedback exists, including insert-count
increments, section acknowledgements, or stream cancellations. The Chrome 152
macOS recipe selects `OnFeedback` because its request-boundary capture had no
decoder-stream bytes; other profiles keep an explicit policy rather than
inheriting Chrome behavior from the transport.

## Lessons from adjacent clients

The projects below are references, not APIs to copy wholesale. Their useful
controls fall into distinct ownership domains. The pinned source, public API,
and pull-request evidence behind these summaries is recorded in the
[ecosystem architecture and pull-request audit](ecosystem-architecture-pr-audit.md).

| Project | Useful exposed controls | Phantom decision |
| --- | --- | --- |
| [HttpCloak](https://github.com/sardanioss/httpcloak) | profile selection, exact H1/H2/H3, ECH source, retries, redirects, streaming, auth, ordered headers, sessions, separate TCP/UDP routes, SOCKS and MASQUE | Keep exact protocol and explicit UDP route capability. Split profile, route, session, and request policy rather than one option bag. |
| [hellojs](https://github.com/unreleased/hellojs) | phase timeouts, CONNECT proxy, pooling, retry, early data, verification, lifecycle events, Peet profile import, forced/disabled H3 | Adopt phase-aware deadlines and import tooling only when the retained data can be validated. Early data requires replay policy; verification is never silently disabled by a profile. |
| [`wreq`](https://github.com/0x676e67/wreq) | Tokio/Compio runtimes, encodings, cookies, forms, DNS, SOCKS, stream and WebSocket features; custom executor/timer, protocol and socket tuning, proxy/no-proxy, pools, TLS stores, key logging | Use its separation of compile-time capabilities from runtime policy as a reference. Do not advertise a second runtime until Phantom has a real implementation and test matrix for it. |
| [`tls-client`](https://github.com/bogdanfinn/tls-client) | custom JA3/profile data, header order, protocol racing, session tickets, proxy, H3 switches | Preserve ordered data and explicit racing policy, but make pool/route identity structural and avoid loosely coupled fingerprint strings. |
| [BrowserOxide](https://github.com/yfedoseev/browser_oxide) | shared cookie, session, and learned client-hint state; budgets; proxy and runtime controls | Session state is an explicit owned object. Client hints are not stored in an immutable wire profile. Browser-engine features outside HTTP remain out of scope. |
| [Obscura](https://github.com/h4ckf0r0day/obscura) | browser-level profile, proxy, and operational controls | Reuse lifecycle and isolation lessons, not its browser/CLI surface. |
| [cronet-rs](https://github.com/sleeyax/cronet-rs) | native Cronet callbacks and async adaptation | Keep as a lifecycle caution and comparison target; do not make Cronet Phantom's engine. |
| [Curlium](https://scrapfly.io/curlium) | vendor-described patched curl/BoringSSL/nghttp2/nghttp3/ngtcp2 client | Confirms the engine-adapter direction, but public claims alone are not source or packet evidence. |
| [Prism](https://github.com/WeAreMaven/prism) | passive TCP, TLS, HTTP, and QUIC fingerprints; bounded capture deadlines, concurrency, body, buffer, and drain limits | Use as an independent observation/differential input. Its knobs inform `phantom-testkit`, not the outbound client API, and its summaries do not define parity. |
| [uTLS](https://github.com/refraction-networking/utls) | versioned and randomized ClientHello IDs, ordered custom extensions, captured-hello import, session/PSK controls, ALPS, ECH, and QUIC hooks | Keep versioned typed recipes and ordered extensions. Resolve correlated randomness once per connection; do not replay opaque hellos or fork a full language TLS stack. |
| [AzureTLS](https://github.com/Noooste/azuretls-client) | session API, TLS/H2/H3 profiles, cookies, proxies, ordered headers, WebSocket, redirects, pinning, and protocol forcing | Keep the approachable session facade, but preserve protocol-component ownership and strict validation. H3 customization, idle reuse, and GOAWAY behavior require lifecycle tests rather than broad support flags. |

Controls are added in end-to-end slices. For example, `socks` is not complete
when a URI parser exists: route identity, DNS ownership, authentication,
cancellation, pooling, local fixtures, and failure-without-direct-leakage must
all be proven. The same rule applies to `http3`, `cookies`, `stream`, `sse`,
and `websocket`.

## Custom stacks

Chromium, Firefox, Safari, OkHttp, curl, language runtimes, and private clients
all use the same browser-neutral profile types. Family and platform are
metadata for provenance and selection; they do not select backend code.

A recipe name such as `v152_macos_tls()` states where the evidence was
captured. It does not claim that the represented TLS settings inherently
differ by operating system. Once captures from other supported systems prove
identical component data, they may share one internal value while retaining
their exact provenance. Differences remain separate data, not `cfg(target_os)`
branches in transport code.

The finite typed profile vocabulary is intentional. A new observed field gets
a named meaning, validation, backend capability check, and differential. An
opaque arbitrary-byte escape hatch would make configuration look flexible
while bypassing those guarantees.

Normalization is fixture policy rather than caller configuration. Allowing a
runtime ignore-list would make a differential easy to pass by hiding a new
wire difference. Capture tools may expose resource limits and completion
conditions, but the retained fixture records exactly which nondeterministic
fields its versioned comparison normalizes.
