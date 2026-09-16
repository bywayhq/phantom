# Configuration model

Phantom exposes behavior by ownership, not as one large builder. A setting is
public only when the implementation can validate it before I/O and an
observable test proves what it changes. Built-in recipes and caller-authored
settings use the same concrete types.

```mermaid
flowchart LR
    Profile["Wire profile\nTLS · H1 · H2 · QUIC · H3"]
    Session["Session policy\ncookies · client hints · redirects · tickets"]
    Route["Route policy\ndirect · proxy · DNS · local bind"]
    Request["Request policy\ntimeouts · retry · protocol · ordered headers"]
    Runtime["Runtime services\nTokio · resolver · clock · entropy"]
    Diagnostics["Diagnostics\ntracing · qlog · key log"]
    Validate["Validate and resolve"]
    Attempt["One owned attempt"]

    Profile --> Validate
    Session --> Validate
    Route --> Validate
    Request --> Validate
    Runtime --> Validate
    Diagnostics --> Validate
    Validate --> Attempt
```

This keeps unrelated lifetimes separate. A TLS cipher list is immutable
profile data. A learned `Accept-CH` value is mutable session state. Proxy
credentials belong to a route. A per-request timeout does not mutate the
client. The runtime owns connection IDs, entropy, clocks, and task execution;
captured profiles describe their policy but never retain captured random
bytes.

## Public shape

The facade grows through three ordinary levels:

- `ClientBuilder` currently owns one immutable profile, additive trust roots,
  and a default `Route` (`Direct`, plaintext HTTP CONNECT, or local-/remote-DNS
  SOCKS5). Later slices add runtime services and pool limits only with their
  implementations.
- `RequestBuilder` currently owns an exact protocol, HTTPS target, and ordered
  fields. It may own a route override; deadline and retry policy remain absent.
- `ClientProfile` owns required TCP TLS, optional H2 settings, and an optional
  atomic H3 bundle containing its own TLS, QUIC transport, H3 connection, and
  H3 request settings. Typed values can be cloned and edited before the client
  is built.

The facade performs a new connection for each request. It synthesizes the H1
`Host` field from the URI, uses the URI authority for H2 and H3, and rejects a
caller-supplied origin `Host` field. A plaintext HTTP CONNECT route has a
separate ordered field sequence with one typed destination-authority
placeholder. Request and CONNECT validation happen before proxy I/O; non-2xx
proxy responses are typed failures and never trigger a direct retry. A
`socks5://` resolves domain origins locally and `socks5h://` resolves them at
the proxy. Both apply to H1, H2, session-owned H1/H2 reuse, and H1 WebSocket.
Selecting H2 or H3 without the
corresponding profile settings also fails before network I/O. H3 currently
supports only `Route::Direct`; pairing it with either TCP-only proxy route is
rejected before either proxy TCP or origin UDP is opened. The response body
implements `http_body::Body` and retains the existing protocol cancellation
behavior when dropped.

There is no global mutable profile registry, environment-only configuration,
browser-family switch inside a transport, or callback invoked while a pool
key is being computed. Resolved configuration is owned so a live connection
cannot change identity underneath the pool.

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
deployment accepts without silently rewriting that offer. Until the public
policy type exists, callers restrict the version range and cipher-suite list
by customizing `TlsSettings` before connector construction.

Profile-policy conflicts will fail before network I/O. This keeps packet
differentials honest and prevents a pool from treating two different wire
identities as equivalent. The complete boundary and threat-review checklist
are documented in [TLS security boundary](tls-security-boundary.md).

## HTTP/3 QPACK policy

HTTP/3 TLS is a separate profile component rather than an adaptation of the
TCP offer. The connector requires TLS 1.3, exact `h3` ALPN, QUIC-compatible
cipher suites, and no ALPS or ticket behavior that the current one-shot path
cannot represent. Phantom deliberately has no built-in Chrome H3 TLS recipe
yet: the Chrome QUIC transport and H3 recipes are capture-backed, but a
retained Chrome H3 ClientHello fixture is still required before those TLS bytes
can be named as a built-in recipe. Caller-authored H3 TLS uses the same typed
validation path without inheriting the TCP ClientHello silently.

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
