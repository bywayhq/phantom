# Scope and coverage

Phantom reproduces observable HTTP-client behavior. It is not a browser DOM,
JavaScript, rendering, canvas, font, WebRTC, or device-fingerprint engine.
Within the HTTP stack, coverage is layered so a TLS match is never presented as
a complete client match.

| Layer | Current | Planned |
| --- | --- | --- |
| TLS over TCP | Typed ordered profiles; fixture-backed Chrome, Firefox, and Safari macOS recipes; certificate and hostname verification; ALPN and ALPS; bounded session-owned H1/H2 ticket caches with exact origin/route partitioning and no early data | More versions/platform captures, public ticket policy, generic imported stacks |
| HTTP/1.1 | Ordered request fields; ordinary methods with optional owned byte bodies; exact content-length validation; response field order, duplicate interleaving, and name spelling; streaming/backpressured responses; session-owned sequential keep-alive reuse with bounded waiters and no pipelining; finite opt-in redirects; direct, plaintext HTTP CONNECT, and local-/remote-DNS SOCKS5 routes; byte-preserving Upgrade handoff | Streaming request bodies, parallel connection policy, retries, forwarding and additional proxy modes |
| HTTP/2 | Ordered SETTINGS, request and response fields, window update, pseudo-header order, priority, ALPS peer settings, flow-controlled owned request bodies and streaming responses; session-owned exact-origin/route reuse with bounded local active work and waiters, peer stream-limit enforcement, stream-scoped cancellation, and one replacement-connection retry for a bodyless GET rejected by `GOAWAY(NO_ERROR)` | Streaming request bodies, configurable general retry policy, and extended CONNECT where evidence requires it |
| QUIC | BoringSSL-backed Quinn client handshake, packet/header protection, key updates, live Retry, and endpoint HMAC; typed captured transport settings; seeded exact transport-parameter serializer with randomized permitted order and GREASE; H3-owned reusable connection lifecycle; bounded opt-in NSS key-log queue; payload-free QUIC v1 packet analyzer and packetization-independent logical-flight comparator; controlled Chrome/Phantom decrypted captures through the first request | Generic non-H3 connection API, repeated packet-shape stability study |
| HTTP/3 | Forced direct request; exact `h3` ALPN; ordinary methods with flow-controlled owned byte bodies; session-owned multiplexed reuse with bounded active work and waiters; typed ordered SETTINGS plus request and response fields; Chrome nonzero inbound QPACK, randomized GREASE, H3 DATAGRAM, and deferred decoder-stream policy; bounded dynamic response decode and connection-owned request encode; live capture-matching QPACK stream and HEADERS bytes; streaming data/trailers and chained informational responses; exact hostile-peer close-code tests; stream-scoped cancellation and bounded shutdown; single-connection bounded qlog | Streaming request bodies, repeated fresh-browser packet differentials, extension-specific datagram APIs; UDP proxies later |
| Public client | Cheap-clone immutable exact-H1/H2/H3 facade; owned request builders with explicit methods and optional owned byte bodies; protocol-specific TCP and QUIC TLS settings; additive DER trust roots; default/per-request routes; unified streaming response body; ordered response metadata plus redirect outcome metadata; typed errors | Streaming request bodies and negotiated protocol policy only after evidence |
| Session policy | Cloneable isolated session; bounded H1, H2, and direct-H3 retained pools with per-origin-and-route active and waiting admission; bounded H1/H2 TLS ticket retention; optional bounded cookie jar with deterministic path/creation order, PSL/prefix/expiry checks, and explicit activation; opt-in finite redirects with WHATWG resolution, browser method/body transitions, and cross-origin credential removal; bounded graceful-H2-GOAWAY retry | Configurable general retry policy, SameSite request context, CHIPS, client hints, QUIC tickets, DNS/Alt-Svc state |
| Higher protocols | Ordinary streaming response body; feature-gated bounded SSE decoder with WHATWG field semantics; feature-gated WSS/H1 with ordered customizable handshake, direct/CONNECT/SOCKS5 routes, session cookies, bounded messages, `Stream`/`Sink`, and strict 101 validation | SSE reconnect/session policy; WebSocket compression/extensions, automatic reconnect, H2 extended CONNECT, and H3 only from evidence |
| Routes | Direct TCP/UDP paths; plaintext HTTP CONNECT and no-auth local-/remote-DNS SOCKS5 for H1/H2 origin TLS with typed negotiation and no direct fallback; H1/H2 pool identity includes the complete route and DNS mode; H3 rejects both TCP-only routes before I/O | HTTP forwarding, HTTPS proxy, SOCKS5 authentication and UDP ASSOCIATE, then CONNECT-UDP/MASQUE |
| Validation | Local TLS/H2/QUIC fixtures, hostile H1/H2/H3 peers, bounded qlog/key-log seams, deterministic authenticated QUIC packet analysis, controlled Chrome/Phantom packet evidence, Peet/Pingly as supplemental observers; no retained browser H3 ClientHello fixture yet | Repeated packet-shape study, browser H3 ClientHello capture, Prism comparison, fuzzing, sanitizers, long soaks |

“Support” means the entire row's relevant lifecycle works: configuration,
validation, emission, response behavior, cancellation, errors, observability,
and deterministic tests. Merely parsing an option or connecting successfully
does not count.

## Client hints and `Accept-CH`

`Accept-CH` is not a TLS-profile field. It is response-driven, origin-scoped
session policy which can affect later request headers. Phantom currently does
not learn or emit client hints automatically. Callers may provide ordered
headers explicitly, and Phantom preserves them.

A browser-like client-hint slice must include all of the following before it is
enabled:

1. accept `Accept-CH` only in the applicable secure-origin context;
2. store the learned hint set by origin in the session, with explicit clearing
   and isolation semantics;
3. apply only supported hint values and preserve their profile-defined order;
4. process redirects without leaking learned hints across origins;
5. honor delegation/permissions rules for subresource-style requests if that
   request mode is exposed;
6. handle `Critical-CH` with at most one internal retry, and only when the
   method and body are replayable;
7. feed HTTP/2 or HTTP/3 `ACCEPT_CH`/ALPS delivery into the same state machine
   rather than creating transport-specific caches;
8. test cache replacement, expiry/clearing, redirect boundaries, retry loops,
   pooling, and concurrent requests against retained browser observations.

The initial public policy should remain explicit: manual headers with no
learning, or a session-owned browser policy once that complete path exists.
There is no process-global hint cache and no immutable profile mutation.

The differential for this feature is an ordered session transcript, not one
fingerprint hash. Connection observations retain TLS and H2/H3 startup state;
request observations retain ordered headers, the response stimulus, the next
request's changes, retry outcome, and connection reuse. That makes the
`Accept-CH` response-to-request transition and origin boundary visible.

## Platform provenance

TLS, H2, and QUIC protocol settings are generally portable data. Capture
provenance is platform-specific because browser builds, system integrations,
launch conditions, and release channels can change emitted bytes. Therefore a
recipe whose name includes `macos` means “observed on macOS,” not “selected by
`target_os = macos`.”

Cross-platform capture decides whether two recipes share component data. The
runtime consumes the validated settings it receives and does not branch on the
host OS or client-family name. OS-specific code is reserved for real socket,
trust-store, native-build, or profiling differences.

## Claim boundary

Local raw captures and packet/frame differentials are the primary evidence.
Pingly, Peet, and Prism are independent observers that can reveal missing
signals, but none is a sole pass/fail oracle. Phantom reports the concrete
fields and behaviors covered by a test; it does not attach ceremonial
“verified” labels to an entire profile.
