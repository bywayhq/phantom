# Scope and coverage

Phantom reproduces observable HTTP-client behavior. It is not a browser DOM,
JavaScript, rendering, canvas, font, WebRTC, or device-fingerprint engine.
Within the HTTP stack, coverage is layered so a TLS match is never presented as
a complete client match.

| Layer | Current | Planned |
| --- | --- | --- |
| TLS over TCP | Typed ordered profiles; fixture-backed Chrome, Firefox, and Safari macOS recipes; certificate and hostname verification; ALPN and ALPS | More versions/platform captures, session resumption, ticket policy, generic imported stacks |
| HTTP/1.1 | Ordered request fields; response field order, duplicate interleaving, and name spelling; streaming/backpressured responses; cancellation tests; direct, plaintext HTTP CONNECT, and remote-DNS SOCKS5 routes; byte-preserving Upgrade handoff | Pooling, redirects/retries, forwarding and additional proxy modes |
| HTTP/2 | Ordered SETTINGS, request and response fields, window update, pseudo-header order, priority, ALPS peer settings, streaming flow control; session-owned exact-origin/route reuse with sequential/concurrent streams and stream-scoped cancellation | GOAWAY admission and draining, peer/local stream admission, bounded waiters, richer request bodies, extended CONNECT where evidence requires it |
| QUIC | BoringSSL-backed Quinn client handshake, packet/header protection, key updates, live Retry, and endpoint HMAC; typed captured transport settings; seeded exact transport-parameter serializer with randomized permitted order and GREASE; bounded opt-in NSS key-log queue; payload-free QUIC v1 packet analyzer and packetization-independent logical-flight comparator; controlled Chrome/Phantom decrypted captures through the first request | Reusable connection lifecycle, repeated packet-shape stability study |
| HTTP/3 | Forced direct one-shot request; exact `h3` ALPN; typed ordered SETTINGS plus request and response fields; Chrome nonzero inbound QPACK, randomized GREASE, H3 DATAGRAM, and deferred decoder-stream policy; bounded dynamic response decode and connection-owned request encode; live capture-matching QPACK stream and HEADERS bytes; streaming data/trailers and chained informational responses; exact hostile-peer close-code tests; body cancellation and bounded shutdown; single-connection bounded qlog | Multiplexed sessions, repeated fresh-browser packet differentials, extension-specific datagram APIs; UDP proxies later |
| Public client | Cheap-clone immutable exact-H1/H2/H3 facade; owned request builders; protocol-specific TCP and QUIC TLS settings; additive DER trust roots; default/per-request routes; unified streaming body; ordered response metadata; typed errors | Broader methods/bodies and negotiated protocol policy only after evidence |
| Session policy | Cloneable isolated session; bounded H2 retained pool; optional bounded cookie jar with deterministic path/creation order, PSL/prefix/expiry checks, and explicit activation | H1/H3 reuse, redirects, retries, SameSite request context, CHIPS, client hints, tickets, DNS/Alt-Svc state |
| Higher protocols | Ordinary streaming response body; feature-gated bounded SSE decoder with WHATWG field semantics; feature-gated WSS/H1 with ordered customizable handshake, direct/CONNECT/SOCKS5h routes, session cookies, bounded messages, `Stream`/`Sink`, and strict 101 validation | SSE reconnect/session policy; WebSocket compression/extensions, automatic reconnect, H2 extended CONNECT, and H3 only from evidence |
| Routes | Direct TCP/UDP paths; plaintext HTTP CONNECT and no-auth remote-DNS SOCKS5 for H1/H2 origin TLS with typed negotiation and no direct fallback; H2 pool identity includes the complete route; H3 rejects both TCP-only routes before I/O | HTTP forwarding, HTTPS proxy, SOCKS5 local DNS/authentication and UDP ASSOCIATE, then CONNECT-UDP/MASQUE |
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
