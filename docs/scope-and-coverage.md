# Scope and coverage

Phantom reproduces observable HTTP-client behavior. It is not a browser DOM,
JavaScript, rendering, canvas, font, WebRTC, or device-fingerprint engine.
Within the HTTP stack, coverage is layered so a TLS match is never presented as
a complete client match.

| Layer | Current | Planned |
| --- | --- | --- |
| TLS over TCP | Typed ordered profiles; fixture-backed Chrome, Firefox, and Safari macOS recipes; certificate and hostname verification; ALPN and ALPS | More versions/platform captures, session resumption, ticket policy, generic imported stacks |
| HTTP/1.1 | Ordered request fields, streaming/backpressured responses, cancellation tests | Pooling, redirects/retries, proxies, WebSocket Upgrade |
| HTTP/2 | Ordered SETTINGS, window update, pseudo/header order, priority, ALPS peer settings, streaming flow control | Reusable sessions, richer request bodies, extended CONNECT where evidence requires it |
| QUIC | BoringSSL-backed Quinn client handshake, packet/header protection, key updates, Retry and endpoint HMAC; typed captured transport settings | Profile-driven exact transport-parameter serializer, reusable connection lifecycle, packet differential |
| HTTP/3 | Forced direct one-shot request; exact `h3` ALPN; typed ordered SETTINGS; Chrome nonzero inbound QPACK, randomized GREASE, and H3 DATAGRAM policy; bounded dynamic response decode; streaming data/trailers; body cancellation and bounded shutdown | Outbound dynamic QPACK and captured request parity, multiplexed sessions, extension-specific datagram APIs, qlog; UDP proxies later |
| Session policy | Caller-controlled ordered headers only | Cookies, redirects, retries, client-hint state, tickets, Alt-Svc, pooling |
| Higher protocols | Ordinary streaming response body | SSE and H1 WebSocket first; later extended CONNECT/H3 only from evidence |
| Routes | Direct paths in current slices | HTTP(S) proxy, SOCKS5 local/remote DNS, UDP ASSOCIATE, then CONNECT-UDP/MASQUE |
| Validation | Local TLS/H2/QUIC fixtures, hostile H1/H2 peers, Peet/Pingly as supplemental observers | Decrypted packet differentials, Prism comparison, fuzzing, sanitizers, long soaks |

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
