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
| HTTP/3 | Forced direct request; exact `h3` ALPN and Chrome H3 ALPS offer; authenticated peer application settings applied before request startup; ordinary methods with flow-controlled owned byte bodies; session-owned multiplexed reuse with bounded active work and waiters; typed ordered SETTINGS plus request and response fields; Chrome nonzero inbound QPACK, randomized GREASE, H3 DATAGRAM, and deferred decoder-stream policy; bounded dynamic response decode and connection-owned request encode; live capture-matching QPACK stream and HEADERS bytes; streaming data/trailers and chained informational responses; exact hostile-peer close-code tests; stream-scoped cancellation and bounded shutdown; single-connection bounded qlog | Nonempty local H3 application settings, streaming request bodies, repeated fresh-browser packet differentials, extension-specific datagram APIs; UDP proxies later |
| Public client | Cheap-clone immutable exact-H1/H2/H3 facade; owned request builders with explicit methods and optional owned byte bodies; protocol-specific TCP and QUIC TLS settings; additive DER trust roots; default/per-request routes; unified streaming response body; ordered response metadata plus redirect outcome metadata; typed errors | Streaming request bodies and negotiated protocol policy only after evidence |
| Session policy | Cloneable isolated session; bounded H1, H2, and direct-H3 retained pools with per-origin-and-route active and waiting admission; bounded H1/H2 TLS ticket retention; optional bounded cookie jar with deterministic path/creation order, PSL/prefix/expiry checks, and explicit activation; profile-defined client-hint fields with bounded exact-origin `Accept-CH` state and one bounded `Critical-CH` retry; opt-in finite redirects with WHATWG resolution, browser method/body transitions, and cross-origin credential and client-hint removal; bounded graceful-H2-GOAWAY retry | Configurable general retry policy, SameSite request context, CHIPS, ALPS `ACCEPT_CH`, permissions/delegation context, QUIC tickets, DNS/Alt-Svc state |
| Higher protocols | Ordinary streaming response body; feature-gated bounded SSE decoder plus finite session-owned reconnects with `Last-Event-ID`, server retry delay, cookies, and 204 termination; feature-gated WSS/H1 with ordered customizable handshake, direct/CONNECT/SOCKS5 routes, session cookies, bounded messages, `Stream`/`Sink`, and strict 101 validation | SSE idle timeout, jitter, and broader browser reconnect differentials; WebSocket compression/extensions, automatic reconnect, H2 extended CONNECT, and H3 only from evidence |
| Routes | Direct TCP/UDP paths; plaintext HTTP CONNECT and no-auth local-/remote-DNS SOCKS5 for H1/H2 origin TLS with typed negotiation and no direct fallback; H1/H2 pool identity includes the complete route and DNS mode; H3 rejects both TCP-only routes before I/O | HTTP forwarding, HTTPS proxy, SOCKS5 authentication and UDP ASSOCIATE, then CONNECT-UDP/MASQUE |
| Validation | Local TLS/H2/QUIC fixtures, hostile H1/H2/H3 peers, bounded qlog/key-log seams, deterministic authenticated QUIC packet analysis, two fresh-profile Chrome H3 ClientHellos, controlled Chrome/Phantom packet evidence, and a versioned Reaper probe mapping checked in CI; Peet/Pingly are supplemental observers | Repeated packet-shape study, Prism comparison, fuzzing, sanitizers, long soaks |

“Support” means the entire row's relevant lifecycle works: configuration,
validation, emission, response behavior, cancellation, errors, observability,
and deterministic tests. Merely parsing an option or connecting successfully
does not count.

## Client hints and `Accept-CH`

`ClientHintSettings` is immutable profile data: it supplies ordered names,
values, and default-versus-negotiated delivery. A session owns the mutable
`Accept-CH` selection. Bare-client requests emit only default fields and retain
nothing. The Chrome 152 macOS recipe is backed by a local navigation capture;
Firefox and Safari recipes do not acquire Chromium client hints by family-name
branching.

For H1, H2, and H3 responses, a valid `Accept-CH` structured-field list
replaces the exact HTTPS origin's selection, an empty or unsupported-only list
clears it, absence leaves it unchanged, and malformed input is ignored.
Origin keys include the effective port. Session clones share the bounded LRU;
separately constructed sessions do not. `Session::clear_client_hints` clears
all retained selections. Caller-supplied configured hint fields win in their
existing positions, while automatic fields retain profile order.

`Critical-CH` can cause one internal retry when a supported requested field was
missing and the HTTP method is idempotent. The current request body is owned
bytes and can be replayed exactly; the retry never changes protocol or route. A
repeated demand cannot loop.
Intermediate redirect responses are learned before the next hop, and
configured caller hint fields are removed at a cross-origin boundary before
the new origin's automatic set is built.

This is a raw-client, top-level request policy. Permissions Policy delegation,
subresource browsing context, persistence, expiry beyond explicit replacement,
full-navigation restart across an already-followed redirect chain, and
transport-delivered ALPS `ACCEPT_CH` remain absent. Those require distinct
public context or engine evidence; they are not inferred from a browser name.
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
