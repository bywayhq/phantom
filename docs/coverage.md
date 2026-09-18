# Scope and coverage

Phantom reproduces observable HTTP-client behavior. It is not a browser DOM,
JavaScript, rendering, canvas, font, WebRTC, or device-fingerprint engine.
Within the HTTP stack, coverage is layered so a TLS match is never presented as
a complete client match.

| Layer | Current | Planned |
| --- | --- | --- |
| TLS over TCP | Typed ordered profiles; fixture-backed Chrome, Firefox, and Safari macOS recipes; certificate and hostname verification; ALPN and ALPS; bounded client-owned H1/H2 ticket caches with exact origin/route partitioning and no early data | More versions/platform captures, public ticket policy, generic imported stacks |
| HTTP/1.1 | Ordered request fields and static trailers; ordinary methods with owned-byte or pull-driven streaming bodies; exact content-length validation; response field order, duplicate interleaving, and name spelling; streaming/backpressured responses; client-owned sequential keep-alive reuse with bounded waiters and no pipelining; finite opt-in HTTPS redirects; opt-in typed pre-dispatch connection retries; direct HTTPS and plaintext HTTP; absolute-form forwarding for `http://` origins over plaintext or TLS proxies, including one fresh-connection replay after a strict, valid Basic challenge; HTTP/HTTPS CONNECT and local-/remote-DNS SOCKS5 routes; byte-preserving Upgrade handoff | Streaming-body-produced trailers, parallel connection policy, broader retry classes, and additional proxy modes |
| HTTP/2 | Ordered SETTINGS, request and response fields, static request trailers, window update, pseudo-header order, priority, ALPS peer settings and connection-scoped `ACCEPT_CH`, flow-controlled owned or pull-driven request bodies and streaming responses; client-owned exact-origin/route reuse with bounded local active work and waiters, peer stream-limit enforcement, stream-scoped cancellation, opt-in typed pre-dispatch connection retries, and one replacement-connection retry for a bodyless GET rejected by `GOAWAY(NO_ERROR)` | Streaming-body-produced trailers, broader retry classes, and extended CONNECT where evidence requires it |
| QUIC | BoringSSL-backed Quinn client handshake, packet/header protection, key updates, live Retry, and endpoint HMAC; typed captured transport settings; seeded exact transport-parameter serializer with randomized permitted order and GREASE; H3-owned reusable connection lifecycle; bounded opt-in NSS key-log queue; payload-free QUIC v1 packet analyzer and packetization-independent logical-flight comparator; controlled Chrome/Phantom decrypted captures through the first request | Generic non-H3 connection API, repeated packet-shape stability study |
| HTTP/3 | Forced direct request; exact `h3` ALPN and Chrome H3 ALPS offer; authenticated peer application SETTINGS plus strict connection-scoped `ACCEPT_CH` decoding and handoff; ordinary methods with flow-controlled owned or pull-driven request bodies and ordered static trailers; client-owned multiplexed reuse with bounded active work and waiters; opt-in typed pre-dispatch DNS/endpoint/QUIC setup retries; typed ordered SETTINGS plus request and response fields; Chrome nonzero inbound QPACK, randomized GREASE, H3 DATAGRAM, and deferred decoder-stream policy; bounded dynamic response decode and connection-owned request encode; live capture-matching QPACK stream and HEADERS bytes; streaming data/trailers and chained informational responses; exact hostile-peer close-code tests; stream-scoped cancellation and bounded shutdown; single-connection bounded qlog | Live BoringSSL-server H3 `ACCEPT_CH` request differential, nonempty local H3 application settings, streaming-body-produced trailers, repeated fresh-browser packet differentials, extension-specific datagram APIs; UDP proxies later |
| Public client | Cheap-clone pooled exact-H1/H2/H3 facade; pooled direct H1/H2 selection with one current ALPN-selected TCP/TLS generation per origin; owned request builders with explicit methods, ordered static trailers on exact H1/H2/H3 and negotiated H1/H2, owned-byte or pull-driven streaming bodies, and default/per-request exact-protocol connection retry policies; one WHATWG/IDNA endpoint boundary shared by wire authority and state keys; protocol-specific TCP and QUIC TLS settings; additive DER trust roots; default/per-request routes; unified streaming response body; selected protocol, ordered fields, redirect count, and setup-retry count metadata; typed errors | Streaming-body-produced trailers, negotiated-protocol retries, status/post-dispatch retry policy, Alt-Svc/H3 upgrade, and evidence-backed racing policy |
| Cross-request state | Bounded H1, H2, and direct-H3 retained pools with per-origin-and-route active and waiting admission; one request-scoped bounded pre-dispatch setup-retry budget across redirect and internal replacement attempts; bounded H1/H2 TLS ticket retention; optional bounded cookie jar with deterministic path/creation order, PSL/prefix/expiry checks, and explicit activation; profile-defined client-hint fields with bounded exact-origin response `Accept-CH` state, connection-scoped H2/H3 ALPS `ACCEPT_CH`, and one bounded `Critical-CH` retry for safe methods; opt-in finite redirects with WHATWG resolution, browser method/body transitions, and cross-origin credential and client-hint removal; bounded graceful-H2-GOAWAY retry | SameSite request context, CHIPS, permissions/delegation context, QUIC tickets, DNS/Alt-Svc state, and broader retry classes |
| Higher protocols | Ordinary streaming response body; feature-gated bounded SSE decoder plus finite client-owned reconnects with `Last-Event-ID`, server retry delay, optional cancellation-safe DATA-activity idle timeout, cookies, and 204 termination; feature-gated WS/H1 with direct plaintext plus direct/HTTP(S)-CONNECT/SOCKS5 TLS routes, ordered customizable handshake, typed opt-in `permessage-deflate`, client cookies, bounded messages, `Stream`/`Sink`, and strict 101 validation | SSE jitter and broader browser reconnect differentials; proxied plaintext WebSocket, other WebSocket extensions, named compression/send policies, automatic reconnect, H2 extended CONNECT, and H3 only from evidence |
| Routes | Direct HTTPS/H1/H2, plaintext HTTP/H1, and H3/QUIC paths; HTTP/1.1 absolute-form forwarding for `http://` origins over plaintext or TLS-encrypted proxies, including challenge-driven Basic with an anonymous first request and exactly one replay on a fresh same-route connection; HTTP/1.1 CONNECT over plaintext or independently authenticated TLS proxies, including one bounded challenge-driven Basic retry; credential-capable RFC 1929 local-/remote-DNS SOCKS5 for H1/H2 origin TLS and H1 WSS; canonical Unicode proxy and origin hosts, typed negotiation, and no direct fallback; forwarding never changes to CONNECT or another protocol; HTTPS proxy and origin trust and ticket caches are isolated; H1/H2 pool identity includes the origin and complete route; H3 rejects all TCP-only routes before I/O | Other proxy authentication schemes and learned challenge state, H2 proxy transport, custom SOCKS5 resolvers, SOCKS5 UDP ASSOCIATE, then CONNECT-UDP/MASQUE |
| Validation | Local TLS/H2/QUIC fixtures, hostile H1/H2/H3 peers, bounded qlog/key-log seams, deterministic authenticated QUIC packet analysis, two fresh-profile Chrome H3 ClientHellos, controlled Chrome/Phantom packet evidence, and scheduled ASan-backed fuzzing of Phantom's ClientHello and H2 frame decoders; Peet/Pingly are supplemental observers | Repeated packet-shape study, Prism comparison, broader protocol fuzzing, native-adapter sanitizers, long soaks |

“Support” means the entire row's relevant lifecycle works: configuration,
validation, emission, response behavior, cancellation, errors, observability,
and deterministic tests. Merely parsing an option or connecting successfully
does not count.

## Client hints and `Accept-CH`

`ClientHintSettings` is immutable profile data: it supplies ordered names,
values, and default-versus-negotiated delivery. A client owns the mutable
response `Accept-CH` selection. The Chrome 152 macOS recipe is backed by a local
navigation capture; Firefox and Safari recipes do not acquire Chromium client
hints by family-name branching.

For H1, H2, and H3 responses, a valid `Accept-CH` structured-field list
replaces the exact HTTPS origin's selection, an empty or unsupported-only list
clears it, absence leaves it unchanged, and malformed input is ignored.
Origin keys include the effective port. Client clones share the bounded LRU;
independently built clients do not. `Client::clear_client_hints` clears
all retained selections. Caller-supplied configured hint fields win in their
existing positions, while automatic fields retain profile order.

For H2 and H3, a peer ALPS `ACCEPT_CH` entry is immutable metadata on that
connection. Exact canonical origin matching augments the response-learned
selection after connection choice, so the first request can carry requested
fields without a warm-up request. Duplicate origins keep the first valid
entry. Non-canonical origins are ignored and retained distinct origins are
capped at 1,024 per connection. This metadata is never copied into the client
cache, does not cross a replacement connection, and does not clear
response-learned state when its value is empty or malformed.

The first-request behavior has a live BoringSSL H2 integration test. H3 is
covered by the BoringSSL QUIC ALPS round trip, strict frame decoder, immutable
connection handoff, and shared request-selection tests; a live BoringSSL-server
H3 request differential remains a separate validation gate.

`Critical-CH` can cause one internal retry when a supported requested field was
missing and the HTTP method is safe. The current request body is owned
bytes and can be replayed exactly; the retry never changes protocol or route. A
repeated demand cannot loop.
Intermediate redirect responses are learned before the next hop, and
configured caller hint fields are removed at a cross-origin boundary before
the new origin's automatic set is built.

This is a raw-client, top-level request policy. Permissions Policy delegation,
subresource browsing context, persistence, expiry beyond explicit replacement,
full-navigation restart across an already-followed redirect chain, and live
post-handshake `ACCEPT_CH` frames remain absent. Those require distinct public
context or engine evidence; they are not inferred from a browser name.
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
