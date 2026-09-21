# Scope and coverage

Phantom reproduces observable HTTP-client behavior. It is not a browser DOM,
JavaScript, rendering, canvas, font, WebRTC, or device-fingerprint engine.
Within the HTTP stack, coverage is layered so a TLS match is never presented as
a complete client match.

| Layer | Current | Planned |
| --- | --- | --- |
| TLS over TCP | Typed ordered profiles; fixture-backed Chrome, Firefox, and Safari recipes retained from macOS captures; certificate and hostname verification; ALPN and ALPS; bounded client-owned H1/H2 ticket caches with exact origin/route partitioning and no early data | Browser/version-oriented transport names, more versions/platform captures, public ticket policy, generic imported stacks |
| HTTP/1.1 | Ordered request fields and static or declared streaming-body-produced trailers; ordinary methods with owned-byte or pull-driven streaming bodies; exact content-length validation; response field order, duplicate interleaving, and name spelling; streaming/backpressured responses; client-owned sequential keep-alive reuse with bounded waiters and no pipelining; finite opt-in HTTPS redirects; opt-in typed pre-dispatch connection retries; opt-in replay of idempotent requests once on a fresh connection after a reused keep-alive connection closes before any response byte; direct HTTPS and plaintext HTTP; absolute-form forwarding for `http://` origins over plaintext or TLS proxies, including one fresh-connection replay after a strict, valid Basic challenge; HTTP/HTTPS CONNECT and local-/remote-DNS SOCKS5 routes; byte-preserving Upgrade handoff; at most 8 informational responses before the final head | Parallel connection policy, broader retry classes, and additional proxy modes |
| HTTP/2 | Ordered SETTINGS, request and response fields, static or declared streaming-body-produced request trailers, window update, pseudo-header order, priority, ALPS peer settings and connection-scoped `ACCEPT_CH`, flow-controlled owned or pull-driven request bodies and streaming responses; an incomplete early response keeps the request upload running (RFC 9113 §8.1), and the upload progresses as the caller reads the response body; exact direct WebSocket extended CONNECT with explicit five-field pseudo order, peer capability gating, duplex DATA flow control, and stream-scoped cancellation; client-owned exact-origin/route reuse with bounded local active work and waiters, peer stream-limit enforcement, opt-in typed pre-dispatch connection retries, and one replacement-connection retry for a bodyless GET rejected by `GOAWAY(NO_ERROR)` | Broader retry classes, named-browser extended-CONNECT recipes, and named-browser extended-CONNECT recipes over proxies |
| QUIC | BoringSSL-backed Quinn client handshake, packet/header protection, key updates, live Retry, and endpoint HMAC; typed captured transport settings; seeded exact transport-parameter serializer with randomized permitted order and GREASE; H3-owned reusable connection lifecycle; bounded opt-in NSS key-log queue behind the internal `phantom-quic-btls/keylog` feature (not exposed by `phantom-http`); payload-free QUIC v1 packet analyzer and packetization-independent logical-flight comparator; controlled Chrome/Phantom decrypted captures through the first request | Generic non-H3 connection API, repeated packet-shape stability study |
| HTTP/3 | Forced exact request over direct QUIC or local-/remote-DNS SOCKS5 using optionally authenticated RFC 1928 UDP ASSOCIATE with retained TCP control and route-keyed connection reuse; opt-in bounded Alt-Svc upgrade from negotiated direct HTTPS with automatic canonical explicit-port `Alt-Used` while preserving origin authority, SNI, and authentication identity; remote-DNS DOMAIN targets without local origin lookup and a stable logical QUIC peer; exact `h3` ALPN and Chrome H3 ALPS offer; authenticated peer application SETTINGS plus strict connection-scoped `ACCEPT_CH` decoding and handoff; ordinary methods with flow-controlled owned or pull-driven request bodies and ordered static or declared streaming-body-produced trailers; client-owned multiplexed reuse with bounded active work and waiters; opt-in typed pre-dispatch DNS/endpoint/QUIC setup retries, with loopback recovery tests for a refused direct handshake, a refused SOCKS5 proxy connect, and a refused handshake retried through a fresh SOCKS5 association; typed ordered SETTINGS plus request and response fields; Chrome nonzero inbound QPACK, randomized GREASE, H3 DATAGRAM, and deferred decoder-stream policy; bounded dynamic response decode and connection-owned request encode; live capture-matching QPACK stream and HEADERS bytes; streaming data/trailers and chained informational responses; exact hostile-peer close-code tests; stream-scoped cancellation and bounded shutdown; single-connection bounded qlog behind the internal `phantom-net/qlog` feature (not exposed by `phantom-http`); RFC 9220 extended CONNECT in `phantom-net` for the WebSocket protocol, gated on peer SETTINGS from ALPS or the control stream with no local setting emitted, an explicit five-field pseudo order from a custom profile, a bounded duplex DATA stream with FIN, stream-scoped `H3_REQUEST_CANCELLED` reset and datagram abort, and a readable rejection body | Live BoringSSL-server H3 `ACCEPT_CH` request differential, nonempty local H3 application settings, repeated fresh-browser packet differentials, extension-specific datagram APIs, Alt-Svc racing, WebSocket over H3, multiplexed CONNECT-UDP tunnels on one outer connection, and browser-captured MASQUE recipes |
| Public client | Cheap-clone pooled exact-H1/H2/H3 facade; pooled direct H1/H2 selection with optional later Alt-Svc H3 selection; owned request builders with explicit methods, ordered static or declared streaming-body-produced trailers on exact H1/H2/H3 and negotiated requests, owned-byte or pull-driven streaming bodies, and default/per-request connection retry policies for exact H1/H2/H3 setup and negotiated pre-ALPN TCP setup, opt-in status retry for idempotent requests on caller-listed 408/425/429/5xx statuses with an optional capped `Retry-After` and a request-wide budget; one WHATWG/IDNA endpoint boundary shared by wire authority and state keys; protocol-specific TCP and QUIC TLS settings; additive DER trust roots; default/per-request routes; unified streaming response body with inclusive bounded collection; opt-in streaming decoding of caller-advertised `gzip`/`x-gzip`, `deflate`, `br`, and `zstd` with an inclusive decoded-byte cap, fail-closed chains, and wire-view response fields; selected protocol, ordered fields, redirect count, and setup-retry count metadata; typed errors | replay of H3 requests on streams that were already open when GOAWAY arrived (deliberately excluded: servers disagree on the GOAWAY identifier boundary), and evidence-backed racing policy |
| Cross-request state | Bounded H1, H2, and H3 retained pools with per-origin-and-route active and waiting admission; bounded opt-in exact-origin Alt-Svc store with caller-owned export/import of direct-route snapshots (canonical origin, location, whole-second expiry; revalidated and never extended), exact-origin H2 ALTSVC frame learning on negotiated requests, and per-location H3 connection slots so exact and Alt-Svc H3 do not churn, with `Age`/`ma`, replacement, expiry, `clear`, setup-failure eviction, `421` eviction, and request-scoped automatic `Alt-Used` limited to managed H3 attempts; one request-scoped bounded pre-dispatch setup-retry budget across redirect and internal replacement attempts; bounded H1/H2 TLS ticket retention; optional bounded cookie jar with deterministic path/creation order, PSL/prefix/expiry checks, and explicit activation that rejects rather than stores `SameSite=Lax`, `SameSite=Strict`, `Partitioned`, insecure `SameSite=None`, and `Secure`-over-`http://` cookies; profile-defined client-hint fields with bounded exact-origin response `Accept-CH` state, connection-scoped H2/H3 ALPS `ACCEPT_CH`, and one bounded `Critical-CH` retry for safe methods; opt-in finite redirects for `https://` requests with WHATWG resolution, `https://`-only targets, browser method/body transitions, and cross-origin credential and client-hint removal (a client with a redirect policy rejects `http://` requests before I/O); bounded per-origin negotiated pre-selection admission converted to H1/H2 admission after ALPN; bounded graceful-H2-GOAWAY retry for exact and negotiated H2; opt-in unprocessed-request replay (H2 `REFUSED_STREAM` or GOAWAY above the stream, H3 `H3_REQUEST_REJECTED` or GOAWAY before the stream opened) for any method with an absent or owned body, on a different connection with the same route and protocol | SameSite request context, CHIPS, permissions/delegation context, QUIC tickets, DNS state, Alt-Svc racing, proxy-route snapshots, and broader policy, and broader retry classes |
| Higher protocols | Ordinary streaming response body; feature-gated bounded SSE decoder plus finite client-owned reconnects with a caller-positionable `Last-Event-ID` placeholder, server retry delay with an optional minimum, optional cancellation-safe DATA-activity idle timeout, cookies, and 204 termination, with differential tests that replay retained Chrome 153 and Firefox 156 Windows HTTP/1.1 captures; feature-gated WS/H1 over its direct and proxy routes plus exact WS/H2 extended CONNECT over direct, HTTP CONNECT (plaintext or TLS proxy, HTTP/1.1 or HTTP/2 proxy transport, one Basic replay on a fresh proxy connection), and local-/remote-DNS SOCKS5 routes for explicit custom profiles, with the peer capability gate and no route or H1 fallback; ordered customizable handshakes, challenge-driven forward-proxy Basic authentication, typed opt-in `permessage-deflate`, client cookies, bounded messages, `Stream`/`Sink`, and protocol-specific strict response validation | Firefox-style transaction restarts on fresh connections (Chrome's single resend after a reused H1 connection closes before a response is available as opt-in reused-connection replay); H2/H3, macOS, and Safari SSE behavior is not yet captured; other WebSocket extensions, named compression/send policies, automatic reconnect, profile WebSocket connection policy with Chrome 153/Edge 153 and Firefox 156 recipes (reuse of a capable H2 session, else an `http/1.1`-only Upgrade connection or a new H2 connection per recipe) and captured CONNECT pseudo order, priority, field templates, and deflate offers; remaining gaps are HPACK representation parity, Firefox stream WINDOW_UPDATE and empty-message RSV1, Chrome REFUSED_STREAM retry, and proxy captures (retained Chrome 153, Edge 153, and Firefox 156 Windows captures show Chromium uses H2 WebSockets only on an existing session that advertises the setting, while Firefox also opens fresh H2 connections; pseudo-order, priority, deflate offer, and send policy differ by family), and H3 only from evidence |
| Routes | Direct HTTPS/H1/H2, plaintext HTTP/H1, exact direct H2 WebSocket extended CONNECT, and H3/QUIC paths; direct negotiated HTTPS may upgrade through learned Alt-Svc without changing the direct route; HTTP/1.1 absolute-form forwarding for `http://` origins over plaintext or TLS-encrypted proxies, including challenge-driven Basic with an anonymous first request and exactly one replay on a fresh same-route connection; HTTP/1.1 CONNECT over plaintext or independently authenticated TLS proxies, including one bounded challenge-driven Basic retry; credential-capable RFC 1929 local-/remote-DNS SOCKS5 for H1/H2 origin TLS and H1 WS/WSS; exact H3 over local-DNS `socks5://` or remote-DNS `socks5h://` through RFC 1928 UDP ASSOCIATE with a retained TCP control connection, fixed IP or canonical domain target, route-keyed reuse, typed terminal proxy failures; exact H3 over RFC 9298 CONNECT-UDP proxies with an https URI template and percent-encoded target, independent proxy trust and SNI, SETTINGS and QUIC DATAGRAM gating before any stream, Context ID 0 HTTP Datagrams with bounded per-stream queues, a 1252-byte outer path MTU with pre-I/O capacity checks, one outer connection per inner connection, outer-only resolve/connect retries, and no fallback; the proxy leg may instead be an explicitly selected HTTP/2 extended CONNECT or HTTP/1.1 Upgrade carrying DATAGRAM capsules, and every leg supports challenge-driven Basic proxy authentication with one replay on a fresh proxy connection; the SOCKS5 UDP adapter drops oversized or undeliverable datagrams like UDP and ends the association when its TCP control connection closes, and no route or protocol fallback; canonical Unicode proxy and origin hosts; forwarding never changes to CONNECT or another protocol; HTTPS proxy and origin trust and ticket caches are isolated; HTTPS proxies can be reached over HTTP/2 by explicit route choice (RFC 9113 §8.5 CONNECT, one proxy connection per tunnel, profile ALPN offered unchanged, and a selection mismatch is a typed error with no fallback) | Other proxy authentication schemes and learned challenge state, a shared or multiplexed H2 proxy session, plaintext forwarding over H2, custom SOCKS5 resolvers, CONNECT-UDP proxy authentication schemes other than Basic, and proxy-route Alt-Svc upgrade |
| Validation | Local TLS/H2/QUIC fixtures, hostile H1/H2/H3 peers, bounded qlog/key-log seams, deterministic authenticated QUIC packet analysis, two fresh-profile Chrome H3 ClientHellos, controlled Chrome/Phantom packet evidence, and ASan-backed fuzzing (short runs on relevant changes, longer weekly runs growing a cached, uncommitted corpus) of Phantom's test-kit ClientHello and H2 frame decoders, Quinn transport parameters, and the production HTTP CONNECT response and proxy Basic challenge parsers; Peet/Pingly are supplemental observers | Repeated packet-shape study, Prism comparison, broader protocol fuzzing, native-adapter sanitizers, long soaks |

“Support” means the entire row's relevant lifecycle works: configuration,
validation, emission, response behavior, cancellation, errors, observability,
and deterministic tests. Merely parsing an option or connecting successfully
does not count.

By default Phantom exposes response bodies exactly as received.
`ContentDecoding::advertised` decodes only the codings the caller's own ordered
`Accept-Encoding` advertises; Phantom never inserts or moves that field,
because its captured wire position belongs to the profile or caller. Unknown,
unadvertised, identity-mixed, over-stacked, or malformed chains fail closed.
That is deliberately stricter than browsers, which pass unknown chains through
or discard trailing bytes.

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
missing and the HTTP method is safe. An owned-bytes request body is replayed
exactly. A one-shot streaming body cannot be replayed, so the retry fails with
`RequestErrorKind::RequestBody` and the original response is not returned. The
retry never changes protocol or route, and a repeated demand cannot loop.
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

TLS, H2, and QUIC protocol settings are transport recipes, not host-OS
selectors. Capture provenance remains platform-specific because browser
builds, system integrations, launch conditions, and release channels can
change emitted bytes. Transport recipes verified on more than one platform
use browser/version names (`chromium::v152_tls`, `firefox::v154_http2`, and
so on); their rustdoc names the capture builds and platforms, and the former
`macos` names remain as hidden compatibility aliases. A remaining `macos`
qualifier means only “observed on macOS,” never “selected by
`target_os = macos`”: `v18_5_macos_tls` because Safari is captured only on
macOS, and `v152_macos_client_hints` because client hints contain platform
data on the wire.

Cross-platform capture decides whether two recipes share component data. [Cross-platform transport parity](../explanation/validation.md#cross-platform-transport-parity) records Windows 11 captures that match the Chrome 152 TLS, H2, QUIC, and H3 recipes and the Firefox 154 TLS and H2 recipes on every compared field. SSE and WebSocket browser captures are Windows 11 (10.0.26200) only; macOS parity is not assumed for them. Chrome 153 (153.0.8010.48), Edge 153 (153.0.4234.48), and Firefox 156 (156.0) recipes come from Windows 11 captures only; their platform-free transport names rest on the 152/154 finding that these layers did not depend on the platform. `chromium::v153_*` differ from 152 only in the trust-anchor ID list (28 IDs; the most frequent of 35 per-process orders in 60 processes). Edge 153 matches Chrome 153 on H2, QUIC, and H3 and omits trust-anchor IDs, so `edge::` carries only `v153_tls`, `v153_http3_tls`, and `v153_windows_client_hints`. `firefox::v156_tls` drops FFDHE-2048/3072 and uses a 240-byte ECH GREASE payload; `v156_http2` equals `v154_http2` apart from its captured extended CONNECT pseudo order and priority. Chrome's trust-anchor ID order is fixed within a browser process and differs between processes (a hash-iteration order, not a per-connection permutation); the Chrome 152 recipe keeps the most frequently observed order. Chrome's ECH GREASE uses HKDF-SHA256 with AES-128-GCM on every observed connection and is compared exactly. Firefox 154 and 156 choose their ECH GREASE AEAD per connection between AES-128-GCM and ChaCha20-Poly1305; both Firefox recipes list both, the backend draws one uniformly for each connection, and 200-connection distribution tests bound the split. Chrome 152, Chrome 153, and Edge 153 recipes leave the list empty and emit AES-128-GCM on every connection. The
runtime consumes the validated settings it receives and does not branch on the
host OS or client-family name. OS-specific code is reserved for real socket,
trust-store, native-build, or profiling differences.

The retained Chrome 152 transport evidence is from build `152.0.7977.83`.
Equivalence for build `152.0.7977.64` is an unverified assumption: under the
major-version profile policy it is expected to use the same transport
fingerprint, but no `.64` capture or differential exists, and Phantom makes no
`.64` claim until one does. The current client-hint recipe remains
exact-build- and platform-specific because its values literally include the
full `.83` version and macOS platform fields. Callers presenting `.64` must
supply matching full-version hint values.

## Claim boundary

Local raw captures and packet/frame differentials are the primary evidence.
Pingly, Peet, and Prism are independent observers that can reveal missing
signals, but none is a sole pass/fail oracle. Phantom reports the concrete
fields and behaviors covered by a test; it does not attach ceremonial
“verified” labels to an entire profile.
