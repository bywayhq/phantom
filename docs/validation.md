# Validation

This document is for contributors and reviewers. It defines the evidence
required for claims about observable behavior.

## Evidence ladder

A wire-sensitive claim needs all applicable levels:

1. A deterministic local assertion for parsing, validation, and lifecycle.
2. A normalized byte, frame, packet, or qlog differential against a pinned
   capture.
3. A hostile-peer regression for relevant unusual or malformed input.
4. Supplemental interoperability or live-observer evidence.

Connectivity and a matching summary fingerprint are not sufficient evidence of
browser-compatible behavior.

## Fixtures and normalization

Fixtures record the client, version, platform, launch conditions, and raw
evidence required to reproduce a claim. Strict decoders retain the ordered
semantic fields used by differentials.

Normalization may remove values that must vary: random bytes, cryptographic key
material, timestamps, connection IDs, packet numbers, and measured GREASE
values. It must not erase order, presence, lengths, negotiated values, or other
profile-controlled behavior.

Built-in recipes are compared through the public path users exercise. A profile
component is not complete when it merely parses or connects.

## Adversarial coverage

Scripted peers vary fragmentation, flow control, challenge sequences, resets,
shutdown, malformed input, and cancellation. Tests assert the ordered outcome,
error category, connection reuse, and bounded completion.

Valid-but-unusual traffic may be compared with a retained browser run.
Malformed traffic is a robustness test: safety and bounds take precedence over
reproducing unsafe behavior. Minimized failures become ordinary regressions;
fuzzing expands the corpus on a schedule.

## Ordered request-trailer evidence

Declared streaming-body-produced request trailers are covered through the
public client on exact H1, H2, and H3 paths and on negotiated H1/H2 paths.
Static trailer coverage remains at each transport boundary and in public route
and retry lifecycles. The regressions assert raw H1 bytes,
including casing, declaration, order, and interleaved duplicates; ordered H2
trailing fields and the HPACK never-indexed representation for sensitive
values; and H3 trailing HEADERS encoded through the connection's stateful QPACK
encoder. Lifecycle tests cover trailer-only, owned, and streaming bodies,
declared name/multiplicity matching, one-shot replay refusal, pre-I/O
validation, and suppression after a body error.

This evidence proves that Phantom emits the caller-selected trailer block with
the documented protocol semantics. It does not claim that a built-in browser
profile emits those application-defined trailers by default.

## Forward-proxy evidence

The public exact-H1 route tests cover an `http://` origin forwarded in absolute
form through plaintext and TLS-encrypted proxies. The TLS fixture proves that
Phantom verifies the proxy certificate and hostname with the independent proxy
trust store, emits the request directly after the proxy TLS handshake without a
CONNECT exchange, and returns the proxied response through the normal streaming
body path. Negative cases cover missing proxy trust, non-H1 selections, and
proxy failure without direct-route fallback.

Authentication regressions prove that every logical request is first sent
without credentials; only a strict, valid Basic `407` challenge triggers one
replay on a fresh same-route connection. They assert the generated sensitive
`Proxy-Authorization` position after caller fields and before framing, exact
owned-body and static-trailer replay, and failure before opening a retry
connection for a one-shot streaming body. A second `407` and malformed or
unsupported challenges return typed proxy errors without direct or protocol
fallback. A subsequent logical request begins anonymously, proving that no
challenge state is learned. Lifecycle cases also cover a nonempty challenge
body, a queued request installing an intervening pooled connection without
capturing the authenticated retry, one total deadline spanning both attempts,
and suppression of challenge-response cookies while retaining cookies from the
final origin response.

This evidence does not claim browser-capture fidelity, redirects, negotiated
H1/H2 forwarding, H2 proxy transport, other authentication schemes, forwarding
an HTTPS origin, or H3 through an HTTP forward proxy. H3's separate SOCKS5 UDP
evidence is described below.

The WebSocket route regressions apply the same contract to plaintext `ws://`
Upgrade through plaintext and TLS-encrypted forward proxies. They assert the
normalized absolute-form request target, caller-selected opening-field order,
the absence of CONNECT and direct-origin traffic, independent proxy trust,
coalesced upgraded bytes, and Ping/Pong traffic. Authentication cases prove an
anonymous first attempt, one fresh-connection replay with the same WebSocket
key and generated credentials appended after caller fields, no learned state,
and terminal behavior for malformed or repeated challenges. A caller-supplied
`Proxy-Authorization` is rejected before proxy or origin I/O.

SOCKS5 WebSocket regressions cover plaintext `ws://` as well as TLS-backed
`wss://`. The plaintext cases prove remote-DNS Unicode canonicalization,
local-DNS address resolution, username/password negotiation, an origin-form
Upgrade with no origin TLS, and delivery of a WebSocket frame coalesced with
the `101` response.

Direct H2 WebSocket regressions use an authenticated loopback peer that
advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. They assert that Phantom waits
for the initial peer SETTINGS before dispatch, emits CONNECT with
`:protocol = websocket` and the configured five-field pseudo order, omits H1
Upgrade/key fields, preserves ordered ordinary fields, and exchanges framed
messages over simultaneous request/response DATA. Negative cases cover an
absent peer setting without CONNECT dispatch or H1 fallback, non-2xx streaming
rejection responses, direct-`wss://` route validation, and stream-scoped reset.
These are standards-level deterministic fixtures, not named-browser evidence.

## H3 SOCKS5 UDP evidence

Public exact-H3 loopback regressions cover local-DNS `socks5://` and
remote-DNS `socks5h://` through RFC 1928 UDP ASSOCIATE, both without
authentication and with RFC 1929 username/password authentication. They verify
end-to-end H3 traffic, reuse of one route-keyed H3 connection and association
across requests, and retention of the TCP control connection for the
client-owned association lifetime. The local path fixes an IP target. The
remote path uses an intentionally unresolvable `.invalid` origin, proves the
exact canonical DOMAIN target on the proxy wire, and forwards it only through
the fixture's proxy-owned mapping. Rejected and malformed association replies
produce typed proxy errors without origin datagrams, direct fallback, or
protocol fallback. HTTP forwarding and HTTP CONNECT routes fail before proxy
or origin I/O.

Transport-focused tests assert the exact authentication and UDP ASSOCIATE
exchanges, fixed IPv4 and IPv6 target headers, zero RSV and FRAG fields, and
fragment rejection. The adapter bounds operation to one datagram per send or
receive and accepts only packets from the negotiated relay carrying the
configured target; malformed, fragmented, spoofed-relay, wrong-domain, or
wrong-port datagrams are discarded by that boundary. Relay-reply tests cover the
compatibility rule that
substitutes only the established TCP proxy peer IP for an unspecified
BND.ADDR, and rejection of domain BND.ADDR or a zero BND.PORT. Remote-target
tests cover exact-domain replies, case-insensitive domain comparison,
same-port IP-form replies, and a stable logical Quinn peer.

This evidence does not claim HTTP proxy or CONNECT routing for H3,
CONNECT-UDP/MASQUE, H3 extended CONNECT, or browser-capture fidelity for a
proxied H3 route. Alt-Svc upgrade has separate direct-route evidence below.

## Alt-Svc HTTP/3 upgrade evidence

An authenticated loopback H2 origin and H3 alternative share one test
identity while listening on distinct transport locations. Public negotiated
requests prove default-off and explicit bounded activation, learning from the
ordered response fields, an H2 first response followed by H3, retention of the
original authority and certificate identity, and selected-protocol metadata.
Parser regressions cover ordered duplicate fields, canonical host forms,
default and explicit `ma`, `Age` subtraction and expiry, replacement, `clear`,
unsupported alternatives, malformed-field retention, bounded LRU eviction,
and explicit removal.

Failure regressions close the authenticated alternative before request
dispatch and prove a typed H3 error, no same-request H1/H2 fallback, eviction,
and recovery through the origin on a later request. A `421` remains visible as
an H3 response, evicts the advertisement, and cannot cause the alternative
connection generation to be reused for the origin transport location. Manual
clearing is covered through the public client.

This evidence does not claim browser policy, connection racing, persistence,
`Alt-Used`, H2 ALTSVC frames, proxy-route upgrades, or multiple-alternative
racing.

## Connection-retry evidence

The shared exact-protocol acquisition state uses scripted typed setup failures
to prove its finite request-wide budget across separate acquisitions, fresh
connect-phase deadlines, timeout exclusion, protocol-labelled timeout
behavior, last-error preservation, and one total deadline across retry delay.
Error-classification tables cover direct,
forward-proxy, CONNECT-proxy, SOCKS5, and QUIC setup variants while excluding
TLS, authentication, rejection, timeout, protocol, and post-dispatch failures.
Public loopback H1 and H2 regressions start their servers only after observing
the first refused setup, then verify the final request and response metadata.
The H1 case uses a one-shot streaming POST with static trailers. A negotiated
H1/H2 refusal proves that configured exact-protocol retries remain excluded.
Live H3 recovery is not claimed: H3 coverage currently consists of the typed
QUIC classification table, shared acquisition lifecycle tests, static pool
wiring review, and the workspace gates.

These tests prove lifecycle and routing behavior, not browser retry policy.
Retries are caller-configured and do not become part of a named browser recipe.

## External suites

External projects are witnesses, not pass badges:

| Suite | Purpose |
| --- | --- |
| Autobahn | Exercise the public WebSocket client and turn failures into focused regressions |
| QUIC Interop Runner | Exercise the public H3 client against an independent server |
| Web Platform Tests | Check selected EventSource behavior through Phantom's API |
| curl scenarios | Source mature lifecycle, proxy, redirect, and timeout cases |
| TLS-Anvil and BoringSSL tests | Probe TLS behavior and native dependency updates |

Server-oriented h2spec and h3spec cases inform hostile client-peer tests; they
are not reported as client conformance.

## Diagnostics and performance

Tracing uses static fields and bounded values. It must not record headers,
cookies, credentials, payloads, certificates, endpoint names, or raw secrets.
H3 qlog and NSS key logging are explicit, bounded, default-off paths.

Benchmarks state exactly what they measure. Current deterministic replays cover
connector construction and public H1/H2 request paths, not TLS handshakes or
end-to-end throughput. Optimization follows profiling and must preserve wire
fixtures.

## Contributor gates

Formatting, lint, test, documentation, MSRV, capture-tool, and vendor checks
live in [AGENTS.md](../AGENTS.md) so there is one canonical command list. A
handoff records what ran and any remaining uncertainty.

See [HTTP/3 internals](http3.md) for its capture and packet proof.
