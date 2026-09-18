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

Static request trailers are covered through the public client on exact H1, H2,
and H3 paths and on negotiated H1/H2 paths. The regressions assert raw H1 bytes,
including casing, declaration, order, and interleaved duplicates; ordered H2
trailing fields and the HPACK never-indexed representation for sensitive
values; and H3 trailing HEADERS encoded through the connection's stateful QPACK
encoder. Lifecycle tests cover trailer-only, owned, and streaming bodies,
pre-I/O validation, and suppression after a body error.

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
an HTTPS origin, H3 proxy support, or UDP-capable proxying.

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
