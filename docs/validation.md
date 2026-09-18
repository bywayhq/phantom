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
