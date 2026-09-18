# Roadmap

This page is for users and contributors following active direction. Exact
current support lives in [Coverage](coverage.md).

Each phase names the dominant delivery focus. Idiomatic Rust, clear ownership,
accurate documentation, and green validation gates remain continuous
requirements; Phase 5 is the final repository-wide audit after the preceding
work has exposed the real architectural boundaries.

## Phase 1 — Functionality (current)

- Complete the remaining client and proxy-route work without introducing
  direct or cross-protocol fallback.
- Extend the current exact-protocol, pre-dispatch connection retry policy only
  when another replay class has explicit ownership and bounded lifecycle rules.
- Complete browser-backed SSE reconnect evidence and remaining WebSocket
  protocol functionality before broad robustness work.
- Expand the Chromium, Firefox, and Safari protocol/profile matrix only from
  fresh captures; do not infer missing H2, H3, QUIC, WebSocket, or SSE behavior
  from browser-family names.
- Add further browser versions, platforms, and non-browser profiles only from
  fresh capture evidence.
- Add H3 upgrade, UDP-capable proxying, and extended CONNECT after their route
  and failure semantics are proven end to end.

## Phase 2 — Ergonomics

- Make supported profile, route, timeout, body, trailer, SSE, and WebSocket
  combinations easier to discover and configure without hiding wire choices.
- Keep stable error categories, examples, and diagnostics aligned with every
  completed functionality slice.

## Phase 3 — Hardening

- Expand cross-platform debug and release gates.
- Broaden fuzzing, sanitizer coverage, lifecycle regressions, and soak tests.
- Keep vendored patches reproducible and review dependency updates in
  isolation.

## Phase 4 — Profiling and optimization

- Profile representative cold and warm connections, proxy routes,
  multiplexing, streaming bodies, SSE, and WebSocket workloads.
- Optimize only measured bottlenecks while preserving packet, frame, ordering,
  cancellation, and bounded-resource evidence.

## Phase 5 — Idiomatic architecture and maintainability audit

- Audit the complete workspace for clear, human-readable, idiomatic Rust after
  functionality and measured optimization have settled the real boundaries.
- Review crate, module, file, folder, type, function, field, and test naming for
  consistent protocol/domain language and intuitive ownership.
- Review abstractions and seams for single responsibility, concrete ownership,
  shallow public structure, and removal of accidental indirection or duplicated
  policy without introducing speculative frameworks.
- Revisit file and folder organization, split responsibilities that have become
  genuinely distinct, and consolidate fragments that obscure one concept.
- Require behavior-preserving refactors to retain wire fixtures, public API
  contracts, diagnostics, cancellation behavior, and the full validation gates.

## Completed foundation

The workspace, capture testkit, TLS and ordered H1 path, H2 path, initial
browser-family profiles, forced H3 path, and ordered static request trailers on
exact H1/H2/H3 and negotiated H1/H2 have passed their phase acceptance
criteria. Declared streaming-body-produced request trailers preserve H1
spelling and cross-name duplicate order across exact H1/H2/H3 and negotiated
H1/H2. H1 WebSocket supports direct plaintext `ws://` alongside routed
TLS-backed `wss://`; plaintext `ws://` also supports plaintext and TLS-encrypted
HTTP forward proxies with strict challenge-driven Basic authentication. These
paths share the same ordered opening handshake, strict validation, and bounded
message lifecycle. Exact H1/H2/H3 requests can opt into bounded
typed connection-setup retries without changing route or protocol or replaying
request bytes. HTTP/1.1 absolute-form forwarding for `http://`
origins is available over plaintext and TLS proxies with independent proxy
authentication and trust policies. Challenge-driven Basic starts each logical
request anonymously and permits one replay on a fresh same-route connection,
with no learned challenge state, CONNECT conversion, protocol fallback, or
direct fallback. Code, tests, [Design](design.md), and
[Validation](validation.md) are the maintained record of those decisions.
