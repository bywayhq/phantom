# Roadmap

This page is for users and contributors following active direction. Exact
current support lives in [Coverage](coverage.md).

Each phase names the dominant delivery focus. Idiomatic Rust, clear ownership,
accurate documentation, and green validation gates remain continuous
requirements; Phase 5 is the final repository-wide audit after the preceding
work has exposed the real architectural boundaries.

## Phase 1 — Functionality (current)

- The initial external-root source distribution is documented and manually
  build-proven: one revision-pinned vendorable layout and its complete root
  patch stanza resolve every patched package from the retained trees. Missing
  substitutions fail at compile time, and CI repeats the external-root
  resolution and all-features check. Direct-fork distribution remains before
  one-line installation can be claimed.
- Opt-in streaming response decompression is complete: caller-advertised
  `gzip`, `deflate`, `br`, and `zstd` only, decoded-byte limits, fail-closed
  coding semantics, and no invented `Accept-Encoding` field or wire position.
- Bounded response-body collection is complete: its inclusive cap applies to
  bytes returned to the caller, which are decoded bytes when decoding is
  enabled, abandons an over-limit stream, and has a stable error category.
- Complete the remaining client and proxy-route work without introducing
  direct or cross-protocol fallback.
- Extend the current exact-protocol, pre-dispatch connection retry policy only
  when another replay class has explicit ownership and bounded lifecycle rules.
- Browser-backed SSE reconnect evidence exists for Chrome 153 and Firefox 155
  on Windows over HTTP/1.1. Close the gaps it found: caller-positioned
  `Last-Event-ID`, the Firefox minimum retry delay, and reconnect timing after
  pre-response network errors. Complete the remaining WebSocket protocol
  functionality before broad robustness work.
- Expand the Chromium, Firefox, and Safari protocol/profile matrix only from
  fresh captures; do not infer missing H2, H3, QUIC, WebSocket, or SSE behavior
  from browser-family names.
- Add further browser versions, platforms, and non-browser profiles only from
  fresh capture evidence.
- Within Phase 1, prove route and failure semantics end to end for H3 upgrade,
  UDP-capable proxying, and extended CONNECT, then implement each vertical
  slice without silent fallback.
- The SOCKS5 UDP proxy slice is complete: exact H3 supports local-DNS
  `socks5://` and remote-DNS `socks5h://` through RFC 1928 UDP ASSOCIATE.
- The current H3 upgrade slices are complete: negotiated direct HTTPS requests
  can opt into bounded Alt-Svc learning, preserve origin authority and SNI while
  dialing an advertised `h3` location, send canonical explicit-port `Alt-Used`
  only on that managed attempt, and apply explicit failure and `421` eviction
  semantics without fallback. Racing, persistence, and H2 ALTSVC frames remain
  later Phase 1 functionality.
- The first extended CONNECT slice is complete: explicitly configured custom
  H2 profiles can open exact direct `wss://` WebSockets after peer SETTINGS
  opt-in, with a dedicated five-pseudo-header order, duplex flow control,
  streamed rejection bodies, clean close, and no fallback. Named-browser
  recipes remain capture-gated.
- CONNECT-UDP/MASQUE, proxy-carried or H3 extended CONNECT, and named-browser
  H2 WebSocket recipes remain in Phase 1.
- The Chrome 152 H2 WebSocket recipe requires a retained browser capture of
  the extended-CONNECT opening handshake, including pseudo-header and ordinary
  field order, priority, compression offer, and failure behavior. The generic
  configurable H2 implementation is not evidence for that named recipe.
- Chrome `152.0.7977.64` is expected to share the retained `.83` transport
  fingerprint under the major-version policy. Exact full-version client hints
  remain persona data and must not inherit `.83` values accidentally.

## Phase 2 — Ergonomics

- Make supported profile, route, timeout, body, trailer, SSE, and WebSocket
  combinations easier to discover and configure without hiding wire choices.
- Move transport recipe names to browser/version identity while retaining
  platform and exact-build qualifiers only for data that actually differs,
  such as client hints. Keep capture OS and build provenance in fixtures and
  documentation, with compatibility aliases for existing public names.
- Keep stable error categories, examples, and diagnostics aligned with every
  completed functionality slice.

## Phase 3 — Hardening

- Expand cross-platform debug and release gates.
- Deny `unwrap_used` and `expect_used` after remaining recoverable runtime paths
  have typed errors; a panic aborts embedders that compile with `panic =
  "abort"`.
- Broaden fuzzing, sanitizer coverage, lifecycle regressions, and soak tests.
- Keep vendored patches reproducible and review dependency updates in
  isolation.

## Phase 4 — Profiling and optimization

- Measure cold `Client::builder(profile).build()` cost for the supported
  profiles and keep independently built clients isolated: no shared cookies,
  connection pools, or TLS tickets across sessions.
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
HTTP forward proxies with strict challenge-driven Basic authentication and
authenticated local- or remote-DNS SOCKS5 tunnels. These paths share the same
ordered opening handshake, strict validation, and bounded message lifecycle.
Exact H1/H2/H3 requests can opt into bounded
typed connection-setup retries without changing route or protocol or replaying
request bytes. HTTP/1.1 absolute-form forwarding for `http://`
origins is available over plaintext and TLS proxies with independent proxy
authentication and trust policies. Challenge-driven Basic starts each logical
request anonymously and permits one replay on a fresh same-route connection,
with no learned challenge state, CONNECT conversion, protocol fallback, or
direct fallback. Exact H3 supports local- or remote-DNS SOCKS5 through an
optionally authenticated RFC 1928 UDP ASSOCIATE, retains its TCP control
connection, and reuses the route-keyed H3 connection without direct or protocol
fallback. Code, tests, [Design](design.md), and
[Validation](validation.md) are the maintained record of those decisions.
