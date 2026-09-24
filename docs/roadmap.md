# Roadmap

This page shows where Phantom is heading, for users and contributors planning
around it. It states intent, not commitments or dates. For exact current
support, see [Coverage](reference/coverage.md).

Each phase names its main delivery focus. Idiomatic Rust, clear ownership,
accurate documentation, and green validation gates are required in every
phase. Phase 5 is the final repository-wide audit, run after earlier phases
have shown where the real architectural boundaries are.

## Phase 1: Functionality (current)

### Complete

- Downstream crates can depend on a pinned Git revision or checkout with one
  line and no `[patch]` table. Patched dependencies are renamed `phantom-*`
  forks replayed from their upstream archives, and CI rejects the stock
  package names.
- Opt-in streaming response decompression: only the `gzip`, `deflate`, `br`,
  and `zstd` codings the caller advertises, with decoded-byte limits,
  fail-closed coding semantics, and no invented `Accept-Encoding` field or
  wire position.
- Bounded response-body collection. Its inclusive cap applies to the bytes
  returned to the caller, which are decoded bytes when decoding is enabled.
  An over-limit stream is abandoned and reports a stable error category.
- Browser-backed SSE reconnect evidence for Chrome 153 and Firefox 156 on
  Windows over HTTP/1.1. Phantom reproduces it through
  `SseHeader::last_event_id` and `min_retry`. Chrome's single resend after a
  reused keep-alive connection closes before any response is available as
  opt-in reused-connection replay.
- The SOCKS5 UDP proxy slice. Exact H3 supports local-DNS `socks5://` and
  remote-DNS `socks5h://` through RFC 1928 UDP ASSOCIATE.
- The current H3 upgrade slices. Negotiated HTTPS requests on a direct or
  SOCKS5 route can opt into bounded Alt-Svc learning. They keep the origin
  authority and SNI while dialing an advertised `h3` location over the route
  that learned it, send a canonical `Alt-Used` with an explicit port only on
  that managed attempt, and apply explicit failure and `421` eviction without
  fallback. H2 ALTSVC frames, caller-owned Alt-Svc persistence, per-location
  H3 pool slots, and opt-in racing with backoff for broken alternatives are
  also complete. The store is keyed by origin and route, so an advertisement
  never crosses routes.
- The first extended CONNECT slice. Explicitly configured custom H2 profiles
  can open exact direct `wss://` WebSockets after the peer opts in through
  SETTINGS. The slice includes a dedicated five-pseudo-header order, duplex
  flow control, streamed rejection bodies, clean close, and no fallback.
- The HTTP/3 extended CONNECT foundation in `phantom-net`.
- Exact H3 over RFC 9298 CONNECT-UDP proxies, over HTTP/3, HTTP/2, and
  HTTP/1.1 proxy legs, with Basic proxy authentication.
- Named Chrome 153, Edge 153, and Firefox 156 H2 WebSocket recipes with a
  profile connection policy.

### Remaining

- Publish to crates.io. What blocks this is the `btls-sys` git dependency,
  which crates.io rejects, in the workspace root manifest and in the
  vendored `btls` manifest. The release script already refuses to publish
  while either remains. Bundling is not the obstacle it was assumed to be:
  upstream already publishes `btls-sys` at about 4.9 MiB with the
  BoringSSL sources and every native patch included, well inside the
  10 MiB limit, so no size exemption is needed.
  - Renaming the package and its `links` key does not by itself let a
    dependency graph hold both Phantom and a stock `boring` or `btls`.
    The symbol prefix derives from the build script's own crate name
    rather than the package name, and both crates ask the linker for the
    same static archive names. Symbol prefixing is also skipped outside
    Linux, so coexistence stays a Linux-only property until that upstream
    gap closes. Do not promise it elsewhere.
  - Redistributing the BoringSSL sources makes Phantom a redistributor.
    Carry the bundled third-party licenses, and declare a license
    expression that covers Apache-2.0 BoringSSL rather than inheriting the
    wrapper's own terms.
  - Keep every native patch. Two of them have no upstream equivalent, and
    dropping any of them changes what goes on the wire, which is a
    fidelity regression rather than a packaging tradeoff.
- Complete the remaining client and proxy-route work without adding direct or
  cross-protocol fallback.
- Per-profile HPACK indexing, a per-message compression policy, and a
  `REFUSED_STREAM` retry policy for WebSockets.
- Complete the remaining WebSocket protocol functionality before broad
  robustness work.
- For H3 upgrade, UDP-capable proxying, and extended CONNECT, prove route and
  failure semantics end to end, then implement each vertical slice without
  silent fallback.

### Rules for this phase

- Extend the pre-dispatch connection retry policy (exact H1/H2/H3 and TCP
  setup for negotiated requests before ALPN) only when another replay class
  has explicit ownership and bounded lifecycle rules.
- Expand the Chromium, Firefox, and Safari protocol and profile matrix only
  from fresh captures. Do not infer missing H2, H3, QUIC, WebSocket, or SSE
  behavior from browser-family names.
- Add further browser versions, platforms, and non-browser profiles only from
  fresh capture evidence.
- Named-browser extended CONNECT recipes come only from captures. A Chrome 152
  H2 WebSocket recipe needs a retained browser capture of the extended
  CONNECT opening handshake, including pseudo-header and ordinary field order,
  priority, compression offer, and failure behavior. The generic configurable
  H2 implementation is not evidence for that recipe.
- Chrome `152.0.7977.64` is expected to share the retained `.83` transport
  fingerprint under the major-version policy. That stays an unverified
  assumption until a `.64` capture is compared. Exact full-version client
  hints are persona data and must not inherit `.83` values by accident.

## Phase 2: Ergonomics

- Make supported combinations of profile, route, timeout, body, trailer, SSE,
  and WebSocket settings easier to discover and configure, without hiding
  wire choices.
- Complete: transport recipe names now use browser and version identity.
  Windows captures show no platform-dependent transport field for the Chrome
  152 TLS, H2, QUIC, and H3 recipes or the Firefox 154 TLS and H2 recipes, so
  they are now `chromium::v152_{tls,http2,http3,http3_tls,http3_request,quic}`
  and `firefox::v154_{tls,http2}`. The former `macos` names remain as hidden
  compatibility aliases. Capture OS and build provenance stay in fixtures,
  rustdoc, and documentation. `v152_macos_client_hints` keeps its platform
  qualifier because it carries platform data, and `v18_5_macos_tls` stays
  macOS-specific until Safari is captured elsewhere.
- Keep stable error categories, examples, and diagnostics in step with every
  completed functionality slice.
- Add feature-gated JSON, form, and multipart request bodies that set only the
  fields a caller or captured browser template would send. No request template
  covers a request with a body yet, so there is no evidence for where a browser
  places `Content-Type` in a POST, and none for a captured multipart boundary.
  Either these helpers position every field they add at a caller slot, or a
  POST capture comes first. Add opt-in `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`
  route selection.
- Carry a default request template on the profile
  (`ClientProfile::with_request_template`), which a request can override or
  remove, validated when the client is built. Regular field order stays a
  request concern and pseudo-header order stays a transport recipe; the two
  axes do not merge. Sibling clients apply an order as a sort at encode time
  and leave unnamed caller fields in hash order. Phantom keeps the caller's
  own order for fields the template does not name.
- Close the wire gaps the nearest comparable clients already reproduce, in
  this order:
  1. Split the `cookie` field into one entry per cookie on HTTP/2 and HTTP/3,
     as Chrome and Firefox do. This needs a vendored encoder patch and a
     two-cookie capture.
  2. Send Chromium's preface `PING` on a pooled connection that has been idle
     longer than its at-risk-of-loss time.
  3. Apply the per-profile HPACK indexing decisions planned for extended
     CONNECT to ordinary requests too.
  4. Prove that a resumed ClientHello still matches the captured shape.
     Phantom relies on this today without evidence.
- Close the behaviour gaps that no fingerprint field reveals but a session
  does. A survey of client APIs does not surface these, because they are
  browser behaviour rather than caller surface:
  1. Revalidate with conditional requests. Phantom never sends
     `If-None-Match` or `If-Modified-Since` and never handles a `304`, so a
     client that fetches a resource twice refetches it in full both times. A
     browser's cache warms, and a server watching one session sees that it
     never does. Capture what Chrome and Firefox send on a second fetch,
     including field position and which validator they prefer, before writing
     any cache. Phantom stores nothing today, so the first slice can be
     caller-owned validators rather than a cache.
  2. Establish whether a captured browser sends `Expect: 100-continue`, and on
     which upload shapes. Phantom never sends it. Whether that is correct is
     currently unknown, which is itself the gap.
  3. Resume QUIC sessions and send early data where the captured browser does.
     Connections are made today with no early data at all, so a resumed
     browser connection and a Phantom connection differ in their first flight
     whatever the ClientHello contains. This is distinct from the TLS
     resumption parity item above: that one asks whether a resumed
     ClientHello keeps its captured shape, this one asks whether Phantom
     resumes at all.
- Close the remaining transport and discovery gaps, each from evidence:
  1. Settle what a browser does when an origin advertises more than one
     alternative. Phantom races at most one. Capture an origin advertising
     several before building anything: whether Chrome races them, picks one by
     a stated rule, or tries them in order decides whether this is a feature
     or a documented limit.
  2. Read HTTPS DNS resource records. This is queued today only as a
     prerequisite for real ECH, which understates it: the record is also how a
     browser learns `h3` for an origin it has never contacted, so without it
     Phantom can reach HTTP/3 only after an Alt-Svc advertisement on a prior
     TCP request. A browser reaches it on the first request.
  3. Model Firefox's per-connection keepalive schedule and its address
     selection. Phantom applies Chromium's keepalive and Happy Eyeballs v2 on
     every TCP path, so a Firefox profile currently connects with Chromium's
     transport behaviour. Chromium's macOS idle-only keepalive is a named
     recipe gap beside it.
- Settle whether Chrome draws its trust-anchor identifier order per process,
  as the retained 60-process capture shows, or per connection, as the nearest
  comparable clients assume. Capture many connections from one process.
- Close the gaps callers expect from an HTTP client, in this order:
  1. Caller-owned cookie-jar export and import, beside the Alt-Svc snapshot
     API.
  2. Host-to-address overrides, a caller resolver, and DNS over HTTPS where
     the captured browser uses it.
  3. A source address or interface binding.
  4. Client certificates.
  5. One narrow request hook rather than a middleware framework.
- Close the caller ergonomics gaps a survey of seventeen HTTP clients found,
  in this order. None of these changes a byte on the wire; each is caller-side
  only.
  1. Composed per-browser profile constructors, such as `chromium::v153()`,
     assembling the components that are already verified. Today a Chrome 153
     client takes seven hand-composed calls, and the caller has to know that
     the HTTP/3 leg uses `v153_http3_tls` and not `v153_tls`. Getting that
     wrong is silent and emits a wrong ClientHello, which is the class of
     error Phantom exists to prevent.
  2. Error triage over the existing `kind()`, and a public replay-safety
     accessor. Phantom already computes `RequestRetryability` precisely and
     then hides it, so a caller writing an outer retry loop re-derives it from
     a 27-variant enum and gets it wrong. Carry the response on the errors
     that have one, as `WebSocketError` already does.
  3. Bounded `text()`, `bytes()`, and typed-JSON response helpers over the
     existing inclusive cap, where the bounded form is the only form. A
     response helper must never set a request field: no helper may add
     `Accept` or `Accept-Encoding`. The typed helper takes an optional
     `serde` dependency behind its own feature, which stays off by default
     like every other feature. It decodes what arrived whatever the
     response declares, because a helper that reads `Content-Type` makes
     its behavior depend on a server field rather than caller intent.
     The same feature may carry a serialized form of the cookie-jar and
     Alt-Svc snapshots. Snapshots stay typed values that are revalidated
     on import, so a serialized snapshot can never widen what an import
     accepts.
  4. Re-export the ecosystem types the public API already names, including
     `Bytes`, which appears in `RequestBuilder::body` but cannot be named
     without a matching direct dependency.
  5. A documented tracing span and field contract, observe-only, settled
     before the narrow request hook so the hook is scoped to what tracing
     cannot already do.
  6. A per-request timeout override that layers onto the client's rather than
     replacing it wholesale, and retry backoff with a retry budget that caps
     the extra load a retry storm can add.
  7. One naming convention across the four ordered-field vocabularies and one
     method name per knob across the three request builders. Keep the four
     types distinct: merging them would let a caller pass a slot to a request
     that cannot carry it, which the type system forbids today. Retire the
     duplicate `Route::http_connect`.
  8. Query-parameter construction that never sorts, because a reordered query
     is wire-visible in `:path`, with the encoder pinned to the WHATWG
     `application/x-www-form-urlencoded` rule a browser's `URLSearchParams`
     uses, and a separate already-encoded form.
  9. Authorization value constructors that return a field the caller places,
     never a builder method that places it.
  10. `Link` field parsing as data on the response. Following those links
      automatically is a non-goal.
- Publish a wire-assertion test harness so downstream callers can assert that
  a request matched a named recipe's field order and ClientHello shape.
  `phantom-testkit` is unpublished today, so downstream users have no way to
  assert against a Phantom client. This is the one harness no other client can
  offer. It may instead belong to the Phase 5 tooling audit, which already
  covers the capture scripts it overlaps.

### Deliberate non-goals for this phase

- No middleware or interceptor framework. Middleware is where
  fingerprint-breaking field injection happens: the interceptor stacks of
  comparable clients exist so that another library in a dependency graph can
  add a field to a request. The queued narrow hook may observe and cancel, and
  may fill caller slots a template names; it may never append a field.
- No erroring on a non-2xx status by default. Status stays data. The one
  library in the survey that errors by default keeps only the status number
  and loses the response with it.
- No automatic `Link` following, no base-URL joining, and no blocking API.

- Functionality proposed for after the Phase 1 exit. Each item starts from a
  proposal with acceptance criteria and capture evidence:
  - A feature-gated `danger_accept_invalid_certs` for debugging through an
    intercepting proxy. It skips server chain verification only; the
    ClientHello and every other wire field stay unchanged.
  - Chrome for Android recipes from Android emulator captures.
  - Plaintext `http://` requests on clients with a redirect policy, and
    Digest proxy authentication.
  - SOCKS4 and SOCKS4a routes. Neither carries UDP, so an exact HTTP/3
    request and an Alt-Svc upgrade are refused on them before any I/O, as
    they already are for an HTTP proxy route. SOCKS4 takes an IPv4
    address and SOCKS4a a hostname, so the DNS ownership a caller chooses
    with `Socks5DnsMode` maps onto the choice between them.
  - Real ECH from DNS HTTPS records, where the captured browser uses it.
  - Import of externally described fingerprints, limited to fields Phantom
    can reproduce byte for byte.

## Phase 3: Hardening

- Expand cross-platform debug and release gates.
- Deny `unwrap_used` and `expect_used` once the remaining recoverable runtime
  paths have typed errors. A panic aborts embedders that compile with
  `panic = "abort"`.
- Broaden fuzzing, sanitizer coverage, lifecycle regressions, and soak tests.
- Keep vendored patches reproducible, and review dependency updates in
  isolation.
- Audit the vendored H3 engine against both Hyperium and the independently
  maintained [`0x676e67/http3`](https://github.com/0x676e67/http3) fork before
  its next refresh. Treat the fork as a source of focused fixes and regression
  cases, not as a replacement dependency: its Sans-I/O rewrite, Rust 1.98
  baseline, and fingerprint-control surface do not match Phantom's current
  contracts or Rust 1.88 MSRV.
  - Correct QPACK field-section Base calculation after dynamic-table eviction.
    Port the fork's
    [absolute-Base regression](https://github.com/0x676e67/http3/commit/087a3404c80e31dac4616a0fb1c8a424ffa51b60)
    and prove that reusing an acknowledged retained field emits no duplicate
    insertion, uses the absolute insertion count, and does not become blocked.
  - Backport Hyperium's
    [buffered-write fix](https://github.com/hyperium/h3/commit/14a14224242862de31e780a7907fe8839b893fd6)
    with its cancellation regressions. A cancelled DATA write must be flushed
    before another frame, and the Quinn adapter must flush every buffered frame
    before FIN so the peer cannot observe a truncated HTTP/3 message.
  - Review later QPACK, header validation, stream-drop, and driver-lifecycle
    fixes one commit at a time. Keep only changes that reproduce against
    Phantom, preserve ordered SETTINGS and fields, retain bounded ownership and
    cancellation behavior, and pass the vendored and workspace gates.
- Document the TCP/IP stack fingerprint as decided by the host rather than
  emulating it. A client cannot set the window scale, SACK, timestamps, or
  TCP option order from user space. Setting only the reachable fields, such
  as the hop limit, produces a packet no real host emits. Record the
  reference JA4T and p0f signatures for the profiled platforms. Offer a check
  the caller runs to compare the host platform with the profile's declared
  platform, instead of branching on the host OS. Privileged packet rewriting
  and userspace TCP stacks stay outside this library.
- Evaluate [compio](https://github.com/compio-rs/compio) runtime support with
  a bounded spike.
  - Tokio is required today. The TLS, SOCKS, HTTP/2,
    QUIC, and WebSocket layers and their vendored forks are written against
    Tokio's poll-based I/O traits, while compio uses completion-based owned
    buffers.
  - The spike defines a narrow runtime seam in `phantom-net` (TCP and UDP
    connect, timers, task spawning, socket options), implements quinn's
    `Runtime` trait for compio, and measures a compatibility-adapter path
    against Tokio.
  - A native HTTP/2 and TLS port follows only if measurements justify it,
    behind one runtime feature, and only with byte-identical wire evidence
    (TCP segmentation, TLS record boundaries, socket options) from the
    existing capture fixtures and differentials on every supported platform.
  - Until then, compio applications can drive Phantom on a Tokio runtime in a
    helper thread.

## Phase 4: Profiling and optimization

- Measure the cold cost of `Client::builder(profile).build()` for the
  supported profiles. Keep independently built clients isolated: no shared
  cookies, connection pools, or TLS tickets across sessions.
- Profile representative cold and warm connections, proxy routes,
  multiplexing, streaming bodies, SSE, and WebSocket workloads.
- Optimize only measured bottlenecks, and preserve the packet, frame,
  ordering, cancellation, and bounded-resource evidence.

## Phase 5: Idiomatic architecture and maintainability audit

- Audit the whole workspace for clear, readable, idiomatic Rust after
  functionality and measured optimization have settled the real boundaries.
- Review the naming of crates, modules, files, folders, types, functions,
  fields, and tests for consistent protocol and domain language and intuitive
  ownership.
- Review abstractions and seams for single responsibility, concrete
  ownership, and a shallow public structure. Remove accidental indirection
  and duplicated policy without introducing speculative frameworks.
- Revisit file and folder organization. Split responsibilities that have
  become distinct, and consolidate fragments that obscure one concept.
- Require behavior-preserving refactors to keep wire fixtures, public API
  contracts, diagnostics, cancellation behavior, and the full validation
  gates.
- Audit the tooling from first principles: capture and conformance scripts,
  CI and release scripts, development helpers, GitHub workflows, and agent
  configuration. Remove what no gate or workflow uses, merge overlapping
  tools, give each one clear entry points and help text, follow each
  language's idioms, and keep the documented commands in step with CI.

## Completed foundation

These pieces have passed their phase acceptance criteria:

- The workspace, the capture test kit, the TLS and ordered H1 path, the H2
  path, the initial browser-family profiles, and the forced H3 path.
- Ordered static request trailers on exact H1/H2/H3 and negotiated H1/H2.
- Request trailers produced by a declared streaming body, which keep H1
  spelling and the order of duplicates across names, on exact H1/H2/H3 and
  negotiated H1/H2.
- H1 WebSocket: direct plaintext `ws://` and routed TLS-backed `wss://`.
  Plaintext `ws://` also works through plaintext and TLS-encrypted HTTP
  forward proxies with strict challenge-driven Basic authentication, and
  through authenticated SOCKS5 tunnels with local or remote DNS. These paths
  share the same ordered opening handshake, strict validation, and bounded
  message lifecycle.
- Opt-in, bounded, typed connection-setup retries for exact H1/H2/H3 and
  negotiated H1/H2 requests. They never change route or protocol or replay
  request bytes.
- HTTP/1.1 absolute-form forwarding for `http://` origins over plaintext and
  TLS proxies, with independent proxy authentication and trust policies.
  Challenge-driven Basic starts each logical request anonymously and allows
  one replay on a fresh connection over the same route. There is no learned
  challenge state, CONNECT conversion, protocol fallback, or direct fallback.
- Exact H3 through SOCKS5 with local or remote DNS, over an optionally
  authenticated RFC 1928 UDP ASSOCIATE. The TCP control connection is
  retained, and the H3 connection is reused per route, without direct or
  protocol fallback.

Code, tests, [Design](explanation/design.md), and
[Validation](explanation/validation.md) are the maintained record of these
decisions.
