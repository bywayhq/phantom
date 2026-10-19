# Changelog

## Unreleased

- Retain capture failure causes through shared interruption handling. Move
  macOS capture provenance checks into tested scripts, with failure phases
  and command receipts preserved in the report. Capture acceptance is unchanged.

- Generate browser profile constructors from the catalog's component selections.
  New versions no longer need Python target tables or handwritten composition.
  Keep specific evidence limits and expand omitted unavailable-layer records.

- Update installation examples and profile coverage descriptions. Link the
  existing profile authoring, attempt budget, DNS and persistence APIs from
  the public guides, and clarify caller cookie placement and fork sharing.

- Import raw JA3, raw JA4 and supported captured TCP ClientHello fields using
  explicit base settings. Check the imported projection against a fresh
  in-memory ClientHello and report which settings remain supplemented.
  Import supported ordered QUIC transport parameters with their integer widths
  and runtime-generated connection IDs. Fingerprint hashes remain insufficient
  to reconstruct a profile; imports do not assign browser identity.

- Add `Client::fork` for independent connection pools and shutdown, with
  explicitly shared cookies, DNS, client hints and discovery state. Forks keep
  the source configuration and limits; unselected state starts empty.

- Add caller-supplied direct TCP stream connectors and Unix-domain sockets.
  Requests retain URL authority, TLS verification, pool isolation and deadlines.
  Custom connectors own DNS and socket options; incompatible proxy, discovery
  and source-binding policies are rejected.

## 0.2.0 - 2026-10-19

- Refresh cookie public-suffix data and compatible Rust dependency locks.
  Keep Rust 1.88 as the minimum supported compiler.
- Update the httpcloak comparison adapter's Go dependencies to address the
  reported `golang.org/x/crypto` and `golang.org/x/net` advisories.
- Add explicit DNS-over-TLS address and HTTPS-record resolvers with verified
  endpoint identity, ordered bootstrap addresses, shared query limits and
  deadlines. Lookups reuse a TLS connection and support independent cancellation.
- Support direct cleartext HTTP/2 with prior knowledge when you explicitly
  select `HttpProtocol::Http2` for an `http://` URL. Connections reuse the
  existing HTTP/2 pool, attempt budgets and cancellation. Negotiated requests
  keep their browser behavior. HTTP/1.1 Upgrade and plaintext tunnels are
  unsupported, and an incompatible peer never triggers protocol fallback.

- Add opt-in shared upload and encoded-download caps and pacing, with separate
  reservation, transferred-body and decoded-response counters across resends.

- Add terminal client shutdown that rejects new requests and WebSocket openings,
  waits for existing caller-owned work, and releases retained connections.
  Client clones share shutdown state.

- Add bounded streaming multipart uploads with ordered fields, duplicate names,
  async readers and explicit filenames and boundaries. Reader data is pulled
  in 8 KiB chunks; incomplete uploads remain one-shot and cancellable.

- Add bounded custom redirect policies with resolved URL and method context.
  Callbacks can follow, stop with the redirect response, or reject a hop.
  **Breaking:** `RedirectPolicy` is now `Clone` rather than `Copy` and no longer
  implements equality, `UnwindSafe` or `RefUnwindSafe`. Migrate: clone shared
  policies explicitly, use `max_hops()` to inspect their limit, and keep policies
  outside closures that require unwind safety.

- **Breaking:** new variants change the numeric casts of `RequestErrorKind`,
  `WebSocketErrorKind` and `FingerprintImportErrorKind`. Migrate: match their
  variants instead of storing numeric casts. These enums have no stable numeric
  representation.

- Compare explicit HTTP/2 body cancellation while sibling streams complete.
  Require peer-observed CANCEL resets on one shared connection.

- Add authenticated CONNECT proxy workloads to all four comparison clients.

- Add bounded GET redirect chains and per-hop counts to comparison workloads.
- Avoid an extra copy of HTTP/2 request headers while preserving replay and
  response metadata.

- Add bounded POST uploads and verified peer upload totals to comparison workloads.
- Keep capture lifecycle tests responsive to process-startup failures on Windows.
- Add a pinned wreq adapter for controlled benchmark HTTP/1.1 and HTTP/2 GETs.
- Add a pinned httpcloak adapter for controlled benchmark HTTPS GETs.
- Record completed HTTP/2 disconnects and explicit HTTP/3 zero-code closes
  separately from failed benchmark responses.
- Add a pinned curl_cffi adapter for controlled benchmark GET workloads.
- Read benchmark HTTP/3 GET requests through their end before replying.
- Record completed benchmark QUIC transport `NO_ERROR` closes separately.
- Add client and per-request hooks for logical request start, final response
  heads and terminal send errors. Callbacks borrow metadata without consuming
  bodies or changing retries, redirects or header order.
- Let the benchmark controller run a separately pinned client command against
  its existing independent peer, retaining both commands and artifact identities.

- Add optional bounded redirect history with resolved URLs, method changes and
  response statuses. Debug output omits URLs, and later hops are counted.
- Add `RequestBuilder::redirect_policy` to override redirect following or hop
  limits for one request while retaining the client's policy for other requests.
- Import supported Akamai HTTP/2 descriptions with an explicit base profile
  and a report of observed and supplemented fields.
- Add `ClientBuilder::server_spki_pins` and `proxy_server_spki_pins` to
  restrict verified TLS leaf keys. Keep certificate and hostname checks, reject
  selected cleartext legs, and isolate sessions by origin and proxy pin policy.
- Add `Client::refresh_connections` to select fresh origin and proxy
  connections while existing setup and streams finish. Retain TLS tickets,
  cookies, discovery and admission limits.
- Add opt-in capped exponential backoff and full jitter for connection-setup
  and status retries. Delays keep the existing deadlines and retry budgets.
  **Breaking:** `StatusRetry::honor_retry_after` now sets a minimum wait
  instead of shortening the configured retry delay. Migrate: pass an initial
  delay of zero to `StatusRetry::new` to follow only the honored server delay.
- **Breaking:** apply profile `CookiePlacement` to caller-supplied cookies as
  well as cookie-jar fields. Keep caller values, duplicate order and sensitivity,
  with protocol-specific field spelling. This works without the `cookies` feature.
  Migrate: set `CookiePlacement::before_fields` for a custom position; caller
  cookie positions in the input list no longer determine their wire position.
- Include the Chrome 154 Windows navigation capture in `phantom-testkit`.
  Expose navigation and existing HTTP/1 browser captures through
  `phantom_testkit::fixtures`, usable without a repository checkout.
- Add the Chrome 154.0.8037.95 macOS catalog entry and `chrome::v154_macos`.
  Select macOS TCP and client hints with explicit reused-layer limits and
  required caller User-Agent slots. UDP and DNS recipes remain unavailable.

- Add `Client::close_idle_connections` to release idle origin and proxy
  connections while retaining active work, TLS tickets and session state.
- Rebuild the user documentation around docs.rs: a short README, an API
  overview, and four guides for getting started, browser profiles, requests
  and responses, and proxies.
- Remove the old repository documentation tree and its obsolete navigation.
- Add a bounded JSON example and update the first-request, request-template,
  and proxy examples to use the composed browser profiles.
