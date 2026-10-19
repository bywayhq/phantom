# Changelog

## Unreleased

- Add bounded streaming multipart uploads with ordered fields, duplicate names,
  async readers and explicit filenames and boundaries. Reader data is pulled
  in 8 KiB chunks; incomplete uploads remain one-shot and cancellable.

- Add bounded custom redirect policies with resolved URL and method context.
  Callbacks can follow, stop with the redirect response, or reject a hop.
  **Breaking:** `RedirectPolicy` is now `Clone` rather than `Copy` and no longer
  implements equality. Migrate: clone shared policies explicitly and use
  `max_hops()` to inspect their limit.

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
