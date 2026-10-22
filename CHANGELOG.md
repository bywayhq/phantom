# Changelog

## Unreleased

- Start SSE QUIC shutdown while workers finish, and retire the UDP endpoint
  after a failed graceful close. Cleanup timeouts include connection timings.

- Add Chrome 156 Windows script, stylesheet, image and font request templates,
  including CLI contexts and live HTTP/2 priority dependencies.
- Breaking: use `Http2RequestPriority` for template and per-request HTTP/2
  priorities. Migrate: wrap fixed `Http2Priority` values in `Fixed`; use
  `WeightBand` to choose a live dependency. Template JSON now requires
  `variant: "Fixed"` or `variant: "WeightBand"`. Recreate saved ticket state
  and session checkpoints for ticket-policy version 7.
- Breaking: remove `LayerEvidence::verified_fields()` and the catalog's
  `verified_fields` lists. Migrate: use `support()`, `references()` and
  `limitations()` to inspect a recipe; comparison details live in the tests.

- Stop sending queued HTTP/2 priority fields after the peer disables them.

- Fuzz content-coding headers and chained response decompression.

- Add `chrome-156-windows` with Chrome 156 Windows TLS, HTTP/2, HTTP/3,
  client hints and navigation headers.

- Clear the SOCKS5 UDP authentication buffer when negotiation ends or is
  cancelled.

- Report Node response-body cancellation consistently when abort races with a
  body read or collection.

- Breaking: add `Http3RequestSettings::alt_used_port` and
  `Http3AltUsedPort::{Explicit, OmitDefault}`. Firefox HTTP/3 recipes omit
  `:443` from generated `Alt-Used`; other ports and connection targets stay
  unchanged. Migrate: set the new field to `Explicit` to keep the previous
  value format, or `OmitDefault` to omit the HTTPS default port. Custom-profile
  JSON with HTTP/3 now requires `request.alt_used_port` as `"Explicit"` or
  `"OmitDefault"`; imports missing the field are rejected.
  Ticket-policy encoding advances to version 6; recreate saved ticket state
  and session checkpoints.

- Shorten profile descriptions, API documentation, guides and binding READMEs.
  Remove repeated caveats and capture history. Describe layer coverage per recipe.

- Capture HTTPS resource requests over HTTP/1.1 and HTTP/3 with
  `--resource-protocol`. Retain Chrome 156 Windows client-hint and resource
  observations.


- Clarify qlog file retention and write-failure behavior.

- Keep snapshot captures running when a browser closes a complete TLS opening.
  Retain the failed connection; a complete page and cleanup are still required.

- Capture ordered HTTP/2 script, stylesheet, image and font requests with the
  lifecycle tool's `resources` scenario. Retain Chrome 156 Windows captures
  from headful and headless runs.

- Reduce repeated parsing of fragmented HTTP/1 response headers.

- Restrict direct TCP and QUIC destinations with an optional client-wide
  address callback. Denied candidates never open a connection; proxy and custom
  connector routes fail explicitly while a policy is configured. Denial also
  stops SSE reconnects and WebSocket handshake retries.

- Add `chrome-155-linux` for fresh TLS, HTTP/2 and navigation headers, adapted
  from a pinned httpcloak preset. It does not supply TCP/IP or HTTP/3 recipes.

- Add `Http2IndexingLimit::FullTable` to index fields that fit the current
  HPACK table while retaining existing entries when a larger field is sent.

- Correct Firefox TCP documentation for retained backup connections, address
  family memory and failed-address history.

- Add `--observe-images` to retain ordered HTTP/2 image fields and initial
  HEADERS priority in Alt-Svc captures, rejecting credentials and normalizing
  local ports.
- Close headful Alt-Svc captures through their owned loopback browser endpoint
  after the page finishes. Require process exit and a complete NetLog.
- Reject truncated remote-protocol frames and unfinished fragmented messages
  when a browser closes before replying.

- Add `safari-26-macos` and `safari-26-ios` for TLS, HTTP/2 and navigation
  headers, adapted from pinned curl-impersonate and wreq-util presets.

- Breaking: catalog identities distinguish observed browsers from peer presets.
  Migrate: `ProfileMetadata::build`, `platform_release` and `environment` return
  `Option`; use `version()` for the advertised version and `identity()` for its
  origin. Catalog source declarations use schema 2 with `metadata.identity`.

- Select compiled profiles by fixed short names such as `chrome-154-windows`
  in Rust and the CLI. Full identifiers remain accepted; inspection retains the
  exact browser build, platform and recipe revision.
- Breaking: `phantom profiles list` prints short selectors. Migrate: use
  `phantom profiles describe <selector>` to read the full `id`. Catalog authors
  must add a unique, fixed `selector` to each profile declaration.

- Flush queued HTTP/3 frames before accepting another write or sending FIN.
  Preserve buffered data when a write future is cancelled and then resumed.

## 0.3.0 - 2026-10-21

- Reject malformed HTTP/3 response fields, invalid content lengths and DATA
  on bodyless responses. Reset only the affected stream.

- Breaking: `ResponseReadErrorKind::Json` has a different numeric discriminant
  after adding response error variants. Migrate: update Rust dependencies to
  0.3 and match named variants instead of persisting or comparing numeric casts.

- Connect Python, Go and Node.js clients through fixed Unix-domain sockets.

- Configure native connection pool retention, active and waiting requests,
  connection counts and negotiated setup waits in Python, Go and Node.js.

- Route Node.js requests through SOCKS4/4a proxies with explicit user IDs.

- Allow compatible URL dependency versions so downstream applications can use
  patched forks.

- Clear cached repository metadata before building Linux Python wheels.

- Configure ordered hostname overrides, local source addresses and network
  interfaces in Python, Go and Node.js. Preserve the hostname for TLS and HTTP.

- Retain received header sensitivity in Python, Go and Node.js.
  Migrate: Python response headers are `ResponseHeader` records with `name`,
  `value` and `sensitive` fields instead of name/value pairs. Rename Python
  and TypeScript `ResponseTrailer` imports to `ResponseHeader`. Node.js
  response header records are read-only.

- Stream ordered Node.js multipart fields, lazy files and closeable producers
  with explicit boundaries, encoded-byte limits and owned cleanup.

- Stream ordered Python multipart fields, files and producers with explicit
  boundaries and encoded-byte limits. Open files only when their part is read.

- Stream ordered Go multipart fields and readers with explicit boundaries and
  encoded-byte limits. Preserve upload cleanup errors after early responses.

- Remove the client benchmark harness and its benchmark-dependent release checks.

- Retain response trailers in wire order after body decoding and response
  authentication complete. Expose non-draining trailer snapshots in Python,
  Go and Node.js. Reject oversized HTTP/2 trailers and HTTP/3
  trailer pseudo-headers instead of returning incomplete or invalid fields.

- Reuse parsed PEM or DER client certificates in Python, Go and Node.js with
  a default identity and ordered per-origin overrides.

- Pin origin and HTTPS-proxy leaf public keys separately in Python, Go and
  Node.js while retaining certificate-chain and hostname verification.

- Accept the current audited Linux Python wheels and binding workflow artifacts
  when promoting verified prebuilt releases.

- Observe live request diagnostics from Python, Go and Node.js, including
  failed sends, separate response-body completion and connection/TLS facts.

- Remove the external-client benchmark adapters and their CI workflow.

- Prepare reusable form and multipart bodies in Python, Go and Node.js with
  ordered fields, explicit encoding limits and caller-selected boundaries.

- Send ordered request trailers and opt into `100-continue` waits from
  Python, Go and Node.js. Each attempt keeps the existing deadline and
  replay rules.

- Expose shared Python, Go and Node.js body-byte caps, pacing and coherent
  transfer counters. Attached Go requests retain their control after its
  caller handle closes.

- Export and restore encrypted Python, Go and Node.js session snapshots with
  explicit receiving routes, typed errors and fresh connection pools.

- Preserve completed HTTP/2 responses when a peer stops the upload with a
  clean stream reset. Release binding upload producers after an empty response.

- Stream Python, Go and Node.js upload producers with bounded native demand,
  explicit lengths, cancellation and owned cleanup. Include Python file setup
  in the total deadline. Preserve Python request errors when upload cleanup fails.

- Update the bundled root store and test certificate verifier for the emSign
  certificate distrust fixes.

- Reserve chosen loopback TCP ports in `phantom-testkit`, including refused
  connections that share their port number with a QUIC peer.

- Import raw JA3, JA4, Akamai, ClientHello and QUIC transport descriptions in
  Python, Go and Node.js with an explicit base profile. Reports distinguish
  observed and supplemented settings; hashes cannot reconstruct profiles.

- Build Python wheel candidates from one versioned source archive, retaining
  native dependency licenses and checking clean installs on all three hosts.
  Linux candidates target manylinux 2.28.

- Check Go native library versions before creating resources, and verify
  versioned module installs against matching native candidates.

- Expose bounded advertised-content decoding, redirect policies and history,
  and core retry scheduling in Python, Go and Node.js. Attempts retain shared
  deadlines, budgets and replay rules.

- Breaking: Node.js attempt budgets accept exact `bigint` counts, expose
  external admission and preserve counts beyond safe JavaScript integers.
  Migrate: narrow `AttemptBudget.remaining` from `number | bigint` before
  numeric arithmetic. Use `tryAdmit()` only for attempts outside Phantom.

- Add Node.js Alt-Svc racing-history clearing and refine binding setup,
  streaming, profile and shared-state documentation.

- Fork Python, Go and Node.js clients with independent connection pools and
  explicitly shared cookies, DNS, client hints, discovery state or tickets.

- Add immutable Go profile owners with editable JSON round trips, exact catalog
  selection and explicit request-template contexts.

- Add immutable Python and Node.js profiles with editable JSON round trips,
  exact catalog selection and explicit request-template contexts. Imported
  settings carry no catalog provenance; Node.js preserves large integers
  during editing.

- Expose Python response URLs, redirect counts and caller-enabled connection
  setup retry counts from the core response metadata.

- Add bounded Python text and JSON response readers, a `status_code` alias,
  and explicit HTTP status checks that leave response bodies readable.

- Expose Go response URLs, redirect counts and caller-enabled connection
  setup retry counts from the core response metadata.

- Add Python, Go and Node.js adapters to the controlled-peer benchmark for
  direct H1/H2/H3 requests through the public bindings. Reject measurements
  of launcher processes instead of the client runtime.

- Collect Node.js response bodies in one bounded native operation while
  retaining streaming reads, cancellation and byte limits.

- Add typed Python timeouts, explicit proxy authentication, separate origin
  and proxy trust roots, sensitive headers, base URLs and connection controls.

- Add Go phase timeouts, proxy authentication, separate origin/proxy trust
  roots, sensitive headers, base URLs and connection/cache controls.

- Add Node.js base URLs, phase timeout overrides, separate HTTPS-proxy roots,
  cache clearing and connection retirement. Report actual response protocol,
  final URL, redirect and connection retry counts, and timeout phases.

- Restore native C/C++ profile flags for automatic MSVC builds, including
  optimization, debug information and `NDEBUG` for the selected configuration.

- Add bounded UTF-8 text and JSON response readers to the Node.js adapter,
  with typed decoding errors and a streaming download example.

- Reject canceled Go requests before preparation and native admission. Close
  response bodies when `ReadAll` receives an invalid limit.

- Ship Python type information and explicit synchronous client signatures.

- Collect Python response bodies in one native operation while retaining
  byte limits, cancellation and streaming reads.

- Use fresh Python check environments so restored build caches cannot corrupt
  binding installation checks.

- Stop capture process groups before closing their control pipes to avoid
  intermittent cleanup failures on macOS.

- Add the optional `xml` feature and `response_xml` for bounded typed UTF-8
  response reads that preserve metadata. Reject DOCTYPE declarations,
  unsupported encodings, multiple roots and nesting beyond 128 levels.

- Add a controlled HTTP/2 upload cancellation comparison. Check remote stream
  cancellation after received headers, zero request DATA, and a healthy request
  on the same connection.

- Extend controlled client comparisons with HTTP/1.1 and HTTP/3 body
  cancellation checks, including incomplete responses and healthy concurrent
  requests. Retain unsupported cases and failed cancellation outcomes.

- Breaking: include opted-in HTTPS-record and ECH discovery in encrypted
  session checkpoints, preserving record order and expiry. Checkpoints now use
  format version 2. Migrate: create new checkpoints and set
  `https_record_checkpoint_namespace` when using a fixed or callback HTTPS
  resolver. Paired native resolvers cannot yet persist their discovery state.
- Add offline, versioned profile bundles with bounded validation and
  publisher-supplied provenance. Inspect and install bundles with the CLI,
  then select an exact digest and profile name. Rollback selects an older
  installed digest without changing existing clients.

- Prepare native CLI archive candidates with dependency notices, source hashes
  and extracted-install request checks. Uploads require passing installation
  checks on each target.

- Add optional charset-aware response text reads with separate input and UTF-8
  output limits. Invalid labels and malformed text return typed errors while
  preserving response metadata. Existing text reads remain strict UTF-8.

- Prevent a Windows stack overflow in CLI proxy requests when all library
  features are enabled.

- Add a native Node.js and TypeScript adapter with reusable clients, ordered
  headers, bounded streaming and file uploads, cookies, shared attempt budgets
  and cancellation. Source builds target Node.js 22 and 24. Prepare native
  package candidates with dependency notices and isolated installation checks
  on both Node.js versions.

- Import bounded, complete HTTP/1.1 requests with `Client::request_from_http1`.
  Match an explicit destination, retain supported field ordering and use the
  normal request builder. Ambiguous framing and proxy credentials are rejected;
  imports parse and reserialize requests rather than replaying wire bytes.

- Share live TLS tickets with `SessionSharing::tickets(true)` across independent
  connection pools. Single-use tickets are consumed once, and bounded stores
  survive either client being dropped. Portable transfers reject ambiguous
  active stores; caller-owned CONNECT-UDP pools reject conflicting sharing groups.

- Add caller-owned async checkpoint storage through `SessionStore` and explicit
  `Client::save_session` / `load_session` calls. Operations use absolute deadlines,
  preserve backend errors and restore into independent clients without changing
  the receiver. Storage backends receive encrypted snapshots, never keys.

- Add encrypted, versioned session checkpoints behind `session-snapshot`.
  Restore supported cookies, direct-route Alt-Svc entries and TLS tickets into
  a fresh client. Configuration mismatches and insufficient capacity fail
  without changing the receiving client. Address DNS and client hints are not saved.

- Retain capture failure causes through shared interruption handling. Move
  macOS capture provenance checks into tested scripts, with failure phases
  and command receipts preserved in the report. Capture acceptance is unchanged.

- Add the `phantom` CLI for requests, streaming files, explicit profile and
  proxy selection, measured diagnostics and editable profile JSON. Check clean
  CLI installation alongside the library release archives.

- Add a native Python adapter with reusable sync and async clients, bounded
  streaming, cookies, shared attempt budgets and cancellation. Prepare native
  wheel candidates with dependency notices and isolated installation checks.
  Upload only candidates that pass on their recorded host.

- Add a native Go adapter with reusable clients, bounded pull streaming,
  cookies, shared attempt budgets and cancellation. Prepare paired source and
  native-library archives with dependency notices, external consumer checks
  and the existing Go tests run from the extracted installation.

- Generate browser profile constructors from the catalog's component selections.
  New versions no longer need Python target tables or handwritten composition.
  Keep specific evidence limits and expand omitted unavailable-layer records.

- Update installation examples and profile coverage descriptions. Link the
  existing profile authoring, attempt budget, DNS and persistence APIs from
  the public guides, and clarify caller cookie placement and fork sharing.

- Let compatible low-level TCP and QUIC connector clones attach the same
  consuming TLS ticket cache while retaining separate DNS and connection pools.
  Reject attachment after incompatible profile, certificate or trust changes.

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
