# Request-client advisory regression ledger

This ledger converts relevant request-client advisories and issue histories
into Phantom invariants and tests. The 2026-09-17 review covered the completed
redirect, cookie, TLS-session, H1/H2/H3 lifecycle, proxy-authentication, and
WebSocket paths against the advisories linked below. It found no reproduced
advisory in those reviewed paths. Untested paths have no assessment. “Gap”
means the invariant lacks direct regression evidence; it is not a vulnerability
claim.

## Highest-value gaps

| Failure class and evidence | Current boundary | Required regression |
| --- | --- | --- |
| Protocol racing bypasses route policy or shares mutable request state ([tls-client releases](https://github.com/bogdanfinn/tls-client/releases)) | Phantom has no general racing/fallback and rejects unsupported H3 proxy routes before I/O. | Any future Auto, Alt-Svc, or racing leg inherits the exact route capability check and owns immutable request state. |

## Additional adversarial coverage

- Exercise thousands of H2 HEADERS/RST cycles and verify stream state returns
  to baseline while a healthy sibling continues. This covers the class in
  [h2 GHSA-f8vr-r385-rh5r](https://github.com/advisories/GHSA-f8vr-r385-rh5r).
- Add a no-panic unsolicited WebSocket subprotocol regression. Tiny and empty
  fragment floods now have a separate count bound; a later message-idle policy
  should cover slow arrival rate independently. See
  [Undici GHSA-vxpw-j846-p89q](https://github.com/nodejs/undici/security/advisories/GHSA-vxpw-j846-p89q)
  and
  [GHSA-rfgv-xxqx-mfg5](https://github.com/nodejs/undici/security/advisories/GHSA-rfgv-xxqx-mfg5).
- Retain the patched Quinn malformed-transport-parameter proof as a fuzz seed,
  then cover reordered, duplicated, truncated, and malformed-varint parameters.
  See
  [Quinn GHSA-6xvm-j4wr-6v98](https://github.com/quinn-rs/quinn/security/advisories/GHSA-6xvm-j4wr-6v98).
- Soak slow H1/H2/H3 and SSE consumers under an allocator/RSS ceiling and
  verify cancellation. Current H3 channels are bounded and one slow response
  already has sibling-progress coverage.
- Send hostile non-UTF8 ordinary and connection-specific response fields and
  prove the documented typed outcome without panic. See
  [wreq PR 1070](https://github.com/0x676e67/wreq/pull/1070).
- Test a malicious TLS downgrade canary through customized ClientHello settings
  to prove backend ServerHello validation remains authoritative. See
  [uTLS GHSA-pmc3-p9hx-jq96](https://github.com/refraction-networking/utls/security/advisories/GHSA-pmc3-p9hx-jq96).

## Existing relevant invariants

- Cookie domains are lowercased and IDNA-normalized before matching and public
  suffix policy. Regressions cover mixed-case suffixes, Unicode and A-label
  equivalence, terminal root dots, and the rule that a public suffix equal to
  the request host becomes host-only. This covers the canonicalization bypass
  class in [curl CVE-2023-46218](https://curl.se/docs/CVE-2023-46218.html).
- TLS sessions issued during a handshake remain pending until certificate and
  hostname authentication succeeds. A reusable TLS 1.2 session is restored
  only after actual resumption; a rejected ticket followed by authentication
  failure leaves the cache empty. Deterministic capture-state, wrong-host, and
  three-connection certificate-failure regressions cover the failure boundary,
  while positive TLS 1.2 and TLS 1.3 resumption tests remain in place. This
  covers the state-contamination class in
  [curl CVE-2024-0853](https://curl.se/docs/CVE-2024-0853.html).
- HTTP/1 response parsing owns a 32-KiB aggregate head limit, a 100-field
  limit, and a 16-KiB per-chunk size-line limit. Exact-boundary and overflow
  regressions cover aggregate heads, field count, whitespace and extensions in
  chunk-size lines, typed failures, and connection discard. The chunk-line
  bound is a canonical `wreq-proto` patch whose crates.io replay and focused
  commands are maintenance-tested. This covers the resource-exhaustion class
  in [curl CVE-2023-38039](https://curl.se/docs/CVE-2023-38039.html).
- Peer HTTP/2 `SETTINGS_MAX_FRAME_SIZE` values of zero and 16,777,216 are
  rejected on the live public connection path. Each case completes within the
  hostile-peer deadline, emits one `PROTOCOL_ERROR` GOAWAY, closes the
  connection, and never reaches the writer's zero-progress DATA path. This
  covers the failure class in
  [Go GO-2026-4918](https://pkg.go.dev/vuln/GO-2026-4918).
- HTTP/2 header-block continuation work is bounded from the configured receive
  header-list limit using separate encoded-byte, total-fragment, empty-fragment,
  and cumulative decoded-size ceilings. Encoded-byte overflow, seventeen empty
  fragments, seventeen tiny nonempty fragments, and a decoded `4x` overrun
  spread across legal Huffman fields each produce one specifically asserted
  `ENHANCE_YOUR_CALM` shutdown under an absolute deadline. A valid 65,535-byte
  decoded header list whose near-maximum Huffman representation spans fourteen
  frames remains accepted, and the connection serves a later stream. This
  covers the unbounded-processing class in
  [Go CVE-2023-45288](https://pkg.go.dev/vuln/GO-2024-2687).
- Cross-origin redirects strip `Authorization`, `Proxy-Authorization`, and
  caller cookies; client cookies are reconstructed for the new origin.
- HTTP Basic proxy credentials are validated before I/O and sent only after a
  valid 407 on one fresh same-route connection. Parser and public integration
  tests cover malformed/mixed challenges, retry bounds, ordered placement,
  plaintext and TLS proxies, H1/H2, pooled reuse, WSS, origin separation, and
  redacted diagnostics. This addresses the credential-boundary classes in
  [Requests GHSA-j8r2-6x86-q33q](https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q)
  and
  [urllib3 GHSA-qccp-gfcp-xxvc](https://github.com/urllib3/urllib3/security/advisories/GHSA-qccp-gfcp-xxvc).
- Overlong SOCKS hostnames fail before proxy I/O.
- H2 body cancellation resets one stream; the only automatic GOAWAY replay is
  a bodyless GET after `NO_ERROR`, at most once.
- Proxy TLS roots, hostname policy, ticket cache, and origin TLS state remain
  separate.
- WebSocket decompression enforces the message bound during inflation.
- WebSocket message assembly independently bounds data-frame count. The engine
  counts the initial frame and empty continuations, ignores interleaved control
  frames, rejects overflow before decompression or buffering, and enters a
  terminal receive state. Public integration proves the typed capacity error,
  automatic Pong behavior, and transport release.
- H3 tests cover missing/duplicate SETTINGS, invalid GOAWAY, QPACK blocking,
  critical-stream failure, and active bodies after GOAWAY.

## Constraints for future features

- Decompression needs decoded-byte, expansion-ratio, and CPU/time bounds before
  exposure ([urllib3 GHSA-mf9v-mfxr-j63j](https://github.com/urllib3/urllib3/security/advisories/GHSA-mf9v-mfxr-j63j)).
- Partial response retry must validate range/framing and cannot append decoded
  bytes under stale `Content-Length`
  ([Undici GHSA-8xcm-r25x-g524](https://github.com/nodejs/undici/security/advisories/GHSA-8xcm-r25x-g524)).
- Per-request TLS policy must participate in pool identity
  ([Requests GHSA-9wx4-h78v-vm56](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)).
- An optional SSRF policy must evaluate the resolved connection address, resist
  rebinding, and apply through every route; redirect limits alone are not that
  policy
  ([curl_cffi GHSA-qw2m-4pqf-rmpp](https://github.com/advisories/GHSA-qw2m-4pqf-rmpp)).
