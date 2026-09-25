# Changelog

Phantom has no releases or tags yet, so this file groups changes by commit
range instead of by version. Downstream projects pin an exact commit with
`rev`, and each breaking entry names the commit that introduced it and a
`Migrate:` note for moving past it.

To move `rev`, follow [Adding Phantom to a project](docs/guides/downstream.md).
The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Changes since `a84e73c` (2026-09-21), the first commit with a license grant.

### Breaking

- Phantom's patched dependencies are renamed `phantom-*` forks that Phantom's
  manifests reference by exact version and path, and the root `[patch]`
  tables are gone. A downstream crate now depends on Phantom with one line.
  (`9067a25`)
  Migrate: delete the `[patch]` table you copied from Phantom's root
  manifest; it patches packages that no longer appear in the dependency
  graph. See [Adding Phantom to a project](docs/guides/downstream.md).
- The browser recipes now carry one version per browser: Chrome
  154.0.8037.58, Edge 153.0.4234.48, and Firefox 156.0, captured on Windows 11.
  `chromium::v152_*` and every `v152_macos_*` alias, `chromium::v153_*`,
  `firefox::v154_*` and its `v154_macos_*` aliases, and the `safari` module
  are removed from `phantom-profile` and the `phantom` facade. The new
  recipes send a different fingerprint: Chrome 154 sorts its trust-anchor IDs
  and sends a new `sec-ch-ua` brand list. (`f129363`)
  Migrate: rename every `chromium::v152_*`, `chromium::v152_macos_*`, and
  `chromium::v153_*` function to the `chromium::v154_*` function with the same
  suffix, such as `v153_tcp` to `v154_tcp` or `v153_windows_navigation_template`
  to `v154_windows_navigation_template`. Replace
  `chromium::v152_macos_client_hints` with
  `chromium::v154_windows_client_hints`; no macOS client-hint recipe remains.
  Rename every `firefox::v154_*` and `firefox::v154_macos_*` function to
  `firefox::v156_*`, such as `v154_tls` to `v156_tls`.
  `safari::v18_5_macos_tls` has no replacement; build your own `TlsSettings`
  if you need it.
- The one-shot `phantom_net::http3::send_request`, `send_request_with_body`,
  `send_request_with_body_and_trailers`, `send_request_with_qlog`, and
  `send_request_with_body_and_qlog` take ordered request input instead of
  `http::Request<()>`, so they send the profile's pseudo-header order and the
  caller's field order. (`1abc9a7`)
  Migrate: replace the `request` argument with `&Http3RequestSettings` (for
  example `chromium::v154_http3_request()`), an `http::Method`, the authority
  as `&str`, an `OriginForm::parse("/path")?` target, and a
  `Vec<RequestHeader>` built with `RequestHeader::new(name, value)` in wire
  order. `OriginForm` and `RequestHeader` are exported from
  `phantom_net::http3`.
- `SessionBuilder::build` returns `Result<Client, BuildError>` instead of
  `Client`. It fails with `BuildErrorKind::InvalidPolicy` when Alt-Svc
  learning is enabled on a transport without negotiated HTTP/1.1+HTTP/2 or
  HTTP/3, as `ClientBuilder::build` already did. (`b5783a1`)
  Migrate: add `?` or handle the error after
  `client.session_builder()...build()`.
- `SseRequestBuilder::headers` takes `Vec<SseHeader>` instead of
  `Vec<RequestHeader>`. A literal `Last-Event-ID` field is rejected before any
  I/O. (`940e05c`)
  Migrate: wrap each field as `SseHeader::field(header)`. To place
  `Last-Event-ID` yourself, add `SseHeader::last_event_id("last-event-id")`
  at its position; without it, a nonempty ID is still appended last.
- `TlsSettings`, `Http2Settings`, and `Http3RequestSettings` gained public
  fields, so struct literals that name every field no longer compile:
  `TlsSettings::ech_grease_aeads` (`6d7a24c`),
  `Http2Settings::extended_connect_priority` (`4f64c99`),
  `Http2Settings::hpack` (`c41222c`), and
  `Http3RequestSettings::extended_connect_pseudo_header_order` (`7b76049`).
  Migrate: add `ech_grease_aeads: Vec::new()`,
  `extended_connect_priority: None`, `hpack: Default::default()`, and
  `extended_connect_pseudo_header_order: None` to keep the previous
  behavior, or fill the rest from a recipe with struct update syntax, such
  as `..chromium::v154_tls()`.
- `phantom_profile::ClientHintSlot` is no longer re-exported at the crate
  root; it is hidden plumbing for request templates. This affects only
  commits from `d7907cb` up to `31a3be0`. (`31a3be0`)
  Migrate: remove the import and use `RequestTemplate`.

- Request templates no longer check a caller's `User-Agent` or `sec-ch-ua`
  against the template's browser. `RequestIdentity`, `ProductVersion`, the
  `RequestTemplate::identity` field, and `RequestErrorKind::IdentityMismatch`
  are removed from `phantom-profile` and the `phantom` facade. The Edge
  templates mark `User-Agent` as a required caller slot instead, and a
  request that leaves a required slot empty fails before any I/O with
  `RequestErrorKind::RequestTemplate`. `RequestField::Caller` gains a
  `required` field. (`d88bd9e`)
  Migrate: delete the `identity` field from `RequestTemplate` literals, and
  mark a caller slot the request must fill with
  `RequestField::required_caller(name)` instead of a `RequestIdentity`. Add
  `required: false` where you build or match `RequestField::Caller` by its
  fields, or use `RequestField::caller`. Handle a missing required field
  under `RequestErrorKind::RequestTemplate` instead of `IdentityMismatch`.
- `RequestBuilder::template` takes `&PreparedRequestTemplate` instead of a
  `RequestTemplate` by value. `PreparedRequestTemplate::new` validates the
  template once, so invalid template data fails there with
  `InvalidRequestTemplate` instead of at `send`. Checks that depend on the
  request, such as a missing HTTP/3 list or an empty required caller slot,
  still fail at `send` with `RequestErrorKind::RequestTemplate`. (`6cdd227`)
  Migrate: replace `RequestBuilder::template(template)` with
  `RequestBuilder::template(&PreparedRequestTemplate::new(template)?)`, and
  prepare each template once and reuse it across requests.
- `ProfileMetadata`, `ProfileId`, `ClientFamily`, `Platform`, and their
  errors `InvalidProfileId` and `EmptyClientVersion` are removed from
  `phantom-profile` and `phantom::profile`. No client path read them.
  (`f01d7b1`)
  Migrate: delete the uses. There is no replacement; keep your own label if
  you need to name a profile.
- A caller-supplied `Host` field fails with `RequestErrorKind::InvalidHeader`
  instead of `RequestErrorKind::AuthorityHeader`, which is removed. The error
  message still names `Host`. (`f14cb08`)
  Migrate: match `RequestErrorKind::InvalidHeader` where you matched
  `RequestErrorKind::AuthorityHeader`.

### Added

- Chrome 154, Edge 153, and Firefox 156 recipes for TLS, HTTP/2, HTTP/3, QUIC,
  TCP, WebSocket, cookie placement, client hints, and request templates.
  Edge has TLS, HTTP/3 TLS, client-hint, and template recipes only, and
  Firefox has no HTTP/3, QUIC, or client-hint recipe.
  (`4a01b7f`, `be02e93`)
- Request templates: `RequestTemplate` and `RequestBuilder::template` send a
  captured navigation or no-store fetch field list for each protocol, with
  caller fields in their slots, the captured HTTP/2 priority, and profile
  hints at the captured hint positions. Before any I/O a request fails with
  `RequestErrorKind::RequestTemplate` when a required caller field is
  missing or a hint has no captured position. (`d7907cb`, `1ce99bb`,
  `f203d60`, and follow-up fixes)
- TCP socket options from the profile: `TcpSettings` with `TCP_NODELAY`,
  keepalive, and Chromium-style address racing (IPv6 first, a second attempt
  after 300 ms), set through `ClientProfile::with_tcp` and applied on every
  TCP path. `ClientBuilder::build` rejects settings the host cannot apply.
  (`e6f6ca1`, `b378e2b`, `e00ed90`, `8c9b267`)
- Cookie placement by profile: `ClientProfile::with_cookie_placement` puts
  the jar's `Cookie` field before a named caller field. The default stays
  last. (`3e0b7dd`)
- Opt-in Alt-Svc racing with broken-alternative backoff
  (`ClientBuilder::alt_svc_policy`, `AltSvcPolicy::race`), learning from
  HTTP/2 `ALTSVC` frames, and `Client::export_alt_svc` and
  `Client::import_alt_svc` snapshots. (`679961c`, `fd4be3d`, `5639b7c`)
- Opt-in retries on `RetryPolicy`: `with_status_retry` after listed 408,
  425, 429, 500, 502, 503, or 504 responses, honoring `Retry-After`;
  `with_unprocessed_replay` for HTTP/2 and HTTP/3 requests the peer did not
  process; and
  `with_reused_connection_replay` for a reused HTTP/1.1 connection that
  closes before the response. Negotiated HTTP/1.1+HTTP/2 requests also
  retry TCP connect failures under the caller's policy.
  (`66b6126`, `520243b`, `c05d6b9`, `37e70fe`)
- Opt-in response content decoding for gzip, deflate, br, and zstd through
  `RequestBuilder::content_decoding`, limited to codings the request's own
  `Accept-Encoding` advertises. (`c48e083`)
- Proxy routes: CONNECT-UDP (RFC 9298) for exact HTTP/3 through
  `Route::connect_udp` over an HTTP/3, HTTP/2, or HTTP/1.1 proxy leg with
  optional Basic authentication; HTTP/2 to HTTPS proxies through
  `HttpProxy::with_http2_transport`; negotiated HTTP/1.1+HTTP/2 and the
  Alt-Svc upgrade to HTTP/3 through SOCKS5. None of them falls back to
  another route or protocol. (`298856e`, `9e4ed55`, `ac0366c`, `a02d788`,
  `b7933cc`)
- WebSocket: HTTP/2 WebSockets through HTTP CONNECT and SOCKS5 proxies,
  `Client::websocket_with_profile_policy` to choose the connection by the
  profile's `WebSocketConnectionPolicy`, a profile rule for compressing empty
  messages, and one reopened extended CONNECT after `REFUSED_STREAM` when the
  profile allows it. (`ce5ec61`, `7f54bb8`, `5789072`, `fd2f701`)
- HTTP/3 extended CONNECT (RFC 9220) streams after the peer enables them.
  (`975808b`)
- Per-connection ECH GREASE AEAD selection; the Firefox recipes use it.
  (`6d7a24c`)
- `SseRequestBuilder::min_retry` sets a minimum reconnect delay. (`312c00c`)
- Parallel HTTP/1.1 connections: `Http1Settings`, set through
  `ClientProfile::with_http1`, bounds the HTTP/1.1 connections to each
  origin and route, idle ones included. `chromium::v154_http1` and
  `firefox::v156_http1` allow 6, from browser source, and
  `ClientBuilder::max_concurrent_http1_requests_per_origin` replaces the
  profile's value. A profile without `Http1Settings` keeps one connection,
  as before. (`8f012ec`, `b23067e`)
- Cookie-jar snapshots: `Client::export_cookies` and
  `Client::import_cookies` move the jar through storage the caller owns as a
  `CookieSnapshot` of `CookieSnapshotEntry` values. Import revalidates every
  entry and rejects the whole snapshot with `CookieSnapshotError` if one
  fails. The optional `serde` feature, part of `full`, implements
  `Serialize` and `Deserialize` for snapshots. (`e584e4d`, `f37e7e6`)
- HPACK encoder identity: `Http2Settings::hpack` (`Http2HpackSettings`)
  states which pseudo-headers stay out of the dynamic table, which static
  entry names a repeated name (`Http2StaticNameIndex`), and when a literal is
  Huffman-coded (`Http2HuffmanCoding`). The three types are exported from
  `phantom::profile`, so a custom profile can set them. (`5502db6`,
  `c41222c`)
- Negotiated HTTP/1.1+HTTP/2 requests can use an HTTP proxy route, over the
  HTTP/1.1 or HTTP/2 proxy transport. Each connection opens one CONNECT
  tunnel with the same CONNECT fields and Basic retry as an exact request,
  and ALPN in the origin handshake inside it selects the protocol. The route
  learns no Alt-Svc alternative, because the tunnel cannot carry QUIC, so
  these requests stay on HTTP/1.1 or HTTP/2. A CONNECT-UDP route still
  rejects negotiated requests with `RequestErrorKind::UnsupportedRoute`.
  (`ecdd984`, `5c2a749`)
- Exact HTTP/1.1 `http://` requests can use a SOCKS5 route, with local or
  remote DNS and optional RFC 1929 credentials. The request stays plaintext
  inside the TCP tunnel. `phantom_net::http1::Http1TlsConnector` gains
  `connect_plaintext_socks5_local_with_auth` and
  `connect_plaintext_socks5_remote_with_auth` for this path. (`0ad0621`)
- Negotiated requests accept `http://` URLs. Cleartext has no ALPN, so the
  request is sent as exact HTTP/1.1 on any route that carries exact HTTP/1.1
  `http://` (direct, HTTP proxy forwarding, or SOCKS5), reports
  `HttpProtocol::Http1`, and learns no Alt-Svc alternative. A CONNECT-UDP
  route still rejects it before I/O with `RequestErrorKind::UnsupportedRoute`.
  A negotiated redirect to an `http://` target follows the same rule.
  (`e05234b`, `2335c85`)

- The `diagnostics` feature of `phantom-http` writes a TLS key log and QUIC
  qlog files for your own connections. `ClientBuilder::key_log(capacity)`
  queues the TLS 1.3 secrets of every TCP and QUIC handshake in NSS key log
  format, and `Client::key_log` returns the `KeyLog` whose `write_pending`
  drains the queue. `ClientBuilder::qlog_dir(dir)` writes one JSON-SEQ qlog
  file per QUIC connection. The feature is off by default and not part of
  `full`, because a key log decrypts the client's traffic. (`a2519af`)

### Changed

- The cookie jar keeps `SameSite=Lax`, `SameSite=Strict`, and `Partitioned`
  cookies, treating every request as a top-level navigation, and evicts least
  recently used cookies above 180 per domain or 3300 in total instead of
  rejecting new ones. (`ddabed7`)
- `Secure`, `__Secure-`, and `__Host-` cookies can be stored from
  `localhost` and loopback origins over `http://`, as Chromium allows.
  (`e674491`)
- Negotiated HTTP/1.1+HTTP/2 requests waiting on connection setup to one
  origin are bounded; excess requests fail with
  `RequestErrorKind::Capacity`.
  (`4c3be30`)
- An SSE event source no longer reconnects after input, policy, route,
  runtime, or content-decoding failures; it returns them as errors.
  (`9a4a1f8`, `5f16fbc`)
- HTTP/1.1, HTTP/2, and HTTP/3 accept at most eight informational responses
  per request. HTTP/2 applies a local 393,216-byte response header list
  ceiling when the profile advertises none, and HTTP/3 caps decoded field
  sections at 256 KiB. The SETTINGS the client sends are unchanged.
  (`e51b9cc`, `f56d3a3`, `0b0367e`, `bf61599`, `e2d1778`)
- `chromium::v154_http2` and `firefox::v156_http2` set their browser's HPACK
  encoder choices, so WebSocket CONNECT matches the captures' HPACK
  representations. The choices apply to every request on the connection, not
  only CONNECT, so ordinary requests can encode differently too; on Firefox
  this changes the `:path` name index for most paths. (`c41222c`)
- `btls-sys` comes from `https://github.com/bywayhq/btls` instead of
  `https://github.com/0xARYA/btls`, at the same revision and archive
  checksum, and the `phantom-btls` and `phantom-tokio-btls` forks move to
  `0.5.6-phantom.2`. A downstream lockfile changes only the `btls-sys`
  source and those two versions. (`7744ce3`)
- A client with a redirect policy no longer rejects `http://` requests before
  I/O, and follows redirects to `http://` as well as `https://` targets. Each
  hop is still checked against the request's protocol and route before it is
  sent, and a change between `http://` and `https://` counts as cross-origin,
  so credential fields are removed. A target with another scheme still fails
  with `RequestErrorKind::Redirect`. (`17a5be5`)
- A caller's own `Proxy-Authorization` field on an `http://` request is
  forwarded to an HTTP proxy that has no configured credentials, so the
  first request can authenticate without a `407` round trip. The field still
  fails with `RequestErrorKind::InvalidHeader` before I/O on any other route
  and on a proxy with `with_basic_auth`. (`2f9d072`)

- A templated request no longer clones the template or validates it again
  on every `send`. `PreparedRequestTemplate` keeps the validated form and
  its client-hint placement behind an `Arc`, and the request path parses the
  advertised content codings once instead of once per redirect hop. The
  fields sent on the wire do not change. (`6cdd227`, `f14cb08`)

### Fixed

- HTTP/2 bounds empty and small DATA frames (RUSTSEC-2026-0258). (`03ef6de`)
- HTTP/2 and HTTP/3 keep sending the request body after an early response
  head instead of truncating it. (`8fcc374`, `f7ae758`)
- A missing Tokio runtime returns `RuntimeUnavailable` instead of panicking
  in the HTTP/1.1 and HTTP/2 drivers and in request timers. (`999c4aa`,
  `06c84d1`)
- The isolated TLS session cache resumes only sessions for the same
  hostname. (`c4d3c29`)
- Negotiated requests that select HTTP/2 retry a graceful `GOAWAY` once, as
  exact HTTP/2 requests already did. (`1bca6df`)
- Learned Alt-Svc entries are keyed by origin and route, and exact and
  Alt-Svc HTTP/3 connections to one origin no longer replace each other.
  (`c833c84`, `857c957`)
- Cookie `Domain` attributes on unlisted or private suffixes are rejected.
  (`d38e9c4`)
- SOCKS5 UDP associations end with their control connection, and relay
  send errors or oversized datagrams no longer close every QUIC connection on
  the association. (`783290c`, `09f3547`, `aa041a9`)
- HTTP/3 datagrams for closed request streams are dropped instead of failing
  the datagram router. (`d78b04d`)

### Removed

- The Safari 18.5 TLS recipe and the Chrome 152, Chrome 153, and Firefox 154
  recipes. See the first Breaking entry. (`f129363`)

## Before `a84e73c`

These commits carry no license grant; do not depend on them. The breaking
changes below matter only when moving from one of them to `a84e73c` or later.

### Breaking

- `TlsSettings::permute_extensions: bool` is replaced by
  `extension_order: ClientHelloExtensionOrder`. (`ba3c316`, 2026-09-15)
  Migrate: `permute_extensions: true` becomes
  `extension_order: ClientHelloExtensionOrder::Permuted`, and `false` becomes
  `ClientHelloExtensionOrder::BackendDefault`.
- `TlsSettings` loses `delegated_credential_signature_schemes` and
  `record_size_limit`, `ClientHelloExtension` loses `DelegatedCredential`,
  `RecordSizeLimit`, and `Padding`, and `TlsSettings::session_tickets: bool`
  is required. (`f3f5f90`, 2026-09-15)
  Migrate: delete the removed fields and variants, and set
  `session_tickets: true` to keep ticket resumption.
