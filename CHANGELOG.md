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

- The browser recipes now carry one version per browser: Chrome
  154.0.8037.58, Edge 153.0.4234.48, and Firefox 156.0, captured on Windows 11.
  `chromium::v152_*` and every `v152_macos_*` alias, `chromium::v153_*`,
  `firefox::v154_*` and its `v154_macos_*` aliases, and the `safari` module
  are removed from `phantom-profile` and the `phantom` facade. The new
  recipes send a different fingerprint: Chrome 154 sorts its trust-anchor IDs
  and sends a new `sec-ch-ua` brand list. (`f129363`)
  Migrate: replace `chromium::v152_macos_tls`, `v152_tls`, or `v153_tls` with
  `chromium::v154_tls`, and do the same for `_http2`, `_http3`, `_http3_tls`,
  `_http3_request`, and `_quic`. Replace `chromium::v152_macos_client_hints`
  with `chromium::v154_windows_client_hints`; no macOS client-hint recipe
  remains. Replace `firefox::v154_macos_tls` and `firefox::v154_macos_http2`
  with `firefox::v156_tls` and `firefox::v156_http2`. `safari::v18_5_macos_tls`
  has no replacement; build your own `TlsSettings` if you need it.
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
  `Http2Settings::extended_connect_priority` (`4f64c99`), and
  `Http3RequestSettings::extended_connect_pseudo_header_order` (`7b76049`).
  Migrate: add `ech_grease_aeads: Vec::new()`,
  `extended_connect_priority: None`, and
  `extended_connect_pseudo_header_order: None` to keep the previous
  behavior, or fill the rest from a recipe with struct update syntax, such
  as `..chromium::v154_tls()`.
- `phantom_profile::ClientHintSlot` is no longer re-exported at the crate
  root; it is hidden plumbing for request templates. This affects only
  commits from `d7907cb` up to `31a3be0`. (`31a3be0`)
  Migrate: remove the import and use `RequestTemplate`.

### Added

- Chrome 154, Edge 153, and Firefox 156 recipes for TLS, HTTP/2, HTTP/3, QUIC,
  TCP, WebSocket, cookie placement, client hints, and request templates.
  Edge has TLS, HTTP/3 TLS, client-hint, and template recipes only.
  (`4a01b7f`, `be02e93`)
- Request templates: `RequestTemplate` and `RequestBuilder::template` send a
  captured navigation or no-store fetch field list for each protocol, with
  caller fields in their slots, the captured HTTP/2 priority, and profile
  hints at the captured hint positions. Before any I/O a request fails with
  `RequestErrorKind::IdentityMismatch` when the caller's `User-Agent` or
  brand list names another browser or version, or when a required
  `User-Agent` is missing, and with `RequestErrorKind::RequestTemplate` when
  a hint has no captured position. (`d7907cb`, `1ce99bb`, `f203d60`, and
  follow-up fixes)
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
