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

- Allow transport enums to grow and retire unused validator wrappers.
  Migrate: keep a fallback arm when matching public `phantom-net` enums.
  Replace `http1::validate_request_body` and `_with_trailers` with
  `http1::validate_request_body_source_with_trailers`. Replace
  `http1::validate_forward_request`, `_body`, and `_body_with_trailers` with
  `http1::validate_forward_request_body_source_with_trailers`. Replace
  `http2::validate_request_body` and `_with_trailers` with
  `http2::validate_request_body_source_with_trailers`; validate extended
  CONNECT through connector operations instead of
  `http2::validate_extended_connect` and `_settings`. Inspect `kind()` on
  HTTP/1.1 and HTTP/2 errors and TLS errors for a stable category; their
  typed source chains remain available.

- Replace boolean URL trust selectors with `UrlTrust`. Migrate: pass
  `UrlTrust::PotentiallyTrustworthy` or `UrlTrust::Untrustworthy` to
  `RequestField::default_value` and `WebSocketField::default_value`.
  Profile validation errors now expose `ValidationErrorKind` through
  `kind()`. Field names and reasons remain diagnostic details.

- Keep transport wrapper causes out of `Display`. Migrate: use
  `std::error::Error::source` to inspect or report the original causes of
  HTTP connection, TLS, proxy, and protocol errors. Their categories and
  source chains are unchanged.

- Check required request-template slots only on reachable protocols. Migrate:
  supply fields required by the selected protocol, negotiated protocols, and
  enabled HTTP/2 fallback. A pinned HTTP/3 alternative needs only HTTP/3
  fields. Firefox's exact HTTP/2 upload uses its literal `priority` value;
  its HTTP/1.1 upload still requires your caller `Priority` value.

- Allow future TCP policy variants. Migrate: keep a fallback arm when
  matching `TcpKeepalivePolicy`, `TcpAddressAdvance`, and
  `TcpAddressSelection`. Unsupported policies fail recoverably before I/O.

- Keep `BuildError`, `WebSocketError`, and `SseError` causes out of automatic
  formatting. Migrate: inspect `std::error::Error::source` for typed details
  instead of parsing `Display` or `Debug`. Sources, rejecting WebSocket
  responses, timeout phases, and retry observations remain available.

- Check trust-anchor ID orders before configuring a profile. Migrate:
  construct `TrustAnchorOrder::new(ids)?` for `TrustAnchorIds::Fixed`.
  Construct `TrustAnchorOrders::new(orders)?` for `PerClient` and
  `PerConnection`. Empty fixed orders remain distinct from an omitted
  extension. Repeated IDs and weighted candidate orders keep their order.
  Use `as_slice()` on the checked values to read their contents.

- Separate client timeout policies from per-request overrides. Migrate:
  keep `RequestTimeouts` on `ClientBuilder::request_timeouts`; pass
  `RequestTimeoutOverrides` to `RequestBuilder::timeouts` and
  `SseRequestBuilder::request_timeouts`. Each override is `Inherit`,
  `Disabled`, or `Limit(duration)`; unchanged fields inherit client limits.

- Replace independent ECH fields with checked `EchSettings`. Migrate:
  replace `ech_grease`, `ech_grease_payload_length`, `ech_grease_aeads`, and
  `ech_from_https_records` with `TlsSettings::ech`. Choose `Disabled`,
  `Grease(EchGreaseSettings::new(payload_length, aeads)?)`, or
  `HttpsRecords(settings)`. The checked constructor preserves valid payload
  and AEAD choices. HTTPS record discovery remains opt-in.

- Keep `RequestError` formatting to its category and safe context.
  Migrate: use `std::error::Error::source` to inspect the original cause
  instead of parsing `Display` or `Debug`. The source chain is preserved.
  `origin()` exposes only scheme, canonical host, and effective port;
  `replay_observation()` reports connection observations, not permission
  to resend a method or body.

- Use checked TLS version ranges and session-ticket settings. Migrate:
  replace `TlsSettings::min_version` and `max_version` with `versions:
  TlsVersionRange::new(min, max)?`, `only(version)`, or `TLS12_TO_TLS13`.
  Replace the `session_tickets` boolean and `session_tickets_per_origin`
  count with `SessionTickets::enabled(count)?` or `disabled()`. Enabled
  TCP limits remain `1..=10`; disabled tickets carry no limit. QUIC uses
  enablement while retaining its separate ticket storage policy.


- Group browser recipes under `profile::browser::{chrome, edge, brave,
  opera, firefox}` in the facade and `phantom_profile::browser` in the
  profile crate. Migrate: replace the old root browser modules with these
  modules. Replace `chromium` with `browser::chrome`. Android recipes now
  share their brand's module and include `_android_` after the version.
  Rename `*_tls` to `*_tcp_tls` and `*_http3_tls` to `*_quic_tls`.

- Hide HTTP backend error types from `phantom-net`'s public signatures.
  Migrate: `Http1Error::Protocol` and `ReusedConnectionClosed` now carry an
  opaque `Http1ProtocolError`; inspect the underlying error through
  `std::error::Error::source`. The public `From<wreq_proto::Error>` and
  `From<h3::error::StreamError>` conversions are removed. Protocol operations
  still return `Http1Error` and `Http3Error`, with their existing categories
  and replay signals.


- Keep QUIC packet cryptography private. Migrate: replace direct use of
  `HeaderProtectionKey`, `PacketProtectionKey`, `InitialKeys`,
  `derive_initial_keys`, `DirectionKeys`, `EndpointSide`,
  `retry_integrity_tag`, `verify_retry_integrity`, and `QuicVersion` with
  `QuicClientConfig` through Quinn's crypto traits. The `server` feature
  provides `QuicServerConfig`. `StatelessResetKey` remains available for
  endpoint configuration.

- `phantom-net` connectors now take route values. HTTP/1.1 uses
  `connect(Http1Route)`, `send`, and `upgrade`; HTTP/2 uses
  `connect(Http2Route)`, `send`, and `extended_connect`. Negotiated HTTP/1.1
  or HTTP/2 uses `connect(OriginRoute)`. HTTP/3 uses
  `connect(DatagramRoute, server_name)` and `send`. Route-specific connection,
  request, GET, and Upgrade methods are removed. Migrate: construct
  `TcpRoute::Direct`, `HttpConnect`, `Socks5`, or `Connected`, then select
  `OriginRoute::Plaintext` or `Tls`. Wrap it in the protocol's `Origin`
  route, or use `Forward` with the proxy's transport. HTTP/1.1 origin routes
  take `Http1Target::Origin`; forwarding takes `Http1Target::Absolute`.
  Replace GET helpers with `send`, `Method::GET`, and no body. HTTP/1.1 and
  negotiated connection openings return `(connection, optional_slower)`.
  Replace direct ECH methods with `DirectTlsSetup::Ech` and a pinned lookup;
  replace slower-connection methods with `KeepSlower`, or plaintext family
  memory. These policies require a direct route. Keep-slower setup is only
  supported for HTTP/1.1 and negotiated connection openings. Wrap supplied
  streams in `ConnectedStream::new` instead of passing them to a connector.
  For HTTP/3, use `DatagramRoute::Direct`, `Socks5`, or `ConnectUdp`, and
  `DirectEch` for a pinned ECH lookup. Keep dial targets, origin TLS names,
  and request authorities separate. Connection-based HTTP/2 and HTTP/3
  WebSocket operations remain available.

- Remove the raw HTTP/1.1 and HTTP/2 one-shot free functions. Migrate:
  replace `http1::send_get`, `send_request`, `send_request_body`,
  `send_request_body_with_trailers`, `send_forward_request`,
  `send_forward_request_body`, and `send_forward_request_body_with_trailers`,
  and `http2::send_get`, `send_request`, `send_request_with_trailers`,
  `send_request_body`, and `send_request_body_with_trailers` with protocol
  connector operations. For supplied raw or already secured streams, use
  `Http1Connection::connect` or `Http2Connection::connect`, then their request
  methods. Validate input before opening when needed. Drop the connection
  handle after dispatch to retain one-shot ownership.
- Remove endpoint-only proxy setup helpers from `phantom-net`'s public API.
  Migrate: replace `connect_http_tunnel_direct[_with_basic_auth]` and
  `connect_socks5_tunnel_{direct,local}[_with_auth]` with protocol connector
  operations using `TcpRoute::HttpConnect` or `TcpRoute::Socks5`. Replace
  `HttpsProxyConnector::connect_forward_http2[_with_credentials]` with
  `Http2TlsConnector::connect(Http2Route::Forward { ... })`.
  `connect_http_tunnel` remains available for a supplied proxy stream.
- Replace the six raw HTTP/3 one-shot helpers with `send_with_config`.
  Migrate: replace `send_get`, `send_request`, `send_request_with_body`,
  `send_request_with_body_and_trailers`, `send_request_with_qlog`, and
  `send_request_with_body_and_qlog` with `send_with_config`. Pass the method
  explicitly, then supply body, ordered trailers, and optional bounded qlog
  capture through `Http3SendOptions`. For profile-based routing, use
  `Http3Connector::send`.

- `Http2Settings` has a new field, `idle_timeout` (`Http2IdleTimeout`), so
  literals that list every field no longer compile.
  `Http2Connection::idle_time_left` is new, and `is_reusable` returns
  `false` once that time runs out. Migrate: add
  `idle_timeout: Http2IdleTimeout::Unlimited` to the literal; to keep the
  old Firefox behavior, set `idle_timeout` to `Http2IdleTimeout::Unlimited`
  on `firefox::v157_http2()`.
- `Http3RequestSettings` gained the public field `alt_used`, of the new
  `#[non_exhaustive]` enum `Http3AltUsed`, so struct literals that name
  every field no longer compile. With `Append`, an HTTP/3 request sent to an
  alternative service, learned from `Alt-Svc` or pinned with
  `RequestBuilder::alt_svc_alternative`, carries one `Alt-Used` field after
  every other field; with `Omit`, it carries none.
  `chromium::v154_http3_request`, and so every Chromium-family recipe, sets
  `Omit`, and `firefox::v157_http3_request` sets `Append`
  ([evidence](docs/explanation/validation.md#alt-svc-http3-upgrade-evidence)).
  In `phantom-net`, `Http3Connector::sends_alt_used` reports the setting. A
  caller-supplied `Alt-Used` field or trailer is still rejected before any
  I/O. Migrate: add `alt_used: Http3AltUsed::Append` to an
  `Http3RequestSettings` literal to keep sending the field, or
  `alt_used: Http3AltUsed::Omit` to send none; to keep sending it with the
  Chromium recipe, set `alt_used = Http3AltUsed::Append` on the value
  `chromium::v154_http3_request` returns.
- `TlsSettings` has a new field, `session_ticket_order`
  (`SessionTicketOrder`), so literals that list every field no longer
  compile. It selects the ticket a new TCP connection offers and the one
  dropped when the origin is full. `NewestFirst` keeps the old behavior;
  `OldestConnectionFirst` offers the oldest connection's tickets, newest
  of them first; `OldestFirst` offers the oldest ticket. The Firefox orders
  drop the ticket they would offer next.
  Migrate: add `session_ticket_order: SessionTicketOrder::NewestFirst` to
  a `TlsSettings` literal to keep the old behavior, or copy the setting
  from a browser recipe.
- `WebSocketConnectionPolicy` gained the public field
  `proxied_http2_session`, of the new `#[non_exhaustive]` enum
  `WebSocketProxiedSession`, so struct literals that name every field no
  longer compile. With `Reuse`, a profile-policy `wss://` WebSocket on an
  HTTP proxy or SOCKS5 route opens as an extended CONNECT stream on a
  capable pooled HTTP/2 session to the same origin and route, negotiated or
  exact, inside that session's tunnel, with no proxy CONNECT or
  `Proxy-Authorization` of its own; proxy credentials are part of the route,
  so a session tunnelled with other credentials is never used. With
  `Ignore`, it opens the connection `without_http2_session` names, through
  its own tunnel. `chromium::v154_websocket`, and so
  `chrome_android::v154_websocket` and `brave_android::v153_websocket`, and
  `firefox::v157_websocket` set `Reuse`, as Chromium 154 and Firefox 157
  source do
  ([evidence](docs/explanation/validation.md#websocket-browser-evidence));
  before, such a WebSocket checked only the exact HTTP/2 pool on a proxy
  route. The direct route is unchanged. Migrate: add `proxied_http2_session:
  WebSocketProxiedSession::Reuse` to a `WebSocketConnectionPolicy` literal
  for a WebSocket that joins a proxied session as the browsers do, or
  `Ignore` for one that never does; no value keeps the old reuse of exact
  sessions alone.
- An `AltSvcSnapshot` holds one entry for each alternative an origin's
  field listed, consecutive and in field order, and
  `Client::import_alt_svc` makes the entries for one origin its list of
  alternatives, up to eight, ranking the origin where its last entry
  stands. Before, a snapshot held one entry per origin and a later entry
  for the same origin replaced an earlier one. Migrate: a caller that
  stores an export keyed by origin keeps every entry of each origin, in
  order; to import only one alternative per origin, keep only its latest
  entry before `import_alt_svc`.
- `Http2Settings` gained the public fields `idle_ping_after` and
  `idle_ping_timeout` (`Option<Duration>`). `firefox::v157_http2` sets 58
  and 8 seconds: a connection that has read nothing for 58 seconds sends a
  PING with a zero payload whether or not requests are open, and one that
  then goes 8 seconds with nothing read closes the connection with
  `GOAWAY(0, INTERNAL_ERROR)`, failing its open requests with
  `Http2Error::PingTimeout`, as Firefox 157 does. Before, a Firefox profile
  sent no PING and kept such a connection. `Http2Settings::validate` rejects
  a zero or out-of-range value and a timeout without `idle_ping_after`
  ([evidence](docs/explanation/validation.md#http2-idle-ping-evidence)).
  `ping_failure_retries` covers a failed idle PING as well, and a value
  above 0 is valid with either `ping_timeout` or `idle_ping_timeout`.
  The vendored `phantom-http2` is now `0.5.20-phantom.10`, with the client
  builder option `idle_ping`, and `phantom-wreq-proto` `0.2.5-phantom.10`.
  Migrate: add `idle_ping_after: None, idle_ping_timeout: None` to an
  `Http2Settings` literal; set both to `None` on `firefox::v157_http2()` to
  keep the old behavior.
- `Http2Settings` gained the public field `ping_failure_retries: u8`.
  `chromium::v154_http2`, and so every Chromium-family recipe, sets 2:
  a request whose HTTP/2 connection closed itself after an unanswered PING
  before the request's response head is sent again at once on another
  connection, up to twice per redirect hop, whatever the method and the
  retry policy, as Chrome 154 resends after `ERR_HTTP2_PING_FAILED`. A
  negotiated request sends the field lists of the failed attempt; an exact
  request builds its list again. Before, the request failed with
  `Http2Error::PingTimeout`, which a one-shot streaming body still returns.
  `firefox::v157_http2` sets 0, as Firefox 157 restarts no such request.
  `Http2Settings::validate` rejects a value above 0 without `ping_timeout`
  ([evidence](docs/explanation/validation.md#http2-preface-ping-evidence)).
  Migrate: add `ping_failure_retries: 0` to an `Http2Settings` literal; set
  it to 0 on a Chromium recipe to keep the old failure, and wherever such a
  recipe's `ping_timeout` or `preface_ping_after` is cleared.
- `firefox::v157_tcp` selects addresses with `TcpBackupConnection`, a
  250 ms delay and a 5-second backup timeout for a known family, and
  `firefox::v157_http1` sets `Http1IdleTimeout::ClosedOnTimer` with 115
  seconds, as Firefox 157 does
  ([evidence](docs/explanation/validation.md#firefox-socket-hook-evidence)).
  A Firefox profile now opens an IPv4 backup attempt 250 ms after a slow
  first attempt, keeps the slower connection on direct HTTP/1.1 and
  negotiated requests, connects to the family that worked, and closes an
  idle HTTP/1.1 connection 115 to 116 seconds after its last response;
  before, it tried the addresses one at a time and kept an idle connection
  until the server closed it. For a Firefox profile, connections to a
  proxy, WebSocket connections, exact HTTP/2 requests, and connections that
  offer ECH from HTTPS records now start the backup as well but close the
  slower attempt, where before they tried the addresses one at a time; they
  neither use nor learn the origin's address family. Chromium-family
  profiles keep their behavior. Migrate: to keep the old Firefox behavior,
  set `address_selection` of `firefox::v157_tcp()` to
  `TcpAddressSelection::Sequential(TcpAddressAdvance::AfterRefusalOrTimeout)`
  and `idle_timeout` of `firefox::v157_http1()` to
  `Http1IdleTimeout::Unlimited`.
- `TcpBackupConnection` gained the public field
  `known_family_backup_timeout` (`Option<Duration>`), whole seconds up to
  the new `phantom_profile::tcp::MAX_TCP_BACKUP_TIMEOUT_SECONDS`, 600. Once
  the backup has started, the attempt that lost now keeps connecting for a
  caller that keeps it, and a caller that remembers an origin's address
  family has both attempts try that family alone, the backup with
  `known_family_backup_timeout` on each connect, and the other family once
  every address of it fails. A caller that keeps neither closes the slower
  attempt, as before. Migrate: add `known_family_backup_timeout: None` to a
  `TcpBackupConnection` literal, or `Some(Duration::from_secs(5))` as
  Firefox sets it.
- The macOS Opera and Firefox recipes move to the Windows host's builds,
  captured again on macOS 15.5 arm64: `opera::v135_macos_client_hints`,
  `firefox::v156_macos_navigation_template`, and
  `firefox::v156_macos_fetch_no_store_template` are removed from
  `phantom-profile` and the `phantom` facade. `opera::v136_macos_client_hints`
  sends Opera 136's brand list,
  `"Chromium";v="152", "Not?A_Brand";v="24", "Opera";v="136"`, and the
  136.0.6008.52 full versions, which are the values of
  `opera::v136_windows_client_hints` with macOS platform data, so it no
  longer mixes two Opera builds with `opera::v136_tls`. The Firefox macOS
  templates send `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15;
  rv:157.0) Gecko/20100101 Firefox/157.0`; their other fields are unchanged
  ([evidence](docs/explanation/validation.md#macos-recipes)).
  Migrate: rename `opera::v135_macos_client_hints` to
  `opera::v136_macos_client_hints`,
  `firefox::v156_macos_navigation_template` to
  `firefox::v157_macos_navigation_template`, and
  `firefox::v156_macos_fetch_no_store_template` to
  `firefox::v157_macos_fetch_no_store_template`.
- A request on a Tokio runtime without I/O enabled no longer reuses a warm
  HTTP/3 connection that another runtime opened; it fails with
  `RequestErrorKind::RuntimeUnavailable`, because pooled connections now
  belong to the runtime that opened them. Migrate: send from a runtime with
  I/O enabled.
- `DnsCacheSettings` has a `min_record_ttl` field. An answer that carries a
  record TTL is kept for that TTL or `min_record_ttl`, whichever is longer,
  and `ttl` now applies only to an answer without one, as from the
  operating system. `chromium::v154_dns_cache` sets 60 s, Chromium 154's
  `kMinimumTTLSeconds`, and `firefox::v157_dns_cache` sets zero, as Firefox
  157 keeps the TTL it reads on Windows without a lower bound
  ([evidence](docs/explanation/validation.md#address-cache-evidence)).
  Migrate: add `min_record_ttl` to a `DnsCacheSettings` literal, such as
  `Duration::ZERO` to keep the record TTL as it is, or build from a recipe
  with `..chromium::v154_dns_cache()`.
- `ServerAuthentication::Disabled` is now
  `ServerAuthentication::DangerDisabled`, and exists only with the new
  non-default `danger-disable-verification` feature of `phantom-http` and
  `phantom-net`, which `full` leaves out. A runtime value, read from
  configuration for example, could turn off certificate chain and name
  checks in any build; a build must now opt in. The
  `phantom-net` example `tls_anvil_client` requires the feature.
  `ServerAuthentication::verifies` tells whether a policy verifies the
  server. Migrate: enable `danger-disable-verification` and replace
  `ServerAuthentication::Disabled` with
  `ServerAuthentication::DangerDisabled`; replace a comparison with
  `Disabled` by `!policy.verifies()`.
- `TlsSettings` has a `close_notify` field: whether shutting down a TLS
  connection over TCP sends a `close_notify` alert before the TCP FIN. The
  Chromium-family recipes leave it unset and send only the FIN, as Chrome
  154 does when it aborts a response, ends a connection after a failed
  PING, or exits; `firefox::v157_tls` and `firefox_android::v156_tls` set
  it, as Firefox 157 sent the alert when it aborted a response and at exit
  ([evidence](docs/explanation/validation.md#tls-close-evidence)). Before,
  every shutdown sent the alert. Migrate: add `close_notify: true` to a
  `TlsSettings` literal to keep the old behavior, or `false` to close as
  Chromium does.
- `TlsSettings::requested_trust_anchor_ids` is an `Option<TrustAnchorIds>`
  instead of an `Option<Vec<Box<[u8]>>>`. `TrustAnchorIds::Fixed(ids)` sends
  one order on every connection, as before. `PerClient(orders)` draws one of
  the listed orders for each client and keeps it on all of the client's
  connections, and `PerConnection(orders)` draws one for each connection;
  each listed order is equally likely, and every order must list the same
  IDs. `Client::build` draws each `PerClient` list before it builds any
  connector, so the client's HTTP/1.1, HTTP/2, and WebSocket connections,
  its connections to an HTTPS proxy, and its TLS connections through a
  proxy tunnel send one order; it fails with `InvalidProfile` when the
  orders of a `PerClient` list hold different IDs, in the TLS or the HTTP/3
  TLS settings. `ClientProfile::draw_per_client` and
  `TlsSettings::draw_per_client` make that draw with a caller's fallible
  random source, and the new `phantom_net::draw_per_client` makes it with
  BoringSSL's random number generator. `opera::v136_tls` now draws from
  the 29 Opera 136 processes' TCP orders, per client, and
  `opera::v136_http3_tls` from the 20 QUIC ClientHellos' orders, per
  connection, where each sent one fixed order
  ([evidence](docs/explanation/validation.md#opera-136-trust-anchor-id-order)).
  The Chrome and Chrome for Android recipes keep their one sorted list.
  Migrate: replace `requested_trust_anchor_ids: Some(ids)` with
  `Some(TrustAnchorIds::Fixed(ids))`, and match `TrustAnchorIds::Fixed` or
  call `TrustAnchorIds::orders` where code read the list.
- `TlsSettings::ech_grease_payload_length` is an `EchGreasePayloadLength`
  instead of an `Option<u16>`. `BackendDefault` keeps the TLS backend's
  length, drawn per connection; `Exact(n)` sends `n` payload bytes; and
  `FromClientHello { maximum_name_length }` sizes the payload from the
  ClientHello that carries it, as Firefox 157's NSS does. `firefox::v157_tls`,
  `firefox::v157_http3_tls`, and `firefox_android::v156_tls` now use
  `FromClientHello { maximum_name_length: 100 }`: a fresh ClientHello to a
  host name still carries 240 bytes, but a resumed one carries Firefox's 368
  with the capture servers' tickets where it carried 240, and one to an IP
  literal is padded by the address text, as Firefox pads it
  ([evidence](docs/explanation/validation.md#firefox-ech-grease-payload-evidence)).
  The Chromium-family recipes keep `BackendDefault`.
  Migrate: replace `ech_grease_payload_length: None` with
  `EchGreasePayloadLength::BackendDefault` and `Some(n)` with
  `EchGreasePayloadLength::Exact(n)`. To keep the old Firefox length, set
  `Exact(240)` on the returned settings.
- `TlsSettings` gained the public field
  `tls12_extensions_in_tls13_client_hello` (`bool`), so struct literals that
  name every field no longer compile. When it is set, a ClientHello whose
  minimum version is TLS 1.3 also sends an empty `extended_master_secret`
  and a `renegotiation_info` with an empty renegotiated connection, as NSS
  does; a ClientHello that also offers TLS 1.2 sends both anyway. The
  Firefox recipes set it, and every other recipe leaves it `false`.
  Migrate: add `tls12_extensions_in_tls13_client_hello: false` to a
  `TlsSettings` literal, or build it from a recipe with `..recipe`.
- `TcpSettings` gained the public field `port_randomization`
  (`Option<TcpPortRandomization>`), so struct literals that name every field
  no longer compile. `TcpPortRandomization { minimum_windows_build }` sets
  `SO_RANDOMIZE_PORT` on each TCP socket, after the other options and before
  the socket is bound or connects, on Windows 10.0 from that build on;
  Windows then picks each connection's local port at random instead of in
  sequence. A rejection fails the connection attempt, and the setting has
  no effect off Windows. `chromium::v154_tcp` sets it from build 22621
  (Windows 11 22H2), as Chromium 154 does, so Chrome, Brave, Edge, and Opera
  profiles on such a host now connect from random local ports; the Chrome
  154, Edge 154, and Opera 136 hook logs show the option on every TCP socket
  ([evidence](docs/explanation/validation.md#socket-hook-evidence)).
  `firefox::v157_tcp` leaves it `None`, as Firefox 157 does. `phantom-net`
  sets it through a Windows-only FFI module, the workspace's second unsafe
  code boundary
  ([audit](docs/explanation/design.md#windows-port-randomization-audit)).
  Migrate: add `port_randomization: None` to a `TcpSettings` literal to keep
  the host's port choice, or end the literal with `..TcpSettings::default()`;
  copy the value from `chromium::v154_tcp()` to match Chromium.
- `TcpSettings` replaces `keepalive: Option<TcpKeepalive>` with
  `keepalive: TcpKeepalivePolicy` and `address_racing:
  Option<TcpAddressRacing>` with `address_selection: TcpAddressSelection`,
  gains `send_buffer_size: Option<NonZeroU32>`, and implements `Default`,
  which asks for nothing. `TcpKeepalivePolicy::Schedule` takes a
  `TcpKeepaliveSchedule` that changes keepalive over an HTTP connection's
  life; `TcpAddressSelection::Sequential` takes a `TcpAddressAdvance`, the
  failures that move an attempt to the next address; and
  `TcpAddressSelection::Backup` takes a `TcpBackupConnection`, an IPv4
  backup attempt for a slow first one, which closes the slower attempt where
  Firefox keeps it. `firefox::v157_tcp` now uses the schedule and a
  524,288-byte `SO_SNDBUF`, so a Firefox profile's connection sends
  keepalive probes after 10 s idle; after 600 s once a request has run 72 s
  (with a one-second probe interval) or the connection was upgraded; and
  none after HTTP/2 is negotiated. Before, it set no keepalive. It still
  tries the addresses one at a time, but now moves to the next only after a
  refused, unreachable, or timed-out connect, as Firefox does
  ([evidence](docs/explanation/validation.md#firefox-socket-hook-evidence)).
  `chromium::v154_tcp` keeps its behavior.
  Migrate: replace `keepalive: Some(keepalive)` with `keepalive:
  TcpKeepalivePolicy::Fixed(keepalive)` and `keepalive: None` with
  `TcpKeepalivePolicy::Unchanged`; replace `address_racing: Some(racing)`
  with `address_selection: TcpAddressSelection::Racing(racing)` and
  `address_racing: None` with
  `TcpAddressSelection::Sequential(TcpAddressAdvance::AfterAnyFailure)`; add
  `send_buffer_size: None`, or end the literal with
  `..TcpSettings::default()`. To keep the old Firefox behavior, set those
  three fields of `firefox::v157_tcp()` to `Unchanged`,
  `TcpAddressSelection::default()`, and `None`.
- `RequestTemplate` gained the public field
  `restarts_for_connection_accept_ch` (`bool`), so struct literals that name
  every field no longer compile. It says whether a request with the template
  restarts when its HTTP/2 or HTTP/3 connection's ALPS `ACCEPT_CH` names a
  client hint it lacks. Every Chromium-family navigation template sets it to
  `true`, as Chromium restarts only navigations; every `fetch` template and
  every Firefox template leaves it `false`, so such a request goes out as
  built. A Chrome `fetch` template on such a connection is now sent where it
  failed with `RequestErrorKind::RequestTemplate`
  ([evidence](docs/explanation/validation.md#alps-accept_ch-restart-evidence)).
  Migrate: add `restarts_for_connection_accept_ch: true` to a navigation
  `RequestTemplate` literal and `false` to any other, or build the template
  from a recipe with `..recipe`.
- `Http1Settings` gained the public field `idle_timeout`
  (`Http1IdleTimeout`), so struct literals that name every field no longer
  compile. With `Http1IdleTimeout::CheckedOnRequest(duration)`, when a
  request reaches the HTTP/1.1 connections of its origin and route, an idle
  connection that has been idle that long or longer is closed instead of
  reused, and the request opens another. `Http1IdleTimeout` is
  non-exhaustive, so a match on it needs a wildcard arm.
  `chromium::v154_http1` sets 300 seconds, Chromium's used idle socket
  timeout, which the Chrome 154, Edge 154, and Opera 136 hook logs show, so
  Chrome, Edge, Brave, and Opera profiles now replace a connection idle
  300 s or more. Exact and negotiated HTTP/1.1 requests both apply it.
  `firefox::v157_http1` sets `Http1IdleTimeout::Unlimited`, so Firefox
  profiles keep an idle connection until the server closes it, as before
  ([evidence](docs/explanation/validation.md#http11-connection-bound-evidence)).
  Migrate: add `idle_timeout: Http1IdleTimeout::Unlimited` to an
  `Http1Settings` literal to keep reusing idle connections, or copy the
  value from `chromium::v154_http1`.
- The Windows Firefox recipes move to Firefox 157.0 on Windows 11: every
  `firefox::v156_*` function except the two macOS templates is removed from
  `phantom-profile` and the `phantom` facade and replaced by its `v157_*`
  counterpart. Two things change on the wire. The Windows templates send
  `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101
  Firefox/157.0`, and `firefox::v157_http3_tls` no longer offers ML-DSA-44,
  ML-DSA-65, or ML-DSA-87 in `signature_algorithms` or
  `delegated_credentials`, as Firefox 157's QUIC ClientHello no longer does.
  Every other setting is unchanged
  ([evidence](docs/explanation/validation.md#firefox-157-against-firefox-15601)).
  `firefox::v156_macos_navigation_template` and
  `v156_macos_fetch_no_store_template` stay, because the retained Mac
  captures are from Firefox 156.0, and `firefox_android::v156_tls` keeps its
  Firefox 156.0.1 for Android evidence and now returns `firefox::v157_tls`,
  whose TCP ClientHello Firefox 157 left unchanged.
  Migrate: rename `firefox::v156_tls` to `firefox::v157_tls`, and likewise
  `v156_tcp`, `v156_dns_cache`, `v156_http1`, `v156_http2`,
  `v156_websocket`, `v156_proxy_connect`, `v156_cookie_placement`,
  `v156_http3_tls`, `v156_quic`, `v156_http3`, `v156_http3_request`,
  `v156_windows_navigation_template`, and
  `v156_windows_fetch_no_store_template` to their `v157_` names. Send a
  Firefox 157 `User-Agent` with a template you build yourself.
- `TlsSettings` gained the public field `tcp_early_data: bool`, so struct
  literals that name every field no longer compile. When set, a direct TCP
  connection that resumes a TLS 1.3 ticket permitting early data offers
  `early_data` and sends a safe request without a body or trailers as early
  data; any other request waits for the server's answer. Proxy routes never
  offer it. `firefox::v156_tls` (now named
  `v157_tls`), and so `firefox_android::v156_tls`, sets it, as Firefox 156
  offers early data on every such resumption; every other recipe, and
  `firefox::v156_http3_tls` (now `v157_http3_tls`), leaves it unset. `TlsSettings::validate` rejects it without
  `session_tickets` or below TLS 1.3
  ([evidence](docs/explanation/validation.md#tls-resumption-over-tcp-evidence)).
  Migrate: add `tcp_early_data: false` to a `TlsSettings` literal to keep
  connections that never offer early data, or set the field to `false` on a
  Firefox recipe.
- `Http2HpackSettings` gained the public field
  `sensitive_proxy_authorization` (`Http2SensitiveProxyAuthorization`), so
  struct literals that name every field no longer compile.
  `chromium::v154_http2` and `firefox::v157_http2` set `FieldIndexing`: on
  an HTTP/2 connection to a proxy, a sensitive `proxy-authorization` is now
  a literal with incremental indexing on first use and an index after that,
  as Chrome, Edge, Brave, Opera, and Firefox send it
  ([evidence](docs/explanation/validation.md#hpack-encoder-evidence)).
  Toward an origin it stays never-indexed.
  Migrate: add `sensitive_proxy_authorization:
  Http2SensitiveProxyAuthorization::NeverIndexed` to an
  `Http2HpackSettings` literal, or set it on a recipe, to keep the
  never-indexed form.
- `WebSocketSettings` gained the public field `handshake_timeout`
  (`Option<Duration>`), the browser's own opening-handshake timer, so struct
  literals that name every field no longer compile. `chromium::v154_websocket`
  sets 240 seconds, Chromium's `kHandshakeTimeoutIntervalInSeconds`, and so
  do `chrome_android::v154_websocket` and `brave_android::v153_websocket`,
  which return it. `firefox::v157_websocket` sets 20 seconds, Firefox's
  `network.websocket.timeout.open` default. `WebSocketSettings::validate`
  rejects `Some(Duration::ZERO)` and a timeout the clock cannot represent.
  A WebSocket opened by a client whose profile has one of these recipes now
  fails with `WebSocketErrorKind::Timeout` after that long, where it waited
  without a limit, and needs a Tokio runtime with time enabled; without one,
  `connect` fails with `WebSocketErrorKind::RuntimeUnavailable`.
  Migrate: add `handshake_timeout: None` to a `WebSocketSettings` literal to
  keep no limit, or copy the value from a recipe. Call
  `WebSocketRequestBuilder::handshake_timeout(None)` to open one WebSocket
  without the recipe's limit.
- `Http2Settings` gained the public field `ping_timeout: Option<Duration>`,
  so struct literals that name every field no longer compile, and
  `phantom_net::http2::Http2Error` gained the variants `PingTimeout` and
  `ReusedConnectionClosed`, so exhaustive matches on it no longer compile.
  When set, a PING sent under `preface_ping_after` that goes unanswered
  while nothing is read from the peer for that long closes the connection
  with `GOAWAY` (last stream ID 0, `PROTOCOL_ERROR`, debug data
  `Failed ping.`). Requests open on it fail with `Http2Error::PingTimeout`,
  which is not replayed, and the pool drops the connection. A request that
  reaches the closed connection before the pool does fails with
  `Http2Error::ReusedConnectionClosed`, having sent nothing;
  `RetryPolicy::with_reused_connection_replay` replays it on a fresh
  connection when the method is idempotent.
  `chromium::v154_http2`, and so every Chromium-family recipe,
  sets 10 seconds, Chromium's `kHungIntervalSeconds`; `firefox::v157_http2`
  sets `None`. `Http2Settings::validate` rejects a zero timeout, one the
  clock cannot represent, and a timeout without `preface_ping_after`, so
  setting `preface_ping_after` to `None` on a Chromium recipe now also needs
  `ping_timeout: None`. A process that cannot start Phantom's timer thread
  fails such a connection with `Http2Error::RuntimeUnavailable`.
  Migrate: add `ping_timeout: None` to an `Http2Settings` literal to keep
  connections whose PING is never answered, or copy the field from
  `chromium::v154_http2`. Where code sets `preface_ping_after = None` on a
  recipe, also set `ping_timeout = None`. Add arms for
  `Http2Error::PingTimeout` and `Http2Error::ReusedConnectionClosed` to an
  exhaustive match.
- `Http2Settings` gained the public field `preface_ping_after:
  Option<Duration>`, so struct literals that name every field no longer
  compile. When set, a connection that has read nothing from the peer for
  longer than that time sends a PING right after the next request HEADERS or
  non-empty DATA frame, with a 64-bit big-endian counter from 1 as payload,
  and sends no other while it awaits the ACK. `chromium::v154_http2`, and so
  every Chromium-family recipe, sets 10 seconds, as Chromium's
  `SpdySession::MaybeSendPrefacePing` does; a pooled connection reused after
  10 idle seconds now sends that PING. A retained loopback capture of Chrome
  154 shows the PING right after the request HEADERS, before the request's
  DATA, and `scripts/capture/http2_preface_ping.py` records it.
  `firefox::v157_http2` sets `None`.
  Migrate: add `preface_ping_after: None` to an `Http2Settings` literal to
  keep sending no such PING, or copy the field from `chromium::v154_http2`.
- `Http2StreamSettings` gained the public field `max_concurrent_streams_cap:
  Option<u32>`, so struct literals that name every field no longer compile.
  A `SETTINGS_MAX_CONCURRENT_STREAMS` value the peer states above the cap is
  lowered to it, and initial SETTINGS that omit the setting lift the limit
  only to the cap. `chromium::v154_http2` caps at 256, Chromium's
  `kMaxConcurrentStreamLimit`, so a Chromium-family connection to a peer
  that states more opens at most 256 streams at once;
  `Http2Connection::peer_max_concurrent_streams` reports the capped value.
  `firefox::v157_http2` sets `None`, as Firefox's `Http2Session` applies the
  stated value unchanged.
  Migrate: add `max_concurrent_streams_cap: None` to an
  `Http2StreamSettings` literal to apply every stated limit unchanged, or
  use `..Http2StreamSettings::default()`.
- `QuicTransportSettings` gained the public fields `max_ack_delay_ms`,
  `active_connection_id_limit`, `min_ack_delay_us`, `reset_stream_at`,
  `initial_path_mtu`, and `initial_destination_connection_id`, so struct
  literals that name every field no longer compile. The protocol defaults
  (25, 2, `None`, `false`, `None`, `None`) keep the wire as before;
  `chromium::v154_quic` uses them. The runtime now stores as many of the
  peer's connection IDs as `active_connection_id_limit` advertises, so a
  peer that issues more than 2 to a Chromium-profile connection gets
  `CONNECTION_ID_LIMIT_ERROR`, where Phantom stored up to 5. Distinct values for
  `initial_max_stream_data_bidi_local`, `_bidi_remote`, and `_uni` are now
  accepted, where the QUIC runtime required one value for all three.
  Migrate: add `max_ack_delay_ms: 25, active_connection_id_limit: 2,
  min_ack_delay_us: None, reset_stream_at: false, initial_path_mtu:
  None, initial_destination_connection_id: None` to a
  `QuicTransportSettings` literal.
- `Http3Settings` gained the public field `reserved_frame_after_settings`.
  Migrate: add `reserved_frame_after_settings: false` to an `Http3Settings`
  literal to keep the control stream unchanged.
- The Edge recipes move to Edge 154.0.4258.37 on Windows 11 and macOS 15.5:
  `edge::v153_tls`, `v153_http3_tls`, `v153_windows_client_hints`,
  `v153_macos_client_hints`, `v153_windows_navigation_template`, and
  `v153_windows_fetch_no_store_template` are removed from `phantom-profile`
  and the `phantom` facade. Only the client hints change on the wire: Edge
  154 sends `"Chromium";v="154", "Microsoft Edge";v="154", "Not A(Brand";v="99"`
  and the matching full version list. The TLS settings and templates are
  unchanged. `edge_android::v153_*` keeps its Edge 153 for Android
  evidence.
  Migrate: rename `edge::v153_tls` to `edge::v154_tls`, `v153_http3_tls` to
  `v154_http3_tls`, `v153_windows_client_hints` to
  `v154_windows_client_hints`, `v153_macos_client_hints` to
  `v154_macos_client_hints`, `v153_windows_navigation_template` to
  `v154_windows_navigation_template`, and
  `v153_windows_fetch_no_store_template` to
  `v154_windows_fetch_no_store_template`. Send an Edge 154 `User-Agent` with
  the new client hints.
- The Opera recipes move to Opera 136.0.6008.52 on Windows 11:
  `opera::v135_tls`, `v135_http3_tls`, `v135_windows_client_hints`,
  `v135_windows_navigation_template`, and
  `v135_windows_fetch_no_store_template` are removed from `phantom-profile`
  and the `phantom` facade. Opera 136 is built on Chromium 152.0.7977.130.
  Its TCP and QUIC ClientHellos now carry a trust-anchor IDs extension with
  32 IDs, and its TCP ClientHello puts GREASE at the head of
  `signature_algorithms` again, so `v136_tls` is `chromium::v154_tls` with
  Opera's ID list and `v136_http3_tls` is `chromium::v154_http3_tls` with
  the same list. The client hints send
  `"Chromium";v="152", "Not?A_Brand";v="24", "Opera";v="136"` and the
  matching full version list. The templates are unchanged.
  Opera orders its trust-anchor IDs per process over TCP and per
  connection over QUIC; `v136_tls` sends the most frequent of 29 processes'
  TCP orders and `v136_http3_tls` the most frequent of 20 QUIC ClientHellos'
  orders, which `trust-anchor-orders.txt` tallies.
  `opera::v135_macos_client_hints` stays, because the Mac still runs Opera
  135; no TLS recipe matches Opera 135's ClientHello any more, so pairing it
  with `v136_tls` mixes two builds
  ([evidence](docs/explanation/validation.md#brave-154-and-opera-136-recipes)).
  Migrate: rename `opera::v135_tls` to `opera::v136_tls`, `v135_http3_tls`
  to `v136_http3_tls`, `v135_windows_client_hints` to
  `v136_windows_client_hints`, `v135_windows_navigation_template` to
  `v136_windows_navigation_template`, and
  `v135_windows_fetch_no_store_template` to
  `v136_windows_fetch_no_store_template`. Send an Opera 136 `User-Agent`
  with the new client hints.
- `Http2Settings` gained the public field `streams`, of the new type
  `Http2StreamSettings`, so struct literals that name every field no longer
  compile. `first_stream_id` numbers each connection's first request, and
  `assumed_max_concurrent_streams` bounds the streams open before the peer
  states `SETTINGS_MAX_CONCURRENT_STREAMS`, including after SETTINGS that
  omit it. The recipes change the wire. `firefox::v156_http2` (now named
  `v157_http2`) sends each connection's first request on stream 3, as every
  HTTP/2 connection in the retained Firefox 156 cookie, WebSocket, and proxy
  captures does, where Phantom used stream 1. Both `firefox::v156_http2` and
  `chromium::v154_http2` open at most 100 streams until the peer states a
  limit, where Phantom opened any number.
  `Http2Connection::peer_max_concurrent_streams` reports the assumed limit
  when the peer's first SETTINGS omit the setting.
  Migrate: add `streams: Http2StreamSettings::default()` to an
  `Http2Settings` literal to keep stream 1 and no limit before the peer's
  SETTINGS, or copy `streams` from `chromium::v154_http2` or
  `firefox::v157_http2`.
- `Http2HpackSettings` gained the public fields `field_indexing`
  (`Http2FieldIndexing`), `name_reference` (`Http2NameReference`),
  `unindexed_match` (`Http2UnindexedMatch`), `indexing_limit`
  (`Http2IndexingLimit`), and `table_size_updates`
  (`Http2TableSizeUpdates`), and `Http2HuffmanCoding` gained
  `AlwaysIncludingEmpty`, so struct literals that name every field no longer
  compile. The recipes change the wire. `firefox::v157_http2` now answers
  every `SETTINGS_HEADER_TABLE_SIZE` with a size update, names a literal
  with the oldest dynamic entry that has its name, sends `:path: /` as a
  literal, never indexes `authorization`, stops indexing above half the
  table, and Huffman-codes every string. `chromium::v154_http2` indexes
  every ordinary field, `authorization` and `content-length` included, and
  fields of any size. Every HEADERS block of the retained Chrome, Edge,
  Brave, Opera, and Firefox cookie and WebSocket sessions now equals the
  recipe's byte for byte; before, 24 of 27 Firefox connections differed.
  Migrate: fill the new fields from a recipe with struct update syntax, or
  add `..Http2HpackSettings::default()` to a literal to keep the previous
  encoding.
- `TlsSettings` gained the public fields `session_tickets_per_origin: u8`
  and `session_ticket_extension_when_resuming: bool`, so struct literals
  that name every field no longer compile. The first bounds the TLS tickets
  a TCP connection's cache keeps for one origin, from 1 to 8 when
  `session_tickets` is set; the second keeps or omits the empty
  `session_ticket` extension in a ClientHello that offers a TLS 1.3 ticket.
  Migrate: add `session_tickets_per_origin: 8` and
  `session_ticket_extension_when_resuming: true` to a `TlsSettings` literal
  to keep the previous behavior, or copy both from `chromium::v154_tls` or
  `firefox::v157_tls`.
- `phantom-net` connectors resolve names through a
  `phantom_net::host_resolver::HostResolver`, which holds host overrides, an
  optional `AddressResolver`, and the optional `AddressCache`. On
  `Http1TlsConnector`, `Http2TlsConnector`, `Http1Or2TlsConnector`,
  `Http3Connector`, and `HttpsProxyConnector`, `with_address_cache` and
  `address_cache` are replaced by `with_host_resolver` and `host_resolver`.
  The `phantom` facade API is unchanged. (`f741c5f`)
  Migrate: replace `connector.with_address_cache(AddressCache::new(settings))`
  with `connector.with_host_resolver(HostResolver::new().with_cache(settings))`,
  and `connector.address_cache()` with
  `connector.host_resolver().and_then(HostResolver::cache)`. To share one
  cache between connectors, as a cloned `AddressCache` did, build one
  `HostResolver` and pass a clone of it to each connector; each
  `with_cache` call creates a separate cache.
- `ProxyConnectTemplate` gained the public field `http2_rejected`, of the new
  type `Http2RejectedConnect`, so struct literals that name every field no
  longer compile. It sets what an HTTP/2 CONNECT sends on a stream the proxy
  rejected: `chromium::v154_proxy_connect` uses `EndStream`, and
  `firefox::v157_proxy_connect` uses `LeaveOpen`. `HttpsProxyConnector`
  gained `with_http2_rejected_connect` to apply it. (`8627ac1`)
  Migrate: add `http2_rejected: Http2RejectedConnect::EndStream` to a
  `ProxyConnectTemplate` literal to keep the Chromium behavior, or
  `Http2RejectedConnect::LeaveOpen` for Firefox's.
- `ProxyConnectTemplate` gained the public field `http2_connections`, of
  the new type `Http2ProxyConnections`, so struct literals that name every
  field no longer compile. It sets which requests share an HTTP/2
  connection to an HTTPS proxy: `chromium::v154_proxy_connect` uses
  `Shared` (forwarded `http://` requests, CONNECT tunnels, and WebSocket
  tunnels on one connection), and `firefox::v157_proxy_connect` uses
  `ByPurpose` (a connection for each of the three), as the `https-proxy-*`
  captures show.
  Migrate: add `http2_connections: Http2ProxyConnections::Shared` to a
  `ProxyConnectTemplate` literal for the Chromium behavior, or
  `Http2ProxyConnections::ByPurpose` for Firefox's.
- `phantom_net::proxy::HttpConnectError` gained the variant
  `PooledSetupFailed { kind }`, returned to HTTP/2 tunnels that waited for a
  pooled proxy connection setup that failed, so an exhaustive `match` on
  the enum no longer compiles.
  Migrate: add an arm for `HttpConnectError::PooledSetupFailed { kind }`,
  or match on `HttpConnectError::kind`, which returns the failed setup's
  kind for it.
- `Http2HpackSettings` gained the public field `cookie_crumbs`
  (`Http2CookieCrumbs`) and `Http3RequestSettings` gained `cookie_crumbs`
  (`Http3CookieCrumbs`), so struct literals that name every field no longer
  compile. The recipes change the wire: `chromium::v154_http2`,
  `firefox::v157_http2`, and `chromium::v154_http3_request` send one `cookie`
  field per cookie, at the joined field's position, instead of one joined
  field. Chromium indexes every crumb on HTTP/2 and inserts each into the
  QPACK table on HTTP/3; Firefox sends a crumb under 20 bytes as a
  never-indexed literal and indexes a longer one. This covers a `Cookie`
  field you supply, and `RequestHeader::sensitive` on it no longer makes it
  never-indexed under these recipes. The captures behind it are under
  `fixtures/cookies/`. (`a2c785b`, `6384c1f`)
  Migrate: add `cookie_crumbs: Http2CookieCrumbs::Whole` or
  `cookie_crumbs: Http3CookieCrumbs::Whole` to a struct literal to keep one
  field, or fill the rest from a recipe with struct update syntax. To keep
  one never-indexed field with a recipe, set `settings.hpack.cookie_crumbs =
  Http2CookieCrumbs::Whole` on the value `chromium::v154_http2` or
  `firefox::v157_http2` returns, and `cookie_crumbs =
  Http3CookieCrumbs::Whole` on `chromium::v154_http3_request`.
- `TlsSettings` gained the public field `ech_from_https_records`, so struct
  literals that name every field no longer compile. `chromium::v154_tls`
  sets it, which changes the Chrome 154 recipe's wire behavior on a client
  with HTTPS record discovery: a direct negotiated HTTP/1.1 or HTTP/2
  connection to an origin whose HTTPS record carries `ech` sends a real
  Encrypted Client Hello, with the record's public name as the outer server
  name, and its TLS handshake waits for the lookup for at most 50 ms after
  address resolution. (`e6e5076`)
  Migrate: add `ech_from_https_records: false` to a struct literal to keep
  the previous behavior, or fill the rest from a recipe with struct update
  syntax, such as `..chromium::v154_tls()`. To keep ECH GREASE with the
  Chrome recipe, set `settings.ech_from_https_records = false` on the value
  `chromium::v154_tls` returns.
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
- `phantom_net::http3::Http3Unprocessed` gains `EarlyDataRejected`, reported
  when a server rejects a request sent as HTTP/3 early data. The enum is
  exhaustive, so a `match` on it without a wildcard arm no longer compiles.
  (`550e6f6`)
  Migrate: add an `Http3Unprocessed::EarlyDataRejected` arm. The server did
  not process the request, so handle it as you handle `RequestRejected` and
  `GoAway`.
- `chromium::v154_http3_tls`, and `edge::v154_http3_tls` through it, set
  `session_tickets`. `phantom_quic_btls::QuicClientConfig::with_tls_profile`
  rejects a profile that sets it with `QuicTlsProfileErrorKind::InvalidProfile`
  unless the context was prepared for session resumption, so code that builds
  a `QuicClientConfig` directly from either recipe now fails. It also fails
  with `ContextConflict` when a new-session callback set after preparation
  replaced Phantom's, and with `InvalidProfile` when client session caching
  was turned off after preparation. The `phantom` client and
  `phantom_net::http3::Http3Connector` prepare their contexts and are not
  affected. The commit that changed the recipes, `278645f`, lacks the
  `!` breaking marker; the check it trips came from `f084850`.
  Migrate: call `QuicClientConfig::enable_session_resumption(&mut builder)?`
  on the `SslContextBuilder` before building the context you pass to
  `QuicClientConfig::new`. To keep full handshakes instead, set
  `session_tickets = false` on the recipe's `TlsSettings` before calling
  `with_tls_profile`.
- A `ws://` WebSocket through an HTTP proxy sends `CONNECT host:port` and
  then the direct origin-form Upgrade inside the tunnel, as Chrome 154,
  Edge 153, and Firefox 156 do, instead of an absolute-form Upgrade to the
  proxy. The HTTP/1.1 proxy transport uses a CONNECT tunnel and the HTTP/2
  transport a CONNECT stream, with the route's CONNECT fields and Basic
  retry, so `ws://` now works through an HTTP/2 proxy too. A refused
  CONNECT, including a `407` without configured credentials, fails with
  `WebSocketErrorKind::Proxy` and no response, as for `wss://`; it used to
  return `WebSocketErrorKind::HandshakeRejected` with the proxy's response.
  `phantom_net::http1::Http1TlsConnector` gains
  `upgrade_get_plaintext_http_connect` and
  `upgrade_get_plaintext_https_connect`, each with a `_with_basic_auth`
  variant. (`93f1675`)
  Migrate: the proxy must allow CONNECT to the origin's port. Where you read
  a proxy's refusal of a `ws://` opening with `WebSocketError::into_response`,
  match `WebSocketErrorKind::Proxy` instead and find the status in the
  error's `HttpConnectError::Rejected` source.
- Resumed HTTP/3 connections from the Chrome 154 and Edge 153 recipes change
  on the wire. `phantom_profile::quic::QuicTransportSettings` gains the public
  field `early_data`, and `chromium::v154_quic` sets it, so these recipes
  offer early (0-RTT) data on every resumed connection: the resumed
  ClientHello now carries `early_data`, as resumed Chrome 154 and Edge 153
  connections do. A replay-safe request (`GET`, `HEAD`, `OPTIONS`, or
  `TRACE` with no body and no trailers) on an unanswered resumed connection
  is sent as early data, which a server can process more than once; with
  the named recipes this needs the remembered SETTINGS described under
  Changed. Requests to a resumed origin
  share the connection while its early data is unanswered; any request that
  is not sent early waits for the answer and keeps its body. A rejection
  sends it again (see the entry on rejected early data); a failed handshake
  or invalid handshake metadata is an error. `ClientBuilder::http3_early_data` now
  takes a `bool` that overrides the profile.
  `phantom_quic_btls::QuicClientConfig::with_transport_profile` now offers
  early data when the profile's `early_data` is set, so a
  `phantom_net::http3::Http3Connector` built from these recipes sends early
  data from its isolated clones too; `without_early_data` turns it off. The
  outer connection to a CONNECT-UDP proxy offers none. `Http3Connection`
  gains `early_data_pending` and `early_data_settled`, and `Http3Connector`
  gains `early_data_settled_on` and `requests_wait_for_peer_settings`.
  (`7d81daa`, `6cd4027`, `0563d8d`, `9af2fb6`)
  Migrate: add `early_data: false` to each `QuicTransportSettings` struct
  literal, or `true` to offer early data. Replace
  `ClientBuilder::http3_early_data()` with `http3_early_data(true)`. To
  restore the previous wire shape of a resumed connection from the named
  recipes, turn off both additions: call `http3_early_data(false)` or set
  `early_data = false` on the `QuicTransportSettings` you pass to
  `Http3ClientSettings::new`, and remove the `initial_rtt_us` entry with
  `settings.wire_parameters.retain(|parameter| parameter.kind !=
  QuicTransportParameterKind::InitialRtt)`. Code that builds a
  `QuicClientConfig` with `with_transport_profile` from `chromium::v154_quic`
  and should not offer early data calls `without_early_data` on it.

- Wire change for HTTP/3 connections from the Chrome 154, Edge 153, Brave
  154, and Opera 135 recipes, which share `chromium::v154_http3`. The QPACK
  encoder stream is now client stream 10 and the decoder stream client
  stream 6, and the encoder stream's type is written with its first
  instructions, ahead of the first request's HEADERS, instead of when the
  connection starts. A connection that sends no request writes only its
  control stream, as these browsers do.
  `phantom_profile::Http3Settings` gains the public fields
  `qpack_encoder_stream` (`Http3QpackEncoderStream`) and `qpack_stream_order`
  (`Http3QpackStreamOrder`), which `chromium::v154_http3` sets to
  `OnFirstInstruction` and `DecoderFirst`. The vendored `phantom-h3`
  0.0.8-phantom.4 adds `client::Builder::qpack_decoder_stream_first` and
  `defer_qpack_encoder_stream`; `phantom-h3-datagram` 0.0.2-phantom.4 and
  `phantom-h3-quinn` 0.0.10-phantom.4 follow its pin.
  Migrate: add `qpack_encoder_stream: Http3QpackEncoderStream::Eager` and
  `qpack_stream_order: Http3QpackStreamOrder::EncoderFirst` to each
  `Http3Settings` struct literal to keep the previous streams, or fill them
  from `chromium::v154_http3()` with struct update syntax.

- Wire change for HTTP/3 connections whose early data the server rejects.
  The request is now sent again on the same connection once the handshake
  completes, as Chrome 154 and Edge 153 resend, instead of on a new
  connection that offers no early data. The connection starts a second
  HTTP/3 session, whose control and QPACK streams are client streams 2, 6,
  and 10 again, from the completed handshake's metadata and without the
  SETTINGS remembered with the ticket, so a server whose new SETTINGS lower
  a remembered limit is no longer closed. Chromium closes such a connection
  with the transport error `INTERNAL_ERROR`. In `phantom-net`,
  `Http3Connection::early_data_settled` and
  `Http3Connector::early_data_settled_on` now return `Ok` for such a
  connection, which stays reusable; only a request that went out as early
  data still fails with `Http3Unprocessed::EarlyDataRejected`.
  A rejection that arrives while the early HTTP/3 session is still starting
  is handled the same way. An HTTP/3 session whose control or QPACK stream
  would open on a stream number other than 2, 6, or 10 fails to start and
  closes the connection. Invalid handshake metadata on any HTTP/3
  connection now closes it explicitly: with `H3_GENERAL_PROTOCOL_ERROR` for a
  missing `h3` ALPN or malformed ALPS `ACCEPT_CH`, and with
  `H3_SETTINGS_ERROR` for invalid ALPS SETTINGS.
  Migrate: code that opened a new connection when `early_data_settled`
  returned `EarlyDataRejected` can send the request on the same connection
  once `early_data_settled` returns `Ok`.

- The Chrome for Android recipes follow Chrome 154.0.8037.57, the build
  Play serves to a new Android 17 emulator that reports a Pixel 7.
  `chrome_android::v153_*` became `v154_*`. `v154_tls` and `v154_http3_tls`
  are the Chromium recipes without ECH from HTTPS records: Chrome 154 sorts
  its trust-anchor IDs, so the unsorted Chrome 153 orders are gone.
  `v154_android_client_hints()` sends the captured model `"Pixel 7"` and
  platform version `"17.0.0"`; `v154_android_client_hints_for_model(model)`
  sends another model. Opera for Android's
  `v102_android_client_hints(model)` became `v102_android_client_hints()`,
  with the captured `"Pixel 7"` and platform version `"17"`, and
  `v102_android_client_hints_for_model(model)`. Brave for Android's client
  hints now send platform version `"17.0.0"`.
  Migrate: replace `chrome_android::v153_<name>` with
  `chrome_android::v154_<name>`; replace
  `chrome_android::v153_android_client_hints(model)` and
  `opera_android::v102_android_client_hints(model)` with
  `v154_android_client_hints()` and `v102_android_client_hints()` for a
  Pixel 7, or with the `_for_model(model)` functions for another phone.
- The hidden session API is removed from the `phantom` facade: the `Session`
  alias of `Client`, `SessionBuilder`, `Client::session`, and
  `Client::session_builder`. A separately built `Client` already starts with
  its own pools, cookies, Alt-Svc and client-hint state, proxy credential
  record, and address cache; unlike a session, it also has its own TLS
  contexts and key log.
  Migrate: replace `client.session()` with a second `ClientBuilder::build`
  from the same profile and settings, and
  `client.session_builder().<option>(...).build()?` with the same option on
  `Client::builder(profile)` before `build()`. Replace the type `Session`
  with `Client`.
- The hidden `WebSocketHeader::SessionCookies` variant and
  `WebSocketHeader::session_cookies` constructor are removed.
  Migrate: use `WebSocketHeader::ClientCookies` and
  `WebSocketHeader::client_cookies`, which place the jar's cookies the same
  way.
- `CookieErrorKind::Capacity` is removed. No jar operation returned it: the
  count bounds evict a cookie instead of rejecting one.
  Migrate: delete match arms on `CookieErrorKind::Capacity`.
- `Route::http_connect` is removed.
  Migrate: replace `Route::http_connect(proxy)` with
  `Route::http_proxy(proxy)`, which returns the same route.
- `phantom_net::HostResolver::with_empty_cache` is removed. Phantom no
  longer calls it.
  Migrate: rebuild with
  `HostResolver::new().with_override(..).with_resolver(..).with_cache(..)`.

### Added

- `QuicTransportProfileError::kind()` distinguishes invalid settings from
  entropy failures through `QuicTransportProfileErrorKind`.

- Fill declared template caller slots through `RequestBuilder::fill_slots`.
  The preparation hook runs once, preserves template field positions, and
  cannot insert an undeclared field. Later protocol and redirect changes
  recheck placement without recreating stripped credentials.

- Prepare bounded, replayable JSON, ordered form, and multipart request
  bodies with `PreparedRequestBody`. `RequestBuilder::prepared_body` fills
  a declared `Content-Type` caller slot or checks an explicitly placed
  matching header. Multipart boundaries are caller-supplied.
- Read `SseStream` and `SseEventSource` through the re-exported `Stream`
  trait. Both polling APIs retain partial events, deadlines, and reconnect
  state across cancelled reads. Terminal errors are yielded once.

- Opt in to environment proxy routing with a validated
  `EnvironmentProxies` snapshot. Explicit client and request routes,
  including direct routes, take precedence. Each redirect target checks
  `NO_PROXY` against its logical origin. HTTP, WebSocket, and SSE openings
  use the same snapshot; proxy failures remain errors.

- Compare bounded HTTP/1 request heads against selected retained browser
  requests with `phantom-testkit::http1`. Keep raw names, values, order and
  duplicates; replace targets and indexed Host/User-Agent values explicitly.
  Mismatches and diagnostics omit request bytes. Packaged fixtures and
  versioned development dependencies prepare the testkit for publication.

- Cap caller-enabled retries across redirects with
  `RetryPolicy::with_max_retries`. Per-kind eligibility and limits still
  apply. Browser-required replays keep their separate limits.

- Parse bounded `Link` header values with `parse_link_headers`. Targets,
  repeated parameters, relations, and anchors remain data for the caller
  to interpret. Parsing preserves order and makes no request.

- Inspect safe request origins and connection replay observations,
  including the failing redirect hop and deferred response-body errors.

- Append ordered query pairs with `RequestBuilder::query_pairs`. Existing
  path and query bytes stay unchanged; new pairs retain order and duplicates.
  Construct sensitive authorization fields with
  `RequestHeader::basic_authorization` and `bearer_authorization`. Both
  validate their input and stay where you place them in the header list.


- `error_for_status` checks 4xx/5xx responses and retains the unread response
  in `StatusError`. `response_bytes` and strict UTF-8 `response_text` collect
  with an explicit decoded-byte limit while preserving status, headers, and
  extensions. Failures retain that metadata with a unit body.
  `response_json` adds bounded typed deserialization with the opt-in `json`
  feature, included in `full`. These helpers never change request headers.


- Composed Windows and Android profile constructors combine each browser's
  available layers. Version and platform are explicit. They leave request
  templates unset, and preserve individual recipes for custom composition.
- `ClientProfile::with_request_template` supplies a default HTTP request
  template, prepared once during client construction. A request's
  `template` replaces it; `without_template` disables it. Redirects keep
  this selection and remove cross-origin credentials as before.


- `phantom` re-exports `Bytes`, `Response`, `StatusCode`, and `Uri` for
  request and response APIs. `phantom::profile` also exports
  `Http2StreamSettings`, `QuicAckFrequencyDraft`, and `QuicConnectionIdLength`.
  With `https-records`, `phantom::dns` exports `EchConfig`, `EchCipherSuite`,
  `EchConfigExtension`, `EchConfigListError`, and `EchConfigListErrorKind`, so
  you can name parsed ECH configurations and errors through the facade.
  Discarding a `ClientBuilder` now produces an unused-value warning.
- `ClientBuilder::client_certificate_for(origin, certificate)` presents
  `certificate` to one host and port, such as `"https://api.example:8443"`,
  in place of the certificate from `ClientBuilder::client_certificate`,
  which still serves every other origin. It applies to HTTP/1.1, HTTP/2,
  negotiated, and HTTP/3 requests, to `wss://` openings over HTTP/1.1 and
  HTTP/2, to each redirect hop by its own host and port, to origin TLS
  inside HTTP proxy CONNECT, SOCKS5, and CONNECT-UDP tunnels, and to the
  origin's pinned and learned Alt-Svc alternatives; proxies never receive
  it. Connections, and TLS session tickets over TCP, stay with the host and
  port that made them, so neither is reused with another certificate. An
  origin that is not an `https://` or `wss://` URL with only a host and an
  optional port, or a certificate whose key the profile cannot sign with,
  fails `build` with `BuildErrorKind::InvalidPolicy`
  ([guide](docs/guides/client.md#present-a-client-certificate)).
- `phantom::profile` re-exports `WebSocketProxiedSession`,
  `WebSocketRefusedStreamRetry`, and `WebSocketEmptyMessageCompression`, so
  a custom WebSocket profile can name every `WebSocketSettings` field value
  without depending on `phantom-profile`.
- `ClientBuilder::interface` binds sockets on macOS, with `IP_BOUND_IF` or
  `IPV6_BOUND_IF`, and on Windows, with `IP_UNICAST_IF` or
  `IPV6_UNICAST_IF`, where the name is an interface alias such as
  `Ethernet` or an NDIS name such as `ethernet_32768`, up to 256 UTF-16
  code units. Each socket looks the interface index up from the name
  before it binds or connects, so a name no interface has fails that
  connection with `RequestErrorKind::Connect` and an
  `io::ErrorKind::NotFound` source. On Windows the option picks the
  interface for outgoing packets only. Before, `build` failed with
  `BuildErrorKind::InvalidPolicy` on these platforms
  ([guide](docs/guides/connections-and-state.md#send-connections-from-a-chosen-local-address)).
- `Client::websocket_with_protocol(HttpProtocol::Http3, "wss://...")` opens
  a WebSocket over HTTP/3 extended CONNECT (RFC 9220) to a server the
  caller controls; before, the builder rejected HTTP/3 with
  `ProtocolUnavailable`. The opening is a new stream on the client's pooled
  HTTP/3 connection to the origin and route, direct, over SOCKS5 UDP
  ASSOCIATE, or through a CONNECT-UDP proxy, and holds one per-origin pool
  admission until it is dropped or ends. The profile needs
  `Http3RequestSettings::extended_connect_pseudo_header_order`, which no
  named recipe sets, and the opening starts from the built-in H2 field
  template. A peer that does not enable extended CONNECT fails with the new
  `WebSocketErrorKind::Http3` before any stream is sent, a non-2xx answer is
  `HandshakeRejected` with its body, and nothing falls back to HTTP/2 or
  HTTP/1.1. `ws://` and HTTP proxy routes fail with `UnsupportedRoute`
  before I/O, and profile policy never chooses HTTP/3.
- `AltSvcRace::with_max_alternatives` races up to three learned Alt-Svc
  alternatives at once, the first ones the field listed that are not
  broken, and sends the request on the first to connect, with an `Alt-Used`
  field that names it. The default of 1 keeps Chrome's behavior of racing
  only the first; a value above 3 fails `ClientBuilder::build` with
  `BuildErrorKind::InvalidPolicy`. Each raced setup needs its own H3
  admission, so with `max_concurrent_http3_requests_per_origin` at 1 the
  later alternatives wait and are cancelled when another candidate wins.
  An alternative that fails while another wins is marked broken once the
  winner's handshake completes
  ([guide](docs/guides/http3-discovery.md#race-the-alternative-against-the-origin)).
- `RequestBuilder::alt_svc_alternative(host, port)` sends an exact HTTP/3
  request to an alternative service the caller names, as a request to a
  learned Alt-Svc alternative goes: QUIC connects to that location over
  the request's route, a CONNECT-UDP proxy is asked for the alternative,
  and the request keeps the origin's authority, TLS name, and certificate
  check, with `Alt-Used` after its template, caller, and cookie fields.
  It needs no Alt-Svc store, setup retries follow the request's
  `RetryPolicy`, a failure returns the HTTP/3 error without the HTTP/2
  fallback, and a same-origin redirect keeps the alternative. A
  non-canonical host, a zero port, a request that is not exact HTTP/3, or
  a caller `Alt-Used` fails before any I/O
  ([guide](docs/guides/socks-and-connect-udp.md#reach-a-known-alternative-service)).
- `RequestBuilder::expect_continue(wait)` sends `Expect: 100-continue` and
  holds a nonempty body until the server answers `100 Continue` or `wait`
  ends, on H1, H2, H3, and negotiated requests and on every attempt. A
  final response that comes first, such as `417`, is returned and the body
  is not sent: the H1 connection closes, and an H2 or H3 stream is
  cancelled. A caller's own `Expect` field keeps its position and must be
  `100-continue`. In `phantom-net`, `RequestBody::expect_continue` and
  `RequestBodyMetadata::continue_wait` do the same for a transport request
  ([guide](docs/guides/responses.md#let-the-server-answer-before-the-body)).
- `RetryPolicy::with_http2_fallback` sends an exact HTTP/3 request once
  over the profile's HTTP/2 recipe when no QUIC connection could be set up
  for it: the QUIC connection attempt or handshake failed or was refused,
  took longer than 4 seconds or the connect timeout, or failed before the
  request was written. Any method and an absent, owned, or buffered body
  may fall back. A name-resolution or SOCKS5 proxy failure, a rejected
  Encrypted Client Hello, a failure after the request was sent, a request
  sent as early data, or a one-shot streaming body returns the HTTP/3
  error. Nothing is remembered between requests, so each tries QUIC first,
  and `ResponseInfo::protocol` reports the protocol that answered. An exact
  HTTP/3 request with the policy fails before any I/O on a client without
  an HTTP/2 profile or on a CONNECT-UDP route
  ([guide](docs/guides/http3.md#fall-back-to-http2-when-quic-fails)).
- `RequestBuilder::buffered_streaming_body` and
  `buffered_streaming_body_with_trailers` send a streaming body that a later
  attempt of the request may send again. Up to the caller's byte limit is
  kept as the body is sent, so the first attempt is not delayed; a redirect,
  reused-connection, unprocessed, PING-failure, proxy-authentication,
  `Critical-CH`, or status retry then sends the kept frames and reads on
  from the body. Past the limit the body is sent once, as `streaming_body`
  does, and a later attempt fails with `RequestErrorKind::RequestBody`
  ([guide](docs/guides/redirects.md#send-a-streaming-body-again)).
- `chromium::v154_windows_fetch_template`,
  `chromium::v154_macos_fetch_template`,
  `firefox::v157_windows_fetch_template`, and
  `firefox::v157_macos_fetch_template`: same-origin `fetch()` GETs in the
  default cache mode, the no-store templates without `Pragma` and
  `Cache-Control`, with optional `If-None-Match` and `If-Modified-Since`
  slots where Chrome 154 (after `Accept-Language`, `If-None-Match` first)
  and Firefox 157 (after `Sec-Fetch-Site`, `If-Modified-Since` first) send
  them when their cache revalidates a response
  ([evidence](docs/explanation/validation.md#revalidation-and-upload-evidence)).
- `Http1TlsConnector::with_alpn_protocols`,
  `Http1Or2TlsConnector::http1_connector`, and
  `Http1Or2TlsConnector::http2_connector` return connectors that share the
  source connector's TLS context and session cache. The first two offer
  another ALPN list, keeping the ALPS offer only while its protocol stays
  in it, so a connection resumes the source connector's tickets with the
  ClientHello of `WebSocketConnectionPolicy::http1_tls_settings`.
- `Http1IdleTimeout::ClosedOnTimer(duration)` closes an idle HTTP/1.1
  connection once it has been idle that long, checked when a request
  arrives and by one timer per client, as Firefox's connection manager
  prunes idle connections. The timer is set for the whole seconds the next
  connection to expire has left, at least one, so a connection closes
  within a second after its limit, in the exact HTTP/1.1 and the
  negotiated pools alike. The same timer forgets an origin's address
  family once none of the origin's pool keys, on any runtime, has a
  connection left. It waits and runs on Phantom's deadline service, so it
  keeps closing idle connections on every runtime after the runtime that
  set it is dropped. `Http1IdleTimeout::closed_on_timer` returns the
  limit. `Http1Settings::validate` rejects a timer's limit over 65,535
  seconds, the most Firefox takes, with the new `InvalidHttp1Settings`, and
  `ClientBuilder::build` reports it as `BuildErrorKind::InvalidProfile`.
- `phantom-net` gains hidden seams for the facade's pools, which are not
  supported API: `tcp::AddressFamily`, `tcp::AddressFamilyMemory`,
  `tcp::SlowerConnection`, and `tcp::SlowerProgress`;
  `Http1TlsConnector::connect_direct_keeping_slower`,
  `Http1TlsConnector::connect_plaintext_direct_keeping_slower`, and
  `Http1Or2TlsConnector::connect_direct_keeping_slower`; and `run_after`,
  which runs a task on the deadline service after a delay.
- With the `https-records` feature, `AddressResolver::system_nameservers`
  and `AddressResolver::with_nameservers` resolve names with Phantom's own
  A and AAAA queries, as Chromium 154's built-in DNS client does:
  `localhost` and the hosts file answer locally, names without a dot or
  under `local` go to the operating system, AAAA is sent only when the
  host has a global IPv6 route and before A, and a failed or empty lookup
  falls back to the operating system, which takes over after it has
  answered 16 such lookups in a row. Each answer reports its record TTL,
  which the address cache honors. Pass the resolver to
  `ClientBuilder::dns_resolver`; no recipe or default uses it, because it
  reads the nameservers as hickory does, not as Chromium does
  ([evidence](docs/explanation/validation.md#chromiums-built-in-dns-client)).
- `HttpsRecordResolver::with_udp_settings` opens the resolver's DNS query
  sockets with a profile's `UdpSettings`, and `udp_settings` returns them.
  A client replaces them with its profile's settings when the profile has
  some.
- `phantom::profile::firefox` re-exports `v157_http3_tls`, `v157_quic`,
  `v157_http3`, and `v157_http3_request`, so a crate that depends only on
  `phantom` can build a Firefox 157 profile with HTTP/3.
- `ClientHelloExtensionOrder::PermutedWithTail` shuffles a ClientHello's
  extensions per connection and then writes the listed ones last, before
  only `padding` and `pre_shared_key`, and
  `ClientHelloExtension::QuicTransportParameters` names
  `quic_transport_parameters` (0x39) in such a list.
- `UdpSettings`, set with `ClientProfile::with_udp`, applies socket options
  to every UDP socket that carries QUIC: the socket of a direct HTTP/3
  connection, of the connection to a CONNECT-UDP proxy, and of a SOCKS5 UDP
  association. Its one field, `port_randomization`, sets `SO_RANDOMIZE_PORT`
  before the socket binds, so Windows picks a random local port instead of
  the next one in sequence; a rejection fails the connection attempt, and
  the field has no effect off Windows. `chromium::v154_udp` sets it, as
  Chromium 154 does on every UDP socket it connects, on every Windows; the
  Chrome 154, Edge 154, and Opera 136 hook logs show it on each UDP socket
  their network code opens, and Firefox 157 sets it on none. Brave, Edge,
  and Opera profiles take `chromium::v154_udp`; a Firefox profile takes no
  UDP settings
  ([evidence](docs/explanation/validation.md#udp-socket-option-evidence)).
  `phantom-net`'s `Http3Connector::with_udp_settings` applies the settings
  to a connector's sockets, and `Http3Connector::udp_settings` returns them.
- `scripts/capture/firefox_socket_hooks.py` and the Frida agent extension
  `scripts/capture/firefox_socket_hooks.js` record Firefox's socket options,
  keepalive changes, connection attempts, and host lookups on Windows from
  its parent process, with Firefox's own MOZ_LOG lines about the measured
  origin. Logs of Firefox 157.0 on Windows 11 are retained under
  `fixtures/socket-hooks/firefox/`.
- `RequestField::RestartClientHints`, the place in a request template's
  list for the client hints an ALPS `ACCEPT_CH` restart adds. The
  Chromium-family navigation templates put it after `Accept`, where a
  restarted Chrome navigation sends them, before `Sec-Fetch-Site`; a list
  without it puts them after every other field
  ([evidence](docs/explanation/validation.md#alps-accept_ch-restart-evidence)).
- Edge 154 and Opera 136 profiles can take `chromium::v154_tcp`,
  `chromium::v154_http1`, and `chromium::v154_dns_cache`. Frida hook logs of
  Chrome 154, Edge 154.0.4258.48, and Opera 136.0.6008.52 on Windows 11 show
  the same `TCP_NODELAY` and 45-second keepalive, the 300 ms IPv4 fallback,
  six connections to one origin, and a 60-second system-resolver cache in
  all three ([evidence](docs/explanation/validation.md#socket-hook-evidence)).
  The logs also show Windows port randomization (`SO_RANDOMIZE_PORT`) on
  every socket, which `chromium::v154_tcp` now sets (see Breaking).
- `scripts/capture/socket_hooks.py` and its Frida agent
  `scripts/capture/socket_hooks.js` record a Chromium browser's socket
  options, connection attempts, and host lookups on Windows, from inside its
  network service process, beside a loopback origin's record of the
  connections it accepted. Frida is pinned in
  `scripts/capture/hooks-requirements.txt`. The logs live under
  `fixtures/socket-hooks/`, and each names the agent by its SHA-256.
- `ClientHelloExtension::EarlyData` places the `early_data` extension in a
  fixed extension order; `firefox::v157_tls` lists it between `KeyShare` and
  `SupportedVersions`.
- `Http1Connection::early_data_pending`, `early_data_answered`,
  `early_data_alpn_changed`, and `early_data_failure`, and the same on
  `Http2Connection`, report a connection's TLS early data and, when its
  handshake failed after it, the error a fresh connection reports.
  `Http1Or2TlsConnector::offers_early_data` reports whether a connector
  offers it, `without_early_data` returns a clone, sharing its ticket cache,
  that never does, and `forget_session_tickets` removes the cached tickets
  for one server name. `phantom_net::request::is_replay_safe` states the rule
  for requests that may travel as early data.
- `ClientBuilder::local_address` binds every TCP and QUIC socket a client
  opens, to origins and to proxies, to a local IPv4 or IPv6 address, one per
  family. With an address for one family only, connections skip resolved
  addresses of the other family, and a host without an address of the bound
  family fails with `RequestErrorKind::Connect` (or `Proxy`) and an
  `io::ErrorKind::AddrNotAvailable` source. `ClientBuilder::interface` binds
  them to a network interface with `SO_BINDTODEVICE` on Linux and Android;
  `build` fails with `BuildErrorKind::InvalidPolicy` elsewhere. Both are off
  by default and change no fingerprint field. `phantom-net` adds
  `SourceBinding` and the connectors' `with_source_binding`.
- `ClientBuilder::client_certificate` presents a `ClientCertificate`, parsed
  with `ClientCertificate::from_pem` or `from_der` from a chain and an RSA
  or ECDSA key, when an origin sends a TLS `CertificateRequest`, over TCP
  and QUIC. Ed25519 keys are rejected: no profile has an Ed25519
  signature scheme, and a PKCS #8 v2 key does not parse. The ClientHello
  does not change, and proxies never receive the certificate. A key that
  does not match the certificate fails with
  `ClientCertificateErrorKind::KeyMismatch`, and a key the profile's
  `signature_schemes` cannot sign with fails `build` with
  `BuildErrorKind::InvalidPolicy`. `phantom-quic-btls` adds
  `QuicClientCertificate` and `QuicClientConfig::with_client_certificate`.
- Brave 154 profiles can take `chromium::v154_tcp`, `chromium::v154_http1`,
  and `chromium::v154_dns_cache`: Brave 1.96.59 builds the Chromium tag
  those recipes cite and changes none of their values. Brave 154 and Opera
  135 profiles can take `chromium::v154_cookie_placement`, which their
  retained cookie captures under `fixtures/cookies/` equal over HTTP/1.1,
  HTTP/2, and HTTP/3. Opera still has no TCP, HTTP/1.1 connection, or
  address cache recipe.
- `scripts/capture/snapshot.py` takes the Android browsers. It opens the page
  with an intent and lets the page drive the rest, so Chrome, Brave, and Edge
  for Android snapshots take 3 to 8 seconds a run. Opera and Firefox for
  Android yield the TCP ClientHello only, since neither accepts a
  certificate override from the launcher.
- `quic_resumption.py`, `http2_websocket.py`, and `proxy_route.py` take
  `--android-entry intent` to open the page on an Android browser by intent
  rather than typing it. The Chrome for Android QUIC resumption, WebSocket
  opening, and plaintext-trust evidence is now Chrome 154.0.8037.57 on the
  Android 17 emulator, captured this way; the recipes did not change.
- `WebSocketRequestBuilder::handshake_timeout` bounds one WebSocket opening,
  from the start of `connect` until the accepting response is validated, on
  every route and protocol and on a pooled HTTP/2 session. It defaults to
  the profile recipe's `handshake_timeout` and to no limit without a recipe;
  `None` removes it, and a zero timeout or one the clock cannot represent
  fails with `WebSocketErrorKind::InvalidRequest` before any I/O. When it
  passes, `connect` fails with the new
  `WebSocketErrorKind::Timeout`, and the new `WebSocketError::timeout_phase`
  returns the new `TimeoutPhase::WebSocketHandshake`.
- `WebSocketRetryPolicy` and `WebSocketRequestBuilder::retry_policy` open a
  WebSocket again, with a bounded number of attempts and a fixed delay, after
  a connection-setup failure that sent nothing to the origin: a failed name
  lookup, a failed TCP connect to the origin or proxy, or a SOCKS5 proxy that
  could not connect or resolve. TLS failures, proxy rejections, timeouts,
  and any answer from the server, `101` and `2xx` included, are returned at
  once. It is off by default; browsers do not retry an opening.
- Firefox 156 HTTP/3 recipes from Firefox 156.0.1 captures on Windows 11:
  `firefox::v156_http3_tls`, `v156_quic`, `v156_http3`, and
  `v156_http3_request`, now named `v157_*`, and an HTTP/3 list in the Firefox navigation and
  `fetch` templates. The QUIC transport parameters, their order and
  encodings, the SETTINGS frame and the reserved frame after it, the QPACK
  stream order and encoding, and the request field order match the captures;
  [Validation](docs/explanation/validation.md#firefox-157-http3-recipe)
  lists the remaining differences.
- QUIC version 2 (RFC 9369). A profile whose `version_information` lists two
  available versions offers v2 and v1, follows a server that moves the
  connection from v1 to v2 (RFC 9368 compatible version negotiation), and
  starts a connection that presents a session ticket in the version of the
  connection that received it, presenting only tickets from that version.
  `phantom_quic_btls::QuicVersion` gained `V2`, `wire`, and `from_wire`, and
  `QuicClientConfig::configure_client` applies a profile's per-connection
  settings (the first Destination Connection ID's length and the start
  version) to a Quinn `ClientConfig`, and `QuicClientConfig::configure_path`
  applies the initial path MTU for the peer's address family to a Quinn
  `TransportConfig`; call both when building Quinn endpoints directly.
- `phantom-quinn-proto` 0.11.18-phantom.2 adds `TransportConfig::max_ack_delay`,
  `active_connection_id_limit`, `bidi_remote_stream_receive_window`,
  `uni_stream_receive_window`, `min_initial_datagram_size`,
  `reset_stream_at`, and `ack_frequency_draft`, `EndpointConfig::compatible_versions`,
  and `crypto::Session::initial_keys_for_version` and `switch_version`;
  `phantom-quinn` 0.11.12-phantom.2
  follows it. `phantom-h3` 0.0.8-phantom.5 adds the client builder options
  `reserved_frame_after_settings`, `qpack_insert_policy`, and
  `qpack_huffman`. Each is off or unchanged by default.
- QUIC profile data for `max_ack_delay`, `active_connection_id_limit`, the
  empty `reset_stream_at` parameter, draft 02 and draft 07 `min_ack_delay`
  (`QuicAckFrequencyDraft`), a leading reserved version
  (`QuicVersionGrease::First`), the initial path MTU, which sets the size of
  Initial datagrams for each address family, and the length
  of the first Destination Connection ID (`QuicConnectionIdLength`). The
  runtime honors each: it acknowledges within the advertised delay, stores
  that many connection IDs, delivers the reliable part of a stream reset by
  `RESET_STREAM_AT`, and reads draft 02 `ACK_FREQUENCY` frames.
- `Http3Setting::EnableConnectProtocol`, `EnableWebTransportDraft02` (only
  `false`), and `H3DatagramDraft04`, and
  `Http3QpackEncoding::DynamicUnmatchedNames`, the QPACK encoding of neqo,
  Firefox's HTTP/3 stack.
- `scripts/conformance/aioquic_versions.py` and the
  `quic_version_interop` example of `phantom-net` check QUIC version
  negotiation and v2 resumption against aioquic on loopback.
- `scripts/capture/run_matrix.py` runs desktop browser captures from one JSON
  manifest of tools, browsers, scenarios, and repeat counts. It runs up to
  `--jobs` tool invocations at once, each with its own temporary directory
  and, on Windows, its own kill-on-close Job Object. Tools that use
  machine-wide state always run alone, and tools whose fixtures keep
  connection counts, order, or delays run alone by default. It skips a job
  only when its work directory recorded it as passed with the same parameters
  and unchanged files, retries a failed job once, stops every running attempt
  on Ctrl+C, and writes a summary and a results file. Each tool still writes
  its own fixture. Desktop Firefox launches beside other jobs take turns until
  each has restored its first window, because Firefox processes started
  together can lose their page load.
- macOS recipes from captures on macOS 15.5 on Apple silicon:
  `chromium::v154_macos_client_hints`, `edge::v154_macos_client_hints`, and
  `opera::v135_macos_client_hints` (platform `"macOS"`, platform version
  `"15.5.0"`, architecture `"arm"`), with
  `chromium::v154_macos_navigation_template`,
  `chromium::v154_macos_fetch_no_store_template`,
  `firefox::v156_macos_navigation_template`, and
  `firefox::v156_macos_fetch_no_store_template`. The Chrome templates leave
  `User-Agent` to the caller, because every macOS capture ran headless; the
  Firefox templates carry the macOS `User-Agent`. On macOS, Opera sends the
  fields of its Windows templates, and Edge does too with its language list
  set to `en-US`; for another locale, override `Accept-Language`. Every other
  layer is the Windows recipe: retained single macOS runs of the TCP
  ClientHello and resumption, the H2 session, and, for the Chromium browsers,
  the QUIC ClientHello and H3 startup are replayed against it. The captures
  are under `fixtures/*/*/*/macos-15.5-arm64/`.
- `client_hints.py` and `http2_websocket.py` take `--browser-switch` to add a
  recorded Chromium switch to the launch.
- Edge for Android recipes in `edge_android`, captured from Edge
  153.0.4234.49, the arm64 build Play serves, on an arm64 Android 17
  emulator that reports a Pixel 7: `v153_tls` and `v153_http3_tls`
  (desktop Edge 153's ClientHellos without ECH from HTTPS records),
  `v153_http2`, `v153_quic`, `v153_http3`, and `v153_http3_request` (the
  Chromium recipes), `v153_android_client_hints()` and
  `v153_android_client_hints_for_model(model)`, and
  `v153_android_navigation_template` and
  `v153_android_fetch_no_store_template` with Edge for Android's literal
  `User-Agent`.
- Encrypted Client Hello over QUIC. `phantom_quic_btls::EchOffer` and
  `EchOutcome`, with `QuicClientConfig::with_ech`, offer an `ECHConfigList`
  on one connection and report whether the server accepted it, rejected it
  with or without retry configurations, or BoringSSL refused the list;
  `HandshakeData::ech_accepted` reports acceptance. `Http3Connector` gained
  `connect_direct_with_ech` and `ech_from_https_records` behind the
  `https-records` feature, and `Http3ConnectorError::ech_failure` returns
  the `EchFailure`. A QUIC connector now accepts
  `TlsSettings::ech_from_https_records`.
- The `server` feature of `phantom-quic-btls` adds `QuicServerConfig`, a
  Quinn server crypto provider on a BoringSSL context, and
  `ServerHandshakeData`, which reports the ClientHello, the server name,
  ECH acceptance, and resumption. It exists for loopback tests and capture
  tools, holds ECH keys, and offers no 0-RTT or client authentication.
- `chrome_ech.py --quic` and `capture_ech_client_hello --quic` record a
  browser's QUIC connections to an origin whose HTTPS record lists `h3` and
  carries `ech`, from a loopback QUIC server that decrypts ECH. The fixture
  format is now `phantom-ech-client-hello-v2`. Chrome 154, Edge 153, and
  Brave 154 captures are retained as `ech-quic-accept.txt` and
  `ech-quic-reject.txt`.
- `scripts/capture/snapshot.py` records a desktop browser's fingerprint
  from one headless launch, in one file per run: the TCP and QUIC
  ClientHellos, HTTP/2 startup frames, request fields over HTTP/2, HTTP/3,
  and HTTP/1.1, client hints after `Accept-CH` and `Critical-CH`, and HTTP/3
  transport parameters and SETTINGS. On Windows it observed every layer for
  Chrome 154, Edge 154, Brave 154, and Opera 135, and every layer but client
  hints, which Firefox does not send, for Firefox 156. `snapshot_compare.py`
  lists how a snapshot differs from the browser's retained fixtures.
- `scripts/capture/tls_resumption.py` records how a browser resumes TLS 1.3
  sessions over TCP against a loopback server that issues its own tickets:
  the resumed ClientHello, the ticket each connection presents, early data,
  ticket retention per origin, parallel connections, other ports, and
  top-level-site partitions. Fixtures for Chrome 154, Edge 153, Brave 154,
  Opera 135, and Firefox 156 are retained under `fixtures/tls/`.
- `phantom_net::proxy::Http2ProxyPool` and
  `HttpsProxyConnector::with_http2_proxy_pool`: HTTP/2 CONNECT tunnels
  become streams of one pooled proxy connection per route, keyed by proxy
  host, port, server name, Basic credentials, and connector settings, for
  at most `MAX_HTTP2_PROXY_POOL_ROUTES` (32) routes. Past the proxy's
  `SETTINGS_MAX_CONCURRENT_STREAMS`, a CONNECT waits on that connection. A
  connection that sent `GOAWAY` or closed takes no new tunnels, and a
  CONNECT it left unprocessed is sent once more on another. Tunnels that
  waited for a failed connection setup fail with the new
  `HttpConnectError::PooledSetupFailed`. Without a pool, each tunnel keeps
  its own connection.
  `HttpsProxyConnector::connect_forward_http2_with_credentials` returns a
  pooled forwarding connection for a route's credentials.
- `Http2ProxyPool::with_max_connections_per_route` and
  `ClientBuilder::max_http2_proxy_connections_per_route`, off by default: a
  route may open up to that many proxy connections, at most
  `HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING` (8), opening another once
  each carries `MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION` (100) tunnels or the
  proxy's stream limit. This departs from the browsers, which queue streams
  on one proxy connection; a proxy sees more connections.
- `phantom_net::proxy::MAX_CHALLENGE_BODY_BYTES` (64 KiB): the longest
  `407` body Phantom reads so the replay can use the challenged HTTP/1.1
  proxy connection.
- Brave 154 and Opera 135 recipes, from Windows 11 captures of Brave
  154.1.96.59 and Opera 135.0.5973.92: `brave::v154_tls`,
  `v154_http3_tls`, `v154_windows_client_hints`,
  `v154_windows_navigation_template`, and
  `v154_windows_fetch_no_store_template`, and the matching `opera::v135_*`
  functions, in `phantom-profile` and the `phantom::profile` facade. Both
  use the Chromium 154 H2, QUIC, H3, WebSocket, and proxy CONNECT recipes,
  which equal their captures. Both TLS recipes omit trust-anchor IDs; Opera's
  also sends no GREASE signature algorithm, and Brave's keeps ECH from HTTPS
  records. Brave's templates add `Sec-GPC: 1`, drop signed exchanges from
  the navigation `Accept`, and require the caller's `User-Agent` and
  `Accept-Language`; Opera's require the caller's `User-Agent`. Neither
  browser has a TCP, HTTP/1.1 connection, address cache, or cookie placement
  recipe. Through the Chromium recipes both split `cookie` into crumbs on
  H2 and H3, which no Brave or Opera capture checks, and end a rejected
  HTTP/2 CONNECT stream with an empty END_STREAM DATA frame, as their proxy
  captures show. Brave's ECH from HTTPS records covers exact-protocol
  requests and `wss://` openings, as the Chrome recipe's does.
- The capture tools launch `--browser brave` and `--browser opera`, and
  `chrome_http3.py --output` writes its startup fixture with LF line endings.
  `startup_capture.py` launches a browser against the TLS, HTTP/2, or HTTP/3
  startup listener, on the command line or through a DevTools navigation.
- Chrome for Android recipes in `phantom_profile::chrome_android` and
  `phantom::profile::chrome_android`, captured from Chrome 153.0.8010.52 on
  an Android 15 emulator. That is the build Play served to the emulator,
  which trailed the stable Android build, 155.0.8059.16, when captured; the
  Android recipes carry the Play-served build rather than current stable.
  `v153_tls` and `v153_http3_tls` are the desktop Chromium ClientHellos with
  Chrome 153's unsorted trust-anchor orders and without ECH from HTTPS
  records; the QUIC order varies per browser process, and the recipe's order
  was seen in 9 of 30 captured processes. `v153_android_client_hints(model)`
  takes the device model and has no default, because the captured model names
  the emulator. The navigation and fetch templates are
  `v153_android_navigation_template` and
  `v153_android_fetch_no_store_template`. `v153_http2`, `v153_quic`,
  `v153_http3`, `v153_http3_request`, and `v153_websocket` return the desktop
  Chromium recipes that the Android captures equal. Through those recipes Chrome for Android splits
  `cookie` into crumbs on H2 and H3, which no Android capture checks. There
  is no Android TCP, HTTP/1.1 connection, address-cache, proxy CONNECT, or
  cookie-placement recipe.
- `firefox_android::v156_tls`, from Firefox 156.0.1 on the same emulator. It
  returns `firefox::v157_tls`, which its ClientHellos equal.
- Opera for Android recipes in `opera_android`, from Opera 102.1.5206.90382
  (Chromium 152) on the same emulator: `v102_tls`, Chrome 154's ClientHello
  without trust-anchor IDs, and `v102_android_client_hints(model)`. Opera for
  Android reads no command-line file, so no other layer was captured.
- Brave for Android recipes in `brave_android`, captured from Brave 1.95.104
  (Chromium 153) on the same emulator: `v153_tls` (desktop Brave's
  ClientHello without ECH from HTTPS records), `v153_http3_tls`,
  `v153_android_client_hints`, `v153_android_navigation_template`, and
  `v153_android_fetch_no_store_template`, with desktop Brave's request-field
  changes and a caller `Accept-Language`, and `v153_http2`, `v153_quic`,
  `v153_http3`, `v153_http3_request`, and `v153_websocket`, which return the
  Chromium recipes.
- Android capture support in `scripts/capture`: `--browser chrome-android`,
  `edge-android`, `brave-android`, `opera-android`, and `firefox-android`
  launch the browser on an adb device with a cleared profile, its debug
  command-line or GeckoView configuration, and a URL typed into the address
  bar or opened by intent; `android_run.py` opens one page for the listen-only
  capture examples.
- `ClientBuilder::max_http2_connections_per_origin`: lets exact HTTP/2 and
  negotiated requests that select HTTP/2 open up to that many connections per
  origin and route. A request opens another only when every connection
  carries as many streams as the lower of the active bound and the peer's
  `SETTINGS_MAX_CONCURRENT_STREAMS`, and new streams go to the least-loaded
  connection. The default stays one connection, as browsers keep.
- `ClientBuilder::max_http3_connections_per_origin`, off by default: lets
  exact HTTP/3 requests and Alt-Svc or HTTPS-record alternatives open up to
  that many QUIC connections, at most 8, per origin, route, and transport
  location. A request opens another only when every connection carries as
  many streams as the lower of the active bound and the server's
  `initial_max_streams_bidi`, one setup at a time per location, and new
  streams go to the least-loaded connection.
- `Http3Connector::can_reuse_now` in `phantom-net`: the reuse check of
  `can_reuse` without a future, for a caller holding a synchronous lock.
- `Http3Connection::peer_initial_max_streams_bidi` in `phantom-net` and
  `HandshakeData::peer_initial_max_streams_bidi` in `phantom-quic-btls`
  report the server's `initial_max_streams_bidi` transport parameter once
  the handshake completes.
- `ClientBuilder::negotiated_setup_wait_limit`: bounds how long a negotiated
  request waits for another request's handshake to an origin that selected
  HTTP/2 before, as Chromium 154 does at 300 ms. The default stays
  unbounded, as in Firefox 156.
- `AltSvcRace::with_alternative_setup_limit` and
  `AltSvcRace::alternative_setup_limit`: the raced alternative's connection
  setup limit, still 4 seconds by default.
- `Http2Connection::peer_max_concurrent_streams` in `phantom-net`.
- [Tune throughput and latency](docs/guides/performance.md), and a table of
  every timer in [Defaults and limits](docs/reference/limits.md#delays-and-timers).

- Host-to-address overrides and a caller-supplied address resolver, like
  reqwest's `resolve` and `dns_resolver`. `ClientBuilder::resolve(host, ips)`
  sends a name, normalized as a URL host, to fixed addresses, tried in the
  given order, while the TLS server name, `Host` or `:authority`, cookies,
  and pool keys keep the name; the port always comes from the URL.
  `ClientBuilder::dns_resolver` takes a `phantom::AddressResolver` built
  with `AddressResolver::from_fn` from an async function that returns
  `io::Result<Vec<IpAddr>>`; it replaces the
  operating system resolver, and its answers go through the address cache
  when there is one, one lookup per name per cache lifetime. Both cover the
  names a client resolves itself: origin hosts on a direct route, proxy
  hosts, and local-DNS `socks5://` targets. Targets that `socks5h://`, an
  HTTP proxy, or CONNECT-UDP resolves never use them. An override skips the
  resolver and the cache. A resolver error fails the request with the kind a
  failed system lookup gets on that path. HTTPS record lookups are
  unchanged. See [Resolve host names](docs/guides/name-resolution.md), which
  now also holds the address cache task.

- An address cache for the names a client resolves itself: origin hosts on a
  direct route, proxy hosts, and local-DNS `socks5://` targets.
  `phantom_profile::DnsCacheSettings` (`max_entries`, `ttl`, `negative_ttl`),
  `ClientProfile::with_dns_cache` and `ClientProfile::dns_cache`, the recipes
  `chromium::v154_dns_cache` (1,000 names, answers for 60 seconds, failures
  not kept) and `firefox::v157_dns_cache` (1,600 names, answers and failures
  for 60 seconds) from browser source, `ClientBuilder::dns_cache`,
  `ClientBuilder::no_dns_cache`, and `Client::clear_dns_cache`. Concurrent
  connections to one host share one lookup, run on the starting runtime's
  blocking pool (512 threads by default) as `tokio::net::lookup_host` is, so
  no runtime waits on another and resolutions in flight stay bounded by that
  pool. The resolver's addresses are kept in order with their IPv6 scope.
  An empty answer is cached for `negative_ttl`, and each connection path
  still reports it as before. Clones share the cache;
  each session starts with an empty one. Targets that `socks5h://`, an HTTP
  proxy, or CONNECT-UDP resolves never reach it. A client with a cache sends
  fewer DNS queries: one lookup per host per cache `ttl` instead of one per
  new connection. Without `with_dns_cache` or `ClientBuilder::dns_cache`,
  nothing changes. `phantom_net` gains
  `address_cache::AddressCache` and `with_address_cache` and
  `address_cache` on its TCP, HTTPS proxy, and HTTP/3 connectors.

- `RequestField::ByForwarding`, with the `RequestField::unless_forwarded` and
  `RequestField::when_forwarded` constructors: a template field whose value
  depends on whether an HTTP proxy forwards the request (absolute form on
  HTTP/1.1, `:scheme` `http` on an HTTP/2 proxy connection).
- `ClientProfile::with_proxy_connect` and `ClientProfile::proxy_connect`,
  `ProxyConnectTemplate`, `ProxyConnectField`, and
  `InvalidProxyConnectTemplate`: the ordered fields of the CONNECT request
  that opens an HTTP proxy tunnel, per proxy transport, for a route that sets
  none of its own. `chromium::v154_proxy_connect` (Chrome 154 and Edge 153)
  and `firefox::v157_proxy_connect` carry the captured fields, with the
  tunnelled request's `User-Agent`. A `ProxyConnectField::FromRequest`
  entry keeps the copied field's sensitive marking and cannot name
  `Authorization`, `Cookie`, `Cookie2`, or `Proxy-Authorization`.
- `RequestField::ProxyAuthorization`, with the
  `RequestField::proxy_authorization` constructor, and
  `ProxyAuthorizationAttempt`: the position of the generated
  `Proxy-Authorization` field on a forwarded request, for every attempt or
  separately for a first attempt with remembered credentials and for the
  replay after a `407`.
- Encrypted Client Hello from HTTPS DNS records, as Chrome 154.0.8037.58
  does: `Http1Or2TlsConnector::connect_direct_with_ech` offers an
  `ECHConfigList` on a direct connection, retries once to the same address
  after a rejection with the server's retry configurations, or with ECH
  GREASE and the true server name when it sent none, and reports failures
  through `TlsError::ech_failure` and `EchFailure`. `EchConfigList::parse`
  and `EchConfig` decode a record's `ech` value by the TLS client's rules,
  and the `ech_config_list` fuzz target drives the parser. Chrome and its
  retry path were captured in `fixtures/tls/chrome/154.0.8037.58/`.
  (`124c1f7`, `e6e5076`)
- `Http1TlsConnector::connect_direct_with_ech` and
  `upgrade_get_direct_with_ech`, and `Http2TlsConnector::connect_direct_with_ech`
  and `send_extended_connect_direct_with_ech`, offer an `ECHConfigList` on a
  direct connection with the same wait and retry as the negotiated connector.
  Both connectors gain `ech_from_https_records` and `alpn_protocols`, and
  `Http1TlsError` and `Http2TlsError` gain `ech_failure`.
- `scripts/capture/chrome_ech.py` and the `capture_ech_client_hello`
  example record a Chromium browser's ClientHellos against a loopback origin
  that decrypts ECH, with the HTTPS record served over DNS over HTTPS.
  `phantom_testkit::tls` gains fixed ECH test keys, `ECHConfig` encoding, and
  a decoder for the outer `encrypted_client_hello` extension. (`1f268a5`)
- `ClientBuilder::preemptive_proxy_authentication`, on by default, and the
  `phantom_net::proxy::ProxyCredentialCache` it uses:
  after an HTTP proxy accepts `HttpProxy::with_basic_auth` credentials on the
  replay after a `407`, the client remembers the proxy's scheme, host, and
  port with those credentials, up to 128 pairs, and sends
  `Proxy-Authorization` on the first attempt of later CONNECT tunnels
  (HTTP/1.1 and HTTP/2 proxy transports, WebSocket tunnels included) and
  forwarded `http://` requests through it. Each session built from a client
  starts with an empty record. The origin connectors and
  `HttpsProxyConnector` take the record with `with_proxy_credential_cache`.
- HTTP/2 forwarding of `http://` requests accepts `HttpProxy::with_basic_auth`:
  a Basic `407` is answered with one replay on the same proxy connection.
  Before, such a request failed with `RequestErrorKind::UnsupportedRoute`
  before I/O.
- Proxy authentication captures of Chrome 154, Edge 153, and Firefox 156 in
  `fixtures/proxy/`, and `scripts/capture/proxy_route.py` scenarios that
  answer a Basic challenge through the DevTools protocol or WebDriver BiDi.

- `RequestField::ByTrust`, with the `RequestField::trustworthy_only` and
  `RequestField::by_trust` constructors, and `RequestField::default_value`:
  a template field whose value depends on whether the request URL is
  potentially trustworthy.
- `WebSocketField::ByTrust`, with the `WebSocketField::trustworthy_only` and
  `WebSocketField::by_trust` constructors, and `WebSocketField::default_value`:
  a WebSocket opening field whose value depends on whether the WebSocket URL
  is potentially trustworthy. `WebSocketHeader::DefaultField` and
  `WebSocketHeader::default_field` add an opening field whose value a caller
  field with the same name replaces in place.

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
  `firefox::v157_http1` allow 6, from browser source, and
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
- The `diagnostics` feature of `phantom-http` queues a TLS key log and writes
  QUIC qlog files for your own connections. `ClientBuilder::key_log(capacity)`
  queues the TLS 1.3 secrets of every TCP and QUIC handshake in NSS key log
  format, and `Client::key_log` returns the `KeyLog` whose `write_pending`
  drains the queue. `ClientBuilder::qlog_dir(dir)` writes one JSON-SEQ qlog
  file per QUIC connection. The feature is off by default and not part of
  `full`, because a key log decrypts the client's traffic. (`a2519af`)
- HTTP/3 connections resume TLS 1.3 sessions when the H3 TLS settings enable
  `session_tickets`. Each client pool entry, one origin and one route, keeps
  its own cache of at most 4 tickets, filled only by connections that
  authenticated the server. A ticket is used once, only for the same
  verified server name, and never on another origin or route. A handshake
  that presented a ticket and failed is repeated once with a full handshake
  over the same route. `phantom_net::http3::Http3Connector` gains
  `with_isolated_session_cache`, `without_ticket_offers`, `resumes_sessions`,
  and `has_ticket_for`. `phantom_net::http3::Http3Connection` gains
  `session_resumed`, and `phantom_quic_btls::HandshakeData` gains
  `session_resumed`. `phantom_quic_btls::QuicClientConfig` gains
  `enable_session_resumption`, `with_isolated_session_cache`,
  `without_ticket_offers`, `has_ticket_for`, and `resumes_sessions`.
  `enable_session_resumption` refuses a builder whose new-session callback
  belongs to other code: it fails with the new
  `QuicTlsProfileErrorKind::ContextConflict` and leaves the builder
  unchanged. Calling it twice succeeds.
  (`f084850`, `278645f`)
- `ClientBuilder::http3_early_data(true)` lets a new resumed HTTP/3
  connection send a replay-safe request (`GET`, `HEAD`, `OPTIONS`, or `TRACE`
  with no body and no trailers) as early (0-RTT) data. Early data is
  replayable; the named recipes that now enable it are listed under
  Breaking. `build` fails with
  `BuildErrorKind::InvalidPolicy` unless the H3 TLS settings enable
  `session_tickets`. If the server rejects the early data, the request is
  sent again after the handshake over the same route and protocol. When the
  server accepts the early data, the connection applies the server's ALPS
  SETTINGS and `ACCEPT_CH` entries once the handshake completes, and a
  connection whose ALPS is invalid is closed and its request fails, as on a
  full handshake. `Http3Connector` and `phantom_quic_btls::QuicClientConfig`
  gain `with_early_data`, `without_early_data`, and `sends_early_data`.
  `Http3Connection` gains `sent_early_data` and `early_data_accepted`.
  (`31da936`, `550e6f6`)
- The `https-records` feature, off by default and part of `full`, adds
  HTTP/3 discovery from HTTPS DNS records (RFC 9460).
  `ClientBuilder::https_record_discovery` takes a
  `phantom::dns::HttpsRecordResolver` that queries the host's nameservers
  (`system`), explicit ones (`with_nameservers`), or a caller function
  (`from_fn`), and needs `ClientBuilder::alt_svc`. A negotiated request on
  the direct route with no stored Alt-Svc alternative starts a lookup and
  never waits for it; once a ServiceMode record lists `h3` for the origin's
  own host and port, requests use HTTP/3 there, without `Alt-Used`, under the
  `AltSvcPolicy`. Results are cached per client for the lowest record TTL, at
  most one day, or 60 seconds without one, for at most the Alt-Svc store's
  number of origins. Proxy routes and IP-literal origins send no query. A
  record's `ech` value is kept as bytes but not used for Encrypted Client
  Hello. (`11b01d9`, `74fa7b9`, `ed5cb93`, `f3fa2e3`, `2fc3144`)
- `http://` requests through an HTTP proxy with `with_http2_transport` are
  forwarded as HTTP/2 requests with `:scheme` `http` and the origin in
  `:authority`, as Chrome 154, Edge 153, and Firefox 156 send them. Exact
  HTTP/2 and negotiated requests use it; requests to one origin share one
  pooled proxy connection with the profile's HTTP/2 settings and
  pseudo-header order, and the response reports `HttpProtocol::Http2`.
  Exact HTTP/1.1 on that route now fails before I/O with
  `RequestErrorKind::UnsupportedRoute` instead of `RequestErrorKind::Proxy`,
  and a proxy with `with_basic_auth` fails the same way, because HTTP/2
  forwarding has no challenge retry. `phantom_net` gains
  `HttpsProxyConnector::connect_forward_http2`,
  `Http2Connection::send_forward_request_body_with_trailers`, and
  `HttpConnectError::ForwardingRequiresHttp2`. (`e99940b`)
- The hidden `SessionBuilder` takes every per-client option of
  `ClientBuilder`: it gains `request_timeouts`,
  `max_http2_connections_per_origin`, `negotiated_setup_wait_limit`,
  `alt_svc_policy`, `http3_early_data`, and `https_record_discovery`. A
  session shares the transport options of the client it is built from, such
  as the route, trust roots, key log, and resolver settings. Without
  `http3_early_data`, a session keeps its client's early-data choice.

### Changed

- Document Phase 2 API milestones, completion criteria, and browser/TLS
  behavior that each change must preserve.
- Add crate READMEs, keywords, categories, and plain package descriptions
  for the four publishable crates. Enable Cargo lints, with five documented
  exceptions for incompatible transitive dependency versions.
- Enable `must_use_candidate` and `cast_lossless` workspace warnings.
  Mark address, error kind, future size, and application state storage
  results as `must_use`.
- Clarify public API docs and the browser-recipe and vendoring guides.
  Correct the protocol-selection, proxy-forwarding, and buffered-body
  replay descriptions while keeping the examples unchanged.
- Shorten Design and HTTP/3 internals, and simplify Validation's evidence
  descriptions. Correct ticket-policy, platform, connection-state, and
  retry descriptions while preserving the recordings and source references.
- Enable workspace warnings for public types without `Debug` and Rust
  2018 idioms. Add a non-blocking `Debug` implementation for the testkit's
  DNS server that omits recorded queries.
- Rewrote the README, start pages, and guides in plain language, with
  shorter explanations and the existing examples. Corrected descriptions
  of HTTP/3 discovery and fallback, retries, cookies, and response metadata.
- Rewrite the seven reference pages in plain language. Correct the DNS
  socket settings, default-mode fetch coverage, cookie keys, and origin
  serialization descriptions.
- Wire change for the Firefox HTTP/2 recipe: `firefox::v157_http2` stops
  reusing a connection with no response data for 170 seconds and closes it
  with `GOAWAY(NO_ERROR)` about a second later, or when its last stream
  ends, as Firefox 157 does. The next request opens a new connection.
  Before, a Firefox profile kept such a connection until the server closed
  it. A connection to an HTTPS proxy closes only when the next tunnel
  replaces it. The Chromium recipes set no limit
  ([evidence](docs/explanation/validation.md#http2-idle-close-evidence)).
- Wire change for the Chromium HTTP/3 request recipe:
  `chromium::v154_http3_request`, which the Chrome, Edge, Brave, and Opera
  profiles use, as do `chrome_android::v154_http3_request`,
  `edge_android::v153_http3_request`, and
  `brave_android::v153_http3_request`, no longer sends `Alt-Used` on a
  request to an Alt-Svc alternative or to a pinned alternative, as Chrome
  154's captures and source show it never does. Before, every profile sent
  the field there. `firefox::v157_http3_request` still sends it.
- Wire change for the Firefox TLS recipes over TCP: `firefox::v157_tls`
  offers the oldest connection's tickets, newest of them first, following
  the usual Windows capture order. `firefox_android::v156_tls` offers the
  oldest ticket, from Firefox's Unix clock and token-cache source; Android
  resumption itself is uncaptured. Both kept the newest ticket first
  before. Both now keep up to ten tickets per origin instead of eight,
  Firefox's default, and drop the ticket they would offer next when full.
  `TlsSettings::validate` accepts `session_tickets_per_origin` from 1 to 10,
  and the TCP session cache holds up to ten tickets. After a WebSocket
  opening, a Firefox-profile request resumes a ticket of the page's
  connection, as in every retained Windows Firefox `websocket-http1` run
  ([evidence](docs/explanation/validation.md#tls-resumption-over-tcp-evidence)).
- Wire change for the Chromium and Firefox WebSocket recipes on proxy
  routes: `chromium::v154_websocket`, `chrome_android::v154_websocket`,
  `brave_android::v153_websocket`, and `firefox::v157_websocket` now open a
  proxied `wss://` WebSocket on a capable pooled negotiated HTTP/2 session
  as well as an exact one, through the same proxy route, as Chromium 154
  and Firefox 157 source do. Before, they checked only the exact HTTP/2
  pool on a proxy route.
- Wire change for Alt-Svc: the store keeps up to eight `h3` alternatives a
  field lists, in field order, each expiring on its own `ma`, and a
  negotiated request uses the first one that is not broken, as Chrome 154
  does ([evidence](docs/explanation/validation.md#alt-svc-racing-evidence)).
  A racing client therefore races the next listed alternative once the
  first is broken, where before it used the origin alone until the first
  recovered. An alternative that fails after the request went to it, or
  answers `421`, under either policy, and a sequential client's alternative
  whose setup failed, are removed from the list, so the next request goes
  to the next listed alternative, where before the whole advertisement was
  dropped and it went to the origin. A new field still replaces the whole
  list.
- `chromium::v154_cookie_placement` and `firefox::v157_cookie_placement`
  put the jar's `Cookie` before a request's `If-None-Match` and
  `If-Modified-Since`, as the browsers add it before the validators. Before,
  it went after them where no later listed field followed: on a
  Chromium-family HTTP/1.1 request, and on a request whose template places
  the validators last or has no template. To keep the old Chromium
  placement, pass `CookiePlacement::before_fields(["priority"])` to
  `ClientProfile::with_cookie_placement`.
- A `wss://` opening of a `Client`, direct or through an HTTP or SOCKS5
  proxy, shares the TLS session tickets of its origin's request pool key: a
  profile-policy opening the negotiated pool's, and an exact opening the
  exact pool's of its protocol. It resumes a ticket an earlier request was
  issued, as Firefox 157 resumed the page's ticket on its WebSocket
  connections, and a later request resumes one the opening was issued, as
  Chrome 154's session cache, keyed without ALPN, offers it. A Firefox
  profile's opening now sends early data when it resumes a ticket that
  permits it and offers the ticket's ALPN protocol: the Upgrade GET over
  HTTP/1.1, or the preface, SETTINGS, and WINDOW_UPDATE over HTTP/2.
  Before, every opening made a full handshake
  ([evidence](docs/explanation/validation.md#tls-resumption-over-tcp-evidence)).
- On the direct route the exact HTTP/1.1 pool keeps the slower attempt of a
  `TcpBackupConnection` without a request: it stays with the pool key of
  the runtime that opened it, counts toward that key's connection bound
  once it connects, finishes any TLS handshake the way a request's
  connection does, and waits idle, and a request that finds no idle
  connection claims it instead of opening one. The pool keys of one origin
  and route on every runtime share one memory of the address family of
  their first successful connection for later connections. The key keeps
  every slower connection whatever its count, as Firefox does, so each
  backup connection whose slower attempt is in flight can add one
  connection beyond the bound. The negotiated pool does the same for a slower
  connection that selects HTTP/1.1 while the key has no HTTP/2 connection.
  When the first connection selects HTTP/2, a slower attempt that has not
  connected is closed, and one that has finishes its handshake and is
  closed, an HTTP/2 one after its preface and SETTINGS with `GOAWAY`; a
  slower HTTP/2 connection to a key without one becomes its HTTP/2
  connection.
- `chromium::v154_macos_client_hints` reports Chrome 154.0.8037.95 and
  `edge::v154_macos_client_hints` Edge 154.0.4258.48 in
  `sec-ch-ua-full-version` and `sec-ch-ua-full-version-list`, the builds the
  capture Mac runs since 2026-10-02, in place of 154.0.8037.58 and
  154.0.4258.37. The Edge macOS hints now equal the Windows ones apart from
  platform data
  ([evidence](docs/explanation/validation.md#macos-recipes)).
- `Http1TlsConnector::upgrade_get_direct` and
  `Http2TlsConnector::send_extended_connect_direct`, and their `_with_ech`
  forms when no ECH configuration is offered, offer early data when they
  resume a ticket permitting it and `TlsSettings::tcp_early_data` is set, as
  Firefox 157 does on a resumed WebSocket opening. The HTTP/1.1 Upgrade GET
  travels as early data; over HTTP/2 the connection preface and SETTINGS do,
  and the extended CONNECT waits for the server's answer. After a rejection
  the same bytes go out again on the connection, and a handshake that fails
  after early data fails the opening with the error a fresh connection's
  handshake reports. Openings through a proxy and connections that offer ECH
  from an HTTPS record still offer none, and the Chromium-family recipes
  never offer it
  ([evidence](docs/explanation/validation.md#tls-resumption-over-tcp-evidence)).
  `scripts/capture/tls_resumption.py` gained the `websocket` and
  `websocket-http1` scenarios.
- A client opens the UDP sockets of its HTTPS record lookups, and of an
  `AddressResolver::system_nameservers` resolver, with the profile's
  `UdpSettings`. With `chromium::v154_udp` on Windows, as in the Chrome,
  Edge, Brave, and Opera profiles, each query socket sets
  `SO_RANDOMIZE_PORT` and binds port 0 through the bind that retries a
  reserved port block, so Windows picks its port at random, as Chromium's
  built-in DNS client gets one; hickory picked an explicit random port
  before ([evidence](docs/explanation/validation.md#udp-socket-option-evidence)).
- `opera::v136_tls` and `opera::v136_http3_tls` set
  `ech_from_https_records`: given an HTTPS record with `ech`, Opera
  136.0.6008.52 encrypted its ClientHello over TCP and QUIC and handled a
  rejection as Chrome 154 does, once its own Secure DNS preferences pointed
  it at the record
  ([evidence](docs/explanation/validation.md#real-ech-evidence)). They
  sent ECH GREASE only before.
- `firefox::v157_http3_tls` sends the QUIC ClientHello Firefox 157 sends.
  It keeps `quic_transport_parameters` and then `encrypted_client_hello`
  last after the shuffled extensions, where all of them were shuffled, and
  now sends `record_size_limit` 16385, an empty `extended_master_secret`,
  and a `renegotiation_info` of one zero byte, which it left out. QUIC
  carries no TLS records, so the limit applies to nothing there. A captured
  ClientHello and Phantom's now differ only in per-connection values and
  the order of the shuffled extensions
  ([evidence](docs/explanation/validation.md#firefox-157-http3-recipe)).
  To keep the old ClientHello, set `record_size_limit: None`,
  `tls12_extensions_in_tls13_client_hello: false`, `extension_order:
  ClientHelloExtensionOrder::Permuted`, and `ech_grease_payload_length:
  EchGreasePayloadLength::Exact(240)` on the returned settings.
- `btls-sys` moves to `bywayhq/btls` commit `f478ea16`, whose native
  patches 0014 to 0017 write a fixed extension tail after the shuffled
  extensions, negotiate `record_size_limit` over QUIC, send
  `extended_master_secret` and `renegotiation_info` in a TLS 1.3-only
  ClientHello on request, and size the ECH GREASE payload from the
  ClientHello. The `phantom-btls` and `phantom-tokio-btls` forks move to
  `0.5.6-phantom.5`: `btls` adds
  `SslContextBuilder::set_extension_order_tail`,
  `set_tls12_extensions_in_tls13_client_hello` on `SslContextBuilder` and
  `SslRef`, and `SslRef::set_ech_grease_payload_from_client_hello`. A
  downstream lockfile changes only the `btls-sys` revision and those two
  versions.
- HTTP/2 and HTTP/3 requests carry the client hints known when their fields
  are built, as HTTP/1.1 requests already did, and as Chromium sets a
  request's hints before it chooses a connection. A hint that a response
  teaches while a request waits for a connection reaches the next request,
  not that one. A connection's ALPS `ACCEPT_CH` no longer adds a field at
  dispatch: when it names a hint a navigation, or a request without a
  template, lacks and the origin has not requested, the request stops
  before anything of it is written and starts again with the hints it
  lacked after `Accept` and before `Sec-Fetch-Site`, building its fields
  again, as Chromium 154 restarts a navigation; without a template they
  follow every other field. A `fetch` goes out as built. Any method and body may restart,
  a streaming body included, and a request restarts at most once per hint
  the profile sends on request. The hint stays with the request for its
  redirect hop, so a replacement connection after a graceful `GOAWAY` sends
  it too. A request sent as HTTP/3 early data, and its resend after a
  rejection, are never checked
  ([evidence](docs/explanation/validation.md#alps-accept_ch-restart-evidence)).
- A request that races an Alt-Svc alternative against its origin builds and
  checks its HTTP/3, HTTP/1.1, and HTTP/2 field lists once, before the race,
  and the winner sends them without building them again. A negotiated
  request builds its HTTP/1.1 and HTTP/2 lists once per redirect hop: a
  reused-connection replay, an unprocessed-request replay, and a race started
  again after an early-data handshake failed send them again, while a
  `Critical-CH` or status retry builds them again with the cookies and client
  hints its response stored. A cookie that another request stores during a
  race, or before such a replay, is sent from the next request on
  ([Fields of a repeated attempt](docs/explanation/design.md#fields-of-a-repeated-attempt)).
- `chromium::v154_windows_client_hints` reports Chrome 154.0.8037.97, the
  Windows build after 154.0.8037.58, in `sec-ch-ua-full-version` and the
  `Chromium` and `Google Chrome` entries of `sec-ch-ua-full-version-list`.
  Snapshots of 154.0.8037.97 matched every other retained Chrome 154 layer
  ([evidence](docs/explanation/validation.md#chrome-154-recipes)).
  `chromium::v154_macos_client_hints` keeps the Mac's 154.0.8037.58.
- `edge::v154_windows_client_hints` reports Edge 154.0.4258.48, the
  Windows build after 154.0.4258.37, in `sec-ch-ua-full-version` and
  `sec-ch-ua-full-version-list`. Snapshots of 154.0.4258.48 matched every
  other retained Edge 154 layer
  ([evidence](docs/explanation/validation.md#edge-154-recipes)).
  `edge::v154_macos_client_hints` keeps the Mac's 154.0.4258.37.
- `opera_android::v102_tls` is now built from `chromium::v154_tls` without
  trust-anchor IDs instead of from the desktop Opera recipe, whose Opera 136
  ClientHello carries them. Its settings are unchanged.
- Wire change for the Firefox recipe over TCP: a resumed direct connection
  whose ticket permits early data offers `early_data` and sends `GET`,
  `HEAD`, `OPTIONS`, and `TRACE` requests without a body as early data. After
  the server rejects the early data, the connection sends the same bytes
  again once the handshake completes. If the server then selects another ALPN
  protocol, the connection fails and a negotiated request starts again once,
  after the origin's tickets are removed, on a new connection that makes a
  full handshake, as Firefox restarts it; an exact HTTP/1.1 or HTTP/2
  request fails with the ALPN error a fresh connection reports. A handshake
  that fails after early data fails the request with
  `RequestErrorKind::Tls`, as a fresh connection's would. A negotiated
  request that is not replay safe waits for the server's answer within the
  connect timeout of the attempt that opened its connection, and a request
  sent as early data within its response-head timeout
  (`RequestTimeouts::connect`).
- `btls-sys` moves to `bywayhq/btls` commit `c4596bc5`, whose native patch
  0013 lets a client that sends `record_size_limit` offer early data and
  keeps the early-data capability of its tickets, and whose parent `126eca11`
  keeps the C allocator out of the generated bindings. The `phantom-btls`
  and `phantom-tokio-btls` forks move to `0.5.6-phantom.4`: `btls` adds
  `SslConnectorBuilder::enable_scoped_client_sessions_with_early_data`,
  `ScopedSslSession::early_data_capable`, `SslRef::set_early_data_enabled`,
  `in_early_data`, `early_data_accepted`, `reset_early_data_reject`, and
  `ErrorCode::EARLY_DATA_REJECTED`, and `tokio-btls` adds
  `SslStream::ssl_mut`. A downstream lockfile changes only the `btls-sys`
  revision and those two versions.
- `startup_capture.py --layer http3` launches the browser once
  `chrome_http3.py` reports on standard error that it has bound, instead of
  after a fixed `--server-start` wait of 3 seconds. `--server-start` is now
  the longest wait for that report (default 30 seconds).
- Wire change for the Chrome 154, Edge 153, and Brave 154 HTTP/3 recipes on a
  client with HTTPS record discovery: `chromium::v154_http3_tls` now keeps
  `ech_from_https_records`, and `edge::v154_http3_tls` and
  `brave::v154_http3_tls` inherit it, so a direct QUIC connection to the
  origin's own host and port, for an HTTP/3 alternative found through its
  HTTPS records or an exact HTTP/3 request, sends a real Encrypted Client
  Hello when the first record listing `h3` carries `ech`, as those browsers
  do. The connection starts once the lookup ends, at most 50 ms after
  address resolution. After a rejection it closes with `ech_required` and
  is not repeated over QUIC, as in the captures, and the alternative is
  marked broken. A racing client's request goes to the origin over TCP,
  which retries its own rejection once, as Chrome's does. Under the default
  `AltSvcPolicy::sequential()`, an alternative's setup failure ends the
  request, so a negotiated request that used to succeed with GREASE now
  fails with `RequestErrorKind::Tls` when the origin rejects the record's
  configuration; later requests go over TCP while the alternative is
  broken, and the next request after each broken period fails again. An
  exact HTTP/3 request fails the same way on every attempt. Since the retry
  configurations are not kept, this lasts until the cached record expires,
  after its TTL or at most one day. `opera::v136_http3_tls` clears the
  field, so Opera is unchanged, as are proxy routes and Alt-Svc
  alternatives at another host. To fall back to TCP as Chrome does, use
  `AltSvcPolicy::race`; to keep ECH GREASE on HTTP/3, set
  `settings.ech_from_https_records = false` on the value
  `chromium::v154_http3_tls`, `edge::v154_http3_tls`, or
  `brave::v154_http3_tls` returns.
- Wire change for TLS resumption over TCP. The Chrome 154, Edge 153, Brave
  154, and Opera 135 recipes keep at most two tickets per origin, the newest
  two, instead of eight, as the browsers did in the resumption captures; a
  client whose server issues many tickets resumes fewer connections before a
  full handshake. A resumed ClientHello from `firefox::v156_tls` (now named
  `v157_tls`) omits the empty `session_ticket` extension, as Firefox 156
  does, and the recipe keeps up to eight tickets per origin. Fresh
  ClientHellos are unchanged.
- Wire and performance: through an HTTP/2 proxy, the client opens CONNECT
  tunnels to different origins as streams of one proxy connection per
  session, proxy, and set of Basic credentials, as Chrome 154, Edge 153,
  and Firefox 156 do, instead of one TLS connection per tunnel. The streams
  are numbered 1, 3, 5, as Chromium numbers them; Firefox starts at 3. A
  tunnel past the proxy's `SETTINGS_MAX_CONCURRENT_STREAMS` waits on that
  connection, as in the browsers. With the Chromium CONNECT recipe, or no
  recipe, forwarded `http://` requests to every origin and WebSocket
  tunnels are streams of that connection too; with the Firefox recipe each of the three has its
  own connection. Forwarded requests to different origins now share one
  proxy connection instead of one per origin. A proxy sees fewer
  connections and TLS handshakes; tunnels on a connection share its
  flow-control windows. Each session keeps its own proxy connections.
- Wire change for the Edge 154 recipe on a client with HTTPS record
  discovery: `edge::v154_tls` now keeps `ech_from_https_records` from
  `chromium::v154_tls`, so a direct TLS connection over TCP to an origin
  whose HTTPS record carries `ech` sends a real Encrypted Client Hello instead
  of ECH GREASE, and its TLS handshake waits for the lookup for at most 50 ms
  after address resolution. As with the Chrome recipe, that covers negotiated
  and exact-protocol HTTP/1.1 and HTTP/2 requests and `wss://` WebSocket
  openings. Captures of Edge 153.0.4234.48 navigations show it doing the
  same. To keep GREASE, set
  `settings.ech_from_https_records = false` on the value `edge::v154_tls`
  returns.
- Wire and performance change for HTTP proxies with
  `HttpProxy::with_basic_auth`. After a `407` to an HTTP/1.1 CONNECT
  (plaintext or TLS proxy, WebSocket tunnels included) or to a forwarded
  `http://` request, the replay goes on the connection that carried the
  `407`, as Chrome 154, Edge 153, and Firefox 156 do, instead of a new proxy
  connection. This saves a TCP connect, and a TLS handshake for an
  `https://` proxy, per challenge. A `407` with `Connection: close` or
  `Proxy-Connection: close`, without a stated length, or with a body over
  `phantom_net::proxy::MAX_CHALLENGE_BODY_BYTES` (64 KiB) still gets a new
  connection. When the proxy closes the kept connection before answering, a
  CONNECT or an idempotent forwarded request is sent once more on a new
  connection; a POST or other non-idempotent forwarded request fails with
  the reused-connection error, where Chromium resends it. Reading the `407`
  body counts toward the response-head, read-idle, and total timeouts.

- A negotiated HTTP/1.1-or-HTTP/2 request copies its field lists less
  often: a bodyless `GET` no longer copies every list before dispatch in case
  a graceful `GOAWAY` needs a replay, and the HTTP/1.1 fields as sent are
  copied only when the connection selects HTTP/1.1. The bytes on the wire
  are unchanged.
- Wire change for the Chrome 154 recipe on a client with HTTPS record
  discovery: exact-protocol HTTP/1.1 and HTTP/2 requests and `wss://`
  WebSocket openings on the direct route now look up the origin's HTTPS
  record and send a real Encrypted Client Hello when it carries `ech`, as
  negotiated requests already did. Their TLS handshake waits for the lookup
  for at most 50 ms after address resolution, and a rejection is retried
  once. Before, they sent ECH GREASE and made no lookup. Proxy routes and
  profiles without `ech_from_https_records` are unchanged.
- Wire and performance change for HTTPS proxies with
  `HttpProxy::with_http2_transport` and `with_basic_auth`. After a `407` to
  an HTTP/2 CONNECT, WebSocket tunnels included, the replay is stream 3 of
  the proxy connection that carried the `407` on stream 1, as Chrome 154,
  Edge 153, and Firefox 156 replay on the challenged HTTP/2 connection. It
  used to open a new proxy connection, so each challenge now saves a TCP
  connect, a TLS handshake, and the HTTP/2 preface. On the challenged
  stream, and on any other rejected HTTP/2 CONNECT whose response ended its
  stream, Phantom now does what the profile's CONNECT recipe says, where it
  used to reset the stream with `CANCEL`: the Chromium recipe, and a profile
  without a recipe, send an empty END_STREAM DATA frame and wait until it is
  written before the replay, as Chrome and Edge do; the Firefox recipe sends
  nothing, as Firefox does. The wait ends after about 50 ms if the proxy
  stops reading. A `407` body still arriving is reset with `CANCEL`. The
  tunnel still holds its proxy connection alone. The one credentialed replay
  is sent once more on a new connection when the proxy closes the first one
  before answering it, or answers it with `GOAWAY` or `REFUSED_STREAM`.
  Error kinds and the single-replay rule are unchanged.
- Wire change for Alt-Svc racing (`AltSvcPolicy::race`) on clients that
  offer HTTP/3 early data, as the Chrome 154 and Edge 153 recipes do. A raced
  alternative setup now offers early data like other new connections, unless
  QUIC to the origin's own host and port failed a race and has not connected
  since, as Chromium's QUIC job does. A resumed alternative can win the race
  before its handshake completes, and a replay-safe request on it is sent as
  early data. The alternative is confirmed once the answer to its early data
  shows a completed handshake, read within the request's deadlines. If the
  handshake failed, QUIC to the origin is marked recently broken: a response
  already received is returned as it is, and a failed request with no body
  or an owned body is raced again once, without early data. A background
  alternative setup that resumed with early data after losing its race is
  confirmed once its handshake completes; if that handshake fails, nothing is
  marked broken or recently broken, as the connection carried no request.
- Wire change for `http://` requests forwarded through an HTTP/1.1 proxy.
  The Chrome and Edge request templates send `Proxy-Connection: keep-alive`
  where a direct request has `Connection: keep-alive`, in the same position,
  as Chrome 154 and Edge 153 do. Firefox's templates are unchanged. A caller
  field named `Connection` or `Proxy-Connection` keeps its value at the
  template's position.
- `HttpProxy` equality, and so connection pooling, now tells a proxy whose
  CONNECT fields the caller set with `HttpProxy::header`, `headers`, or
  `connect_headers` apart from one with the default fields, even when the
  fields are the same, such as `headers(Vec::new())`. Only the default fields
  take the profile's CONNECT recipe.
- Wire change for forwarded `http://` requests with `HttpProxy::with_basic_auth`
  credentials and a built-in request template. The generated
  `Proxy-Authorization` field takes the position Chrome 154, Edge 153, and
  Firefox 156 give it, on HTTP/1.1 and HTTP/2 proxies: after
  `Proxy-Connection`, or first on HTTP/2, for Chrome and Edge (after
  `Cache-Control` on a no-store `fetch`); before
  `Connection` with remembered credentials, and last or before `te` on the
  replay after a `407`, for Firefox. It used to follow every other field,
  which is still the position without a template. On a route without
  configured credentials, a caller's own `Proxy-Authorization` on a forwarded
  request takes the template's position for remembered credentials.

- Wire and performance change for negotiated requests (`get_negotiated`,
  `request_negotiated`) from a profile with `Http1Settings`, such as
  `chromium::v154_http1` or `firefox::v157_http1`. When ALPN selects
  HTTP/1.1, concurrent requests to one origin and route now open up to the
  profile's bound of connections, each with its own TLS handshake (and its
  own CONNECT tunnel on an HTTP proxy route), instead of waiting for one
  connection. `ClientBuilder::max_concurrent_http1_requests_per_origin`
  replaces that bound too. Until a connection to the origin and route has
  selected HTTP/2, concurrent requests start their handshakes in parallel,
  as Chromium 154 and Firefox 156 do, and requests beyond the bound wait for
  a handshake instead of failing at the HTTP/1.1 waiting bound. After that,
  a request waits for a handshake in progress, and HTTP/2 requests share
  one connection. Each client remembers up to 500 origin and route pairs
  that selected HTTP/2, beyond the life of their pool entries. Waiting for
  another request's handshake counts against the connect timeout. A
  profile without `Http1Settings` keeps one connection, as before.
- The `phantom-btls` and `phantom-tokio-btls` forks move to
  `0.5.6-phantom.3`: `btls::ssl` exports `SslEchKeys` and
  `SslEchKeysBuilder`, so a server can be given ECH keys. A downstream
  lockfile changes only those two versions. (`41c32d8`)
- Wire and performance change for HTTP proxies with Basic credentials. A
  tunnel or forwarded request to a proxy that already accepted the
  credentials now carries `Proxy-Authorization` on its first attempt, as
  Chrome, Edge, and Firefox do, instead of waiting for a `407` each time.
  After the first challenge, each tunnel saves one proxy round trip and one
  proxy connection. A `407` to remembered credentials forgets them and
  allows the usual single replay. To keep the old behavior, call
  `ClientBuilder::preemptive_proxy_authentication(false)`. CONNECT-UDP
  tunnels still start without credentials.

- Wire change for resumed HTTP/3 connections from the Chrome 154 and Edge
  153 recipes: replay-safe requests (`GET`, `HEAD`, `OPTIONS`, or `TRACE`
  with no body and no trailers) now leave in 0-RTT packets, as resumed
  Chrome 154 and Edge 153 connections send `GET`, `HEAD`, and `OPTIONS`.
  Before, the recipes' dynamic QPACK policy held each request until the
  server's SETTINGS arrived with the completed handshake, so only the H3
  control stream traveled in 0-RTT. Each connection now keeps the server's
  control-stream SETTINGS with the session tickets it receives, in the
  ticket's cache and under its isolation, and a connection that offers early
  data starts from the SETTINGS kept with its ticket (RFC 9114, section
  7.2.4.2), as Chromium does. Its QPACK encoder instructions and request
  HEADERS then go out before the handshake completes. If the server's
  SETTINGS change a remembered nonzero QPACK table capacity, or omit or
  lower another remembered value, the connection closes with
  `H3_SETTINGS_ERROR`.
  A connection holds the tickets it receives, at most two, until the
  server's SETTINGS arrive, and stores none if they never do.
  `phantom_quic_btls` gains `ApplicationState` and
  `QuicClientConfig::with_application_state`, and
  `phantom_net::http3::Http3Connection` gains
  `started_from_remembered_settings`. The vendored `phantom-h3` 0.0.8-phantom.3
  adds `client::Builder::remembered_peer_settings` and
  `client::Connection::peer_settings_to_remember`; `phantom-h3-datagram`
  0.0.2-phantom.3 and `phantom-h3-quinn` 0.0.10-phantom.3 follow its pin.

- Wire change for plaintext `http://` requests. To an origin that is not
  potentially trustworthy (not HTTPS, loopback, `localhost`, or
  `.localhost`), the built-in request templates leave out the `Sec-Fetch-*`
  fields and send `Accept-Encoding: gzip, deflate` instead of
  `gzip, deflate, br, zstd`, as Chrome 154, Edge 153, and Firefox 156 do.
  Automatic client hints now go to `http://` loopback and `localhost` origins,
  and `Accept-CH` from them is learned, where before only HTTPS origins got
  them. Content decoding follows the `Accept-Encoding` of the final redirect
  hop.
- Wire change for WebSocket openings from `chromium::v154_websocket` and
  `firefox::v157_websocket`. The recipes now send `Accept-Encoding`
  themselves: `gzip, deflate, br, zstd` to a `wss://` or loopback `ws://`
  URL, and `gzip, deflate` to any other `ws://` URL, where before the field
  was left to the caller. Firefox's recipe sends `Sec-Fetch-Dest`,
  `Sec-Fetch-Mode`, and `Sec-Fetch-Site` (default `same-origin`) only to a
  potentially trustworthy URL, where before it sent the first two to every
  URL and left `Sec-Fetch-Site` to the caller. This matches the Chrome 154,
  Edge 153, and Firefox 156 proxy route captures. A caller field with one of
  these names still replaces the recipe's value in place.

- Resumed HTTP/3 connections from the Chrome 154 and Edge 153 recipes add
  QUIC transport parameter `initial_rtt_us` (`0x3127`), as resumed Chrome 154
  and Edge 153 connections do. This changes their transport parameters on
  the wire. The value is the smoothed round-trip time that the last
  connection to the same server through the same pool entry measured, as a
  minimal-length varint, at a position permuted with the other parameters.
  A fresh connection sends no `initial_rtt_us`, and neither does the outer
  connection to a CONNECT-UDP proxy, since no capture shows a browser's
  resumed proxy connection.
  `phantom_profile::quic::QuicTransportParameterKind` gains `InitialRtt`, and
  `phantom_quic_btls::QuicClientConfig` gains `record_round_trip_time`.
  (`7d81daa`, `fc99d5a`)

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
- `chromium::v154_http2` and `firefox::v157_http2` set their browser's HPACK
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
- `chromium::v154_http3_tls`, and `edge::v154_http3_tls` through it, enable
  `session_tickets`, so HTTP/3 connections built from them resume sessions.
  The first ClientHello of a connection is unchanged. A resumed ClientHello
  adds the `pre_shared_key` extension, which changes the wire fingerprint of
  every resumed connection. (`278645f`)
- A request needs less memory and, in a debug build, less stack. In a debug
  build the future that `RequestBuilder::send` boxes shrinks from 27,008 to
  14,880 bytes, and the per-attempt allocation an HTTP/1.1, HTTP/2, or
  negotiated request makes to acquire a connection shrinks from 30-32 KB
  to under 200 bytes. A request phase with a timeout no longer allocates for
  the operation it times. Opening a pooled HTTP/1.1, HTTP/2, or negotiated
  connection now makes one allocation for its setup, and an HTTP/3 request
  makes one for its send.
- Opening a connection needs less stack in a debug build, measured on
  Windows. A Basic-authenticated CONNECT through an HTTPS proxy shrinks from
  39,328 to 6,152 bytes with `Http1TlsConnector` and from 39,360 to 6,168
  with `Http2TlsConnector` or `Http1Or2TlsConnector`; a plain one from
  20,168 to 5,440 and from 20,200 to 5,456. `Http3Connector::connect_direct`
  shrinks from 17,056 to 6,800 bytes, and opening a pooled HTTP/3 connection
  from 38,928 to 9,536. A new HTTP/3 connection makes one more allocation,
  for its HTTP/3 start. A proxy's `407` challenge and an HTTP/3 start after
  rejected early data each make one for their retry.

### Fixed

- HTTP/1.1 setup through an HTTPS proxy no longer exceeds the pinned
  nightly compiler's `Send` proof depth on Windows.
- An HTTP/3 request cancelled while its HEADERS frame waited for flow
  control, for example by a response-head timeout or a dropped future, is
  reset with `H3_REQUEST_CANCELLED`. Before, Quinn ended the stream after a
  truncated frame, which RFC 9114 makes a connection error, so a conforming
  server closed the connection and every request on it failed. The fix is
  the vendored h3 patch `reset-unsent-request.patch`; `phantom-h3`,
  `phantom-h3-datagram`, and `phantom-h3-quinn` move to `-phantom.7`.
- A client used from more than one Tokio runtime no longer sends a request
  on a pooled connection that another runtime opened. Once that runtime was
  dropped, or no longer driven, as a current-thread runtime is after
  `block_on` returns, nothing read the connection: an HTTP/3 request hung or
  failed, and HTTP/1.1 and HTTP/2 requests hung while the first runtime
  still existed. Every connection pool, including `phantom-net`'s
  `Http2ProxyPool`, now keys connections by runtime, so each runtime opens
  its own. The per-origin limits on active and waiting requests, and the
  memory that an origin selected HTTP/2, still span runtimes.
- A cross-origin redirect removes the `Authorization`, `Cookie2`, and
  `Proxy-Authorization` fields a request template sends itself, as it
  removed the caller's own. Before, a template literal such as
  `RequestField::literal("Authorization", token)` went to every redirect
  target. Fetch removes `Authorization` at a cross-origin redirect whoever
  set it, and so does Chromium 154.
- An HTTPS-record lookup that ends without a result, because the runtime
  that ran it shut down or a `HttpsRecordResolver::from_fn` resolver
  panicked, no longer leaves its origin waiting on it for the life of the
  client. Every later request counted the origin as advertising no records,
  so it went without the HTTPS-record HTTP/3 upgrade and ECH; the next
  request now starts a new lookup. A request on another runtime no longer
  waits on a lookup running on a runtime that is no longer driven: it starts
  one on its own runtime.
- A forward-proxy `407` whose body is drained before the credentialed
  replay, with a `read_idle` timeout set, fails with `RuntimeUnavailable` on
  a Tokio runtime without its time driver instead of panicking.
- On macOS, internal deadlines such as the wait for an HTTPS record, the
  TCP attempt fallback, the TCP keepalive schedule, and HTTP/2 PING timeouts
  could fire up to about 150 ms late on a loaded host, so a record that
  arrived after Chromium's 50 ms bound could still be offered as ECH. They
  now fire on time.
- The `BuildError` for a `max_http2_proxy_connections_per_route` above the
  ceiling no longer contains a run of spaces left by a broken line
  continuation in its message.
- Nightly Rust 2026-09-01 no longer warns with
  `recursion_depth_exceeding_limit` (rust-lang/rust#159228) when it proves
  that a request or WebSocket future is `Send`. The warning appeared when
  building `phantom-http` and in a crate that spawns `RequestBuilder::send`
  or `WebSocketRequestBuilder::connect`. The compiler says it will become an
  error. The stable toolchain does not report it; the gate checks for it
  with that nightly when it is installed.
- `phantom-net` boxes the Basic challenge exchange of an authenticated HTTP
  or HTTPS proxy tunnel. Proving
  `Http1TlsConnector::connect_https_connect_with_basic_auth` `Send` now
  takes a recursion depth of 95, where it took 121 of the default 128, and
  `connect_http_connect_with_basic_auth` 70 instead of 114.
- Dropping an HTTP/2 tunnel after its connection closed no longer queues a
  `RST_STREAM` that nothing writes, which left the stream in the vendored
  `http2` store and failed its debug assertion in debug builds.
- HTTP/2 sends a field marked sensitive as a never-indexed literal even when
  a static entry, or an entry inserted before the field was marked, matches
  it. It was sent as that entry's index, under any profile.
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
- `HttpsRecordResolver::lookup` fails with `HttpsLookupErrorKind::Resolve`
  when a response carries an HTTPS record owned by a name other than the end
  of the query's CNAME chain, as Chromium does. Before, such a record was
  returned and could decide whether HTTP/3 discovery advertised `h3`.
- A negotiated request with a template that has no HTTP/3 list, such as a
  Firefox template, on a client with Alt-Svc enabled is sent through an HTTP
  proxy route instead of failing with `RequestErrorKind::RequestTemplate`. A
  CONNECT tunnel cannot carry QUIC, so the request never moves to HTTP/3. On
  a CONNECT-UDP route it fails with `UnsupportedRoute`, as a negotiated
  request without a template does. A direct or SOCKS5 route still refuses it.
- `SessionBuilder::build` rejects a retry policy whose delay or
  `Retry-After` limit the runtime clock cannot represent, with
  `BuildErrorKind::InvalidPolicy`, as `ClientBuilder::build` does. The
  `Debug` output of `ClientBuilder` includes its `http3_early_data` choice.
- The capture tools run on macOS. Chromium launches there receive
  `--use-mock-keychain`, so a temporary profile leaves the login keychain
  alone. After a run, processes that still name its temporary profile are
  killed, as on Windows. `startup_capture.py` starts the browser in its own
  process group; without one, its cleanup raised `ProcessLookupError`
  outside Windows.
- On Windows, an HTTP/3 connection or a SOCKS5 UDP association no longer
  fails to open when the host's UDP port counter reaches a reserved port
  block. Windows can refuse that bind to port 0 with os error 10055
  (`WSAENOBUFS`) instead of skipping the block; Phantom now binds again, up
  to three more times. An explicit source binding gets the same retry.
- `scripts/capture/run_matrix.py` names each attempt's temporary directory
  `tmp/<digest>.<attempt>` instead of after the job ID. Firefox 157 on
  Windows does not start from a profile path of 209 or more characters, so
  jobs with the longest IDs, such as `https-proxy-auth-remembered-hostname`
  and `retry-persists-across-reconnect`, timed out in a deep work directory.
  On Windows the runner now refuses a work directory too deep for a Firefox
  profile when the jobs include Firefox.
  Its log no longer says that Windows refused the job object after every
  attempt: the runner read the flag after closing the job.
- `scripts/capture/snapshot_compare.py` no longer reports a difference
  between two Firefox snapshots for the per-connection shuffle of the QUIC
  ClientHello extensions before `quic_transport_parameters` and
  `encrypted_client_hello`, or for the ECH GREASE AEAD Firefox draws per
  connection. Moving either tail extension is still a difference.
- `scripts/capture/chrome_http3.py` accepts `--listen 127.0.0.1:0`: it binds
  a port the operating system chooses, reports it on its `listening on`
  line, and writes it into `listen_address` and in place of each `<port>` in
  `--launch-arguments`. `startup_capture.py` passes port 0 instead of a
  probed and released port checked against a hardcoded Windows reserved
  range. The capture and conformance QUIC servers that bind port 0 retry a
  bind that fails with os error 10055.

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
