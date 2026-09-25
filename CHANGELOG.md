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

- `phantom-net` connectors resolve names through a
  `phantom_net::host_resolver::HostResolver`, which holds host overrides, an
  optional `AddressResolver`, and the optional `AddressCache`. On
  `Http1TlsConnector`, `Http2TlsConnector`, `Http1Or2TlsConnector`,
  `Http3Connector`, and `HttpsProxyConnector`, `with_address_cache` and
  `address_cache` are replaced by `with_host_resolver` and `host_resolver`.
  The `phantom` facade API is unchanged.
  Migrate: replace `connector.with_address_cache(AddressCache::new(settings))`
  with `connector.with_host_resolver(HostResolver::new().with_cache(settings))`,
  and `connector.address_cache()` with
  `connector.host_resolver().and_then(HostResolver::cache)`. To share one
  cache between connectors, as a cloned `AddressCache` did, build one
  `HostResolver` and pass a clone of it to each connector; each
  `with_cache` call creates a separate cache.
- `TlsSettings` gained the public field `ech_from_https_records`, so struct
  literals that name every field no longer compile. `chromium::v154_tls`
  sets it, which changes the Chrome 154 recipe's wire behavior on a client
  with HTTPS record discovery: a direct negotiated HTTP/1.1 or HTTP/2
  connection to an origin whose HTTPS record carries `ech` sends a real
  Encrypted Client Hello, with the record's public name as the outer server
  name, and its TLS handshake waits for the lookup for at most 50 ms after
  address resolution. A QUIC connector rejects the field. (`e6e5076`)
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
- `chromium::v154_http3_tls`, and `edge::v153_http3_tls` through it, set
  `session_tickets`. `phantom_quic_btls::QuicClientConfig::with_tls_profile`
  rejects a profile that sets it with `QuicTlsProfileErrorKind::InvalidProfile`
  unless the context was prepared for session resumption, so code that builds
  a `QuicClientConfig` directly from either recipe now fails. The `phantom`
  client and `phantom_net::http3::Http3Connector` prepare their contexts and
  are not affected. The commit that changed the recipes, `278645f`, lacks the
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
  sends it again on a new connection; a failed handshake or invalid
  handshake metadata is an error. `ClientBuilder::http3_early_data` now
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

### Added

- `phantom_net::proxy::MAX_CHALLENGE_BODY_BYTES` (64 KiB): the longest
  `407` body Phantom reads so the replay can use the challenged HTTP/1.1
  proxy connection.
- `ClientBuilder::max_http2_connections_per_origin`: lets exact HTTP/2 and
  negotiated requests that select HTTP/2 open up to that many connections per
  origin and route. A request opens another only when every connection
  carries as many streams as the lower of the active bound and the peer's
  `SETTINGS_MAX_CONCURRENT_STREAMS`, and new streams go to the least-loaded
  connection. The default stays one connection, as browsers keep.
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
  not kept) and `firefox::v156_dns_cache` (1,600 names, answers and failures
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
  and `firefox::v156_proxy_connect` carry the captured fields, with the
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

### Changed

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
  `chromium::v154_http1` or `firefox::v156_http1`. When ALPN selects
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
  `firefox::v156_websocket`. The recipes now send `Accept-Encoding`
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
- `chromium::v154_http3_tls`, and `edge::v153_http3_tls` through it, enable
  `session_tickets`, so HTTP/3 connections built from them resume sessions.
  The first ClientHello of a connection is unchanged. A resumed ClientHello
  adds the `pre_shared_key` extension, which changes the wire fingerprint of
  every resumed connection. (`278645f`)

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
