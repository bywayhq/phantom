# Route matrix

Find what Phantom does for each combination of request scheme, protocol, and
[route](glossary.md#route). "Rejected" means a typed error
before any proxy or origin I/O. No cell falls back to another row or column.

> For builders choosing a route. Configuration is in
> [Routes and proxies](../guides/routes-and-proxies.md).

Columns:

- **Direct**: no proxy.
- **H1 proxy**: an `http://` or `https://` `HttpProxy` in its default HTTP/1.1
  mode.
- **H2 proxy**: an `https://` proxy with `with_http2_transport`.
- **SOCKS5**: both local-DNS `socks5://` and remote-DNS `socks5h://`.
- **CONNECT-UDP**: an `https://` template over its default H3 leg or an
  explicit H2 or H1 leg.

Rows use [H1, H2, and H3](glossary.md#h1-h2-h3) for HTTP/1.1, HTTP/2, and
HTTP/3. [Exact](glossary.md#exact-protocol) forces one protocol;
[negotiated](glossary.md#negotiated-protocol) lets TLS ALPN choose H1 or H2.

| Request | Direct | H1 proxy | H2 proxy | SOCKS5 | CONNECT-UDP |
| --- | --- | --- | --- | --- | --- |
| `http://`, exact H1 | Plaintext TCP | Absolute-form forwarding | Rejected | Plaintext H1 in a TCP tunnel | Rejected |
| `http://`, negotiated | Plaintext TCP, H1 | Absolute-form forwarding, H1 | H2 forwarding | Plaintext H1 in a TCP tunnel | Rejected |
| `http://`, exact H2 | Rejected | Rejected | H2 forwarding | Rejected | Rejected |
| `http://`, exact H3 | Rejected | Rejected | Rejected | Rejected | Rejected |
| `https://`, exact H1 or H2 | TLS | CONNECT tunnel | CONNECT stream (one proxy connection per tunnel) | TCP tunnel | Rejected |
| `https://`, negotiated | One TLS handshake, then H1 or H2; optional Alt-Svc H3 | One TLS handshake in a CONNECT tunnel, then H1 or H2; no Alt-Svc | One TLS handshake in a CONNECT stream, then H1 or H2; no Alt-Svc | One TLS handshake in a TCP tunnel, then H1 or H2; optional Alt-Svc H3 over UDP ASSOCIATE | Rejected |
| `https://`, exact H3 | QUIC | Rejected | Rejected | UDP ASSOCIATE | QUIC in HTTP Datagrams (H3 leg) or DATAGRAM capsules (H2 extended CONNECT or H1 Upgrade leg) |
| `ws://`, H1 | Plaintext Upgrade | Plaintext Upgrade in a CONNECT tunnel | Plaintext Upgrade in a CONNECT stream | Plaintext Upgrade in a TCP tunnel | Rejected |
| `wss://`, H1 | TLS Upgrade | CONNECT tunnel | CONNECT stream | TLS Upgrade in a TCP tunnel | Rejected |
| `ws://`, H2 | Rejected | Rejected | Rejected | Rejected | Rejected |
| `wss://`, H2 | Extended CONNECT on a dedicated connection | Extended CONNECT inside a CONNECT tunnel | Extended CONNECT inside a CONNECT stream | Extended CONNECT in a TCP tunnel | Rejected |
| `ws://` or `wss://`, H3 | Rejected | Rejected | Rejected | Rejected | Rejected |

Notes:

- Every supported cell has a public loopback regression test.
- Negotiation needs a TLS stream to the origin for ALPN. An HTTP proxy
  carries it in one CONNECT tunnel per connection, over either proxy
  transport. CONNECT-UDP carries only QUIC, so it rejects negotiated requests
  before any proxy I/O.
- The optional Alt-Svc H3 upgrade also needs a UDP path to the advertised
  alternative over the same route. An HTTP proxy's tunnel cannot carry QUIC,
  so negotiated requests through it store no Alt-Svc advertisement and stay on
  H1 or H2. See
  [Routes that carry the upgrade](../guides/http3.md#upgrade-to-http3-when-the-server-advertises-it).
- A negotiated `http://` request has no TLS stream for ALPN, so it is sent as
  H1, as a browser sends it, and follows the exact H1 row. Through an H2
  proxy it follows the exact H2 row instead, as browsers forward it over H2.
  It reports the protocol it used and learns no Alt-Svc alternative.
- H2 forwarding sends the request to the proxy with `:scheme` `http` and the
  origin in `:authority`, in the profile's pseudo-header order. The response
  reports H2. Exact H1 through an H2 proxy is rejected, not sent as H2.
- WebSocket and SSE requests need the matching Cargo feature.
- A `ws://` or `wss://` request over H3 fails when the builder is created.
- SSE event sources follow the ordinary rows for their scheme and protocol.
- The `wss://` H2 row describes `websocket_with_protocol`. With
  `websocket_with_profile_policy`, the profile's connection policy may instead
  place the WebSocket on a pooled H2 session or open an HTTP/1.1 Upgrade
  connection. See
  [Profile connection policy](websocket.md#profile-connection-policy).

## HTTP proxy rules

- `HttpProxy::header` appends a CONNECT field after the leading `Host`.
- `HttpProxy::headers` replaces the fields after `Host`.
- `HttpProxy::connect_headers` replaces the whole sequence, and
  `HttpConnectHeader::authority` places `Host` in it.
- A literal `Host` or framing field in the CONNECT fields fails before proxy
  I/O. These fields do not affect forwarded requests.
- In HTTP/2 mode, each tunnel opens its own proxy connection with the
  profile's HTTP/2 settings.
- In HTTP/2 mode, the CONNECT request (RFC 9113 section 8.5) has only
  `:method` and `:authority`, then lowercase fields.
- In HTTP/2 mode, a connection-specific field such as `Proxy-Connection`
  fails before I/O.
- In HTTP/2 mode, closing the origin connection resets its stream and ends
  its proxy connection.
- In HTTP/2 mode, `http://` requests to one origin share one pooled proxy
  connection with the profile's HTTP/2 settings, separate from tunnels.
- H2 forwarding answers a Basic `407` with one replay on the same proxy
  connection. Without configured credentials, a caller's own
  `proxy-authorization` field is sent to the proxy.
- After a proxy accepts configured Basic credentials, later CONNECT requests
  on either transport and later forwarded requests to it carry them first
  ([Proxy authentication](../explanation/design.md#proxy-authentication)).

## SOCKS5 rules

- An authentication, negotiation, or rejection failure is typed, and no
  other address is tried.
- A failed proxy TCP connect or QUIC setup is retried only through a fresh
  association on the same route, under the
  [connection-setup retry](../guides/retries.md#retry-when-a-connection-fails-to-open)
  policy.
- A UDP ASSOCIATE reply with a domain relay address or a zero port fails.
- An unspecified relay address is replaced with the IP of the established TCP
  proxy connection, keeping the returned port.
- Fragmented, malformed, wrong-target, and non-relay datagrams are dropped.
  With `socks5h://`, replies from the exact domain, or from an IP on the same
  port, are accepted.

## CONNECT-UDP rules

- A template whose scheme is not `https` fails with
  `ConnectUdpProxyConfigErrorKind::UnsupportedScheme`, on every leg.
- A template without `{target_host}` and `{target_port}` in its path or query
  fails before I/O. Only simple (`{var}`) and form-style query (`{?var}`,
  `{&var}`) expressions are accepted.
- The target is always sent as percent-encoded text; Phantom performs no
  local lookup of it.
- Disabled proxy certificate verification fails for this route on every leg,
  including a route set per request.
- A proxy that does not enable extended CONNECT or HTTP Datagrams fails with
  `RequestErrorKind::Proxy` before any origin I/O.
- An HTTP/3-leg proxy profile that cannot carry a full 1,200-byte QUIC
  Initial fails before I/O ([limits](limits.md#connect-udp)).
- On the HTTP/2 and HTTP/1.1 legs, a proxy that selects another ALPN
  protocol fails; Phantom never switches legs.
- A final status other than 2xx (101 on the HTTP/1.1 leg) fails with
  `RequestErrorKind::Proxy`, and the error's source carries the status.
- A caller field named `Host`, `Connection`, `Upgrade`, `Capsule-Protocol`,
  `Content-Length`, or `Transfer-Encoding` fails before I/O.
- A second `407`, or a malformed or non-Basic challenge, fails. Without
  credentials, a `407` is an ordinary rejection. Every tunnel starts without
  credentials; the client does not remember a CONNECT-UDP proxy's challenge.
- Only failures to resolve or connect to the proxy are retried, each on a
  fresh proxy connection with the same route and leg. Every other failure is
  final.
- Each origin connection opens its own connection to the proxy.
- The route never learns or evicts Alt-Svc state.

## Next

- [Routes and proxies](../guides/routes-and-proxies.md): configure each
  route.
- [WebSocket reference](websocket.md#routes): the WebSocket rules behind the `ws://`
  and `wss://` rows.
