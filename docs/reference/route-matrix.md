# Route matrix

This table shows what Phantom does for each combination of request scheme,
protocol, and [route](glossary.md#route). "Rejected" means a typed error
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
| `http://`, exact H1 | Plaintext TCP | Absolute-form forwarding | Rejected | Rejected | Rejected |
| `http://`, exact H2 or H3, or negotiated | Rejected | Rejected | Rejected | Rejected | Rejected |
| `https://`, exact H1 or H2 | TLS | CONNECT tunnel | CONNECT stream (one proxy connection per tunnel) | TCP tunnel | Rejected |
| `https://`, negotiated | One TLS handshake, then H1 or H2; optional Alt-Svc H3 | Rejected | Rejected | One TLS handshake in a TCP tunnel, then H1 or H2; optional Alt-Svc H3 over UDP ASSOCIATE | Rejected |
| `https://`, exact H3 | QUIC | Rejected | Rejected | UDP ASSOCIATE | QUIC in HTTP Datagrams (H3 leg) or DATAGRAM capsules (H2 extended CONNECT or H1 Upgrade leg) |
| `ws://`, H1 | Plaintext Upgrade | Absolute-form forwarded Upgrade | Rejected | Plaintext Upgrade in a TCP tunnel | Rejected |
| `wss://`, H1 | TLS Upgrade | CONNECT tunnel | CONNECT stream | TLS Upgrade in a TCP tunnel | Rejected |
| `ws://`, H2 | Rejected | Rejected | Rejected | Rejected | Rejected |
| `wss://`, H2 | Extended CONNECT on a dedicated connection | Extended CONNECT inside a CONNECT tunnel | Extended CONNECT inside a CONNECT stream | Extended CONNECT in a TCP tunnel | Rejected |
| `ws://` or `wss://`, H3 | Rejected | Rejected | Rejected | Rejected | Rejected |

Notes:

- Every supported cell has a public loopback regression test.
- Negotiation needs a TLS stream to the origin for ALPN, and the optional
  Alt-Svc H3 upgrade that rides on it needs a UDP path to the advertised
  alternative over the same route. HTTP proxies carry only TCP and CONNECT-UDP
  carries only QUIC, so both reject negotiated requests before any proxy I/O.
  See [Routes that carry the upgrade](../guides/http3.md#upgrade-to-http3-when-the-server-advertises-it).
- WebSocket and SSE requests need the matching Cargo feature.
- A `ws://` or `wss://` request over H3 fails when the builder is created.
- SSE event sources follow the ordinary rows for their scheme and protocol.
- The `wss://` H2 row describes `websocket_with_protocol`. With
  `websocket_with_profile_policy`, the profile's connection policy may instead
  place the WebSocket on a pooled H2 session or open an HTTP/1.1 Upgrade
  connection. See
  [Profile connection policy](../guides/websocket.md#open-a-websocket-the-way-the-browser-does).

## Next

- [Routes and proxies](../guides/routes-and-proxies.md): configure each
  route.
- [WebSocket](../guides/websocket.md): the WebSocket rules behind the `ws://`
  and `wss://` rows.
