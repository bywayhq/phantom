# Route matrix

This table lists what each combination of request scheme, protocol, and route
does. "Rejected" means a typed error before any proxy or origin I/O; nothing
falls back to another row or column.

Column meanings:

- **H1 proxy**: an `http://` or `https://` `HttpProxy` in its default HTTP/1.1
  mode.
- **H2 proxy**: an `https://` proxy with `with_http2_transport`.
- **SOCKS5**: both local-DNS `socks5://` and remote-DNS `socks5h://`.
- **CONNECT-UDP**: an `https://` template over its default H3 leg or an
  explicit H2 or H1 leg.

| Request | Direct | H1 proxy | H2 proxy | SOCKS5 | CONNECT-UDP |
| --- | --- | --- | --- | --- | --- |
| `http://`, exact H1 | Plaintext TCP | Absolute-form forwarding | Rejected | Rejected | Rejected |
| `http://`, exact H2 or H3, or negotiated | Rejected | Rejected | Rejected | Rejected | Rejected |
| `https://`, exact H1 or H2 | TLS | CONNECT tunnel | CONNECT stream (one proxy connection per tunnel) | TCP tunnel | Rejected |
| `https://`, negotiated | One TLS handshake, then H1 or H2; optional Alt-Svc H3 | Rejected | Rejected | Rejected | Rejected |
| `https://`, exact H3 | QUIC | Rejected | Rejected | UDP ASSOCIATE | QUIC in HTTP Datagrams (H3 leg) or DATAGRAM capsules (H2 extended CONNECT or H1 Upgrade leg) |
| `ws://`, H1 | Plaintext Upgrade | Absolute-form forwarded Upgrade | Rejected | Plaintext Upgrade in a TCP tunnel | Rejected |
| `wss://`, H1 | TLS Upgrade | CONNECT tunnel | CONNECT stream | TLS Upgrade in a TCP tunnel | Rejected |
| `ws://`, H2 | Rejected | Rejected | Rejected | Rejected | Rejected |
| `wss://`, H2 | Extended CONNECT on a dedicated connection | Extended CONNECT inside a CONNECT tunnel | Extended CONNECT inside a CONNECT stream | Extended CONNECT in a TCP tunnel | Rejected |
| `ws://` or `wss://`, H3 | Rejected | Rejected | Rejected | Rejected | Rejected |

Every supported cell has a public loopback regression. WebSocket and SSE
requests need the matching Cargo feature, and `ws://` or `wss://` over H3
fails when the builder is created. SSE event sources follow the ordinary rows
for their scheme and protocol.

The `wss://` H2 row describes `websocket_with_protocol`. With
`websocket_with_profile_policy`, the profile's connection policy may instead
place the WebSocket on a pooled H2 session, or open an HTTP/1.1 Upgrade
connection; see
[Profile connection policy](../guides/websocket.md#profile-connection-policy).

See [Routes and proxies](../guides/routes-and-proxies.md) for configuration
and [WebSocket](../guides/websocket.md) for WebSocket rules.
