# WebSocket reference

Look up WebSocket routes, opening headers, response checks, and compression.
For a working example, see the [WebSocket guide](../guides/websocket.md).

Frame, message, and write-buffer limits are in
[Defaults and limits](limits.md#websocket). Why the connection and retry
rules work this way is in [Design](../explanation/design.md#websocket-and-sse).

## Routes

| Route | H1 | H2 | H3 |
| --- | --- | --- | --- |
| Direct | `ws://` and `wss://` | `wss://` | `wss://` |
| HTTP proxy, HTTP/1.1 transport | `ws://` and `wss://` (CONNECT tunnel) | `wss://` (CONNECT tunnel) | Rejected |
| HTTPS proxy, HTTP/2 transport (`HttpProxy::with_http2_transport`) | `ws://` and `wss://` (CONNECT stream) | `wss://` (CONNECT stream) | Rejected |
| SOCKS5 (`socks5://` or `socks5h://`) | `ws://` and `wss://` | `wss://` | `wss://` (UDP ASSOCIATE) |
| CONNECT-UDP | Rejected | Rejected | `wss://`, on every proxy leg |

Any other combination fails with a typed error before proxy or origin I/O;
the [route matrix](route-matrix.md) covers every scheme, protocol, and route.

| Route | Rule |
| --- | --- |
| `ws://` through an HTTP proxy | Phantom sends CONNECT for the origin's host and port, then the same origin-form Upgrade as a direct connection inside the tunnel, with no TLS to the origin. The CONNECT carries the route's CONNECT fields, or the profile's [proxy CONNECT fields](profiles.md#proxy-connect-fields) with the opening's `User-Agent`, as for `wss://`. A refused CONNECT is a `WebSocketErrorKind::Proxy` error with no handshake response; an origin that refuses the Upgrade inside the tunnel is `HandshakeRejected`. |
| SOCKS5 | After the tunnel is up, `ws://` sends the same origin-form Upgrade as a direct connection. `socks5://` resolves the origin locally; `socks5h://` sends the canonical DNS name to the proxy. Username and password authentication applies only to SOCKS negotiation. |
| H2 through a proxy | Phantom opens a dedicated tunnel, then runs origin TLS, the HTTP/2 preface, and extended CONNECT inside it, as on a direct route. The origin must still enable extended CONNECT. Under [profile policy](#profile-connection-policy), a pooled H2 session on the same route may carry the WebSocket instead, inside its existing tunnel. |
| H3 | `websocket_with_protocol(HttpProtocol::Http3, ..)` sends RFC 9220 extended CONNECT as a new stream on the QUIC connection the client's HTTP/3 pool keeps for the origin and route, opening one when it has none with room. The stream holds one per-origin admission until the WebSocket is dropped or ends, so a request beyond `max_concurrent_http3_requests_per_origin` waits, and one beyond `max_pending_http3_requests_per_origin` fails with `WebSocketErrorKind::Capacity`. The profile needs `Http3RequestSettings::extended_connect_pseudo_header_order`, which no named recipe sets, or `connect` fails with `ProtocolUnavailable` before I/O. A peer whose SETTINGS do not enable extended CONNECT fails with `WebSocketErrorKind::Http3` before any stream opens. |
| Proxy credentials | Literal `Proxy-Authorization` fields are rejected. With Basic credentials on the proxy, the first connection to that proxy starts anonymously and replays once over the same route, only after a strict `407` Basic challenge: on the challenged connection when the `407` leaves it open, and on a new one otherwise. Once the proxy accepts the credentials, later tunnels to it send them on the first CONNECT. |
| Proxy failure | A proxy rejection, SOCKS5 failure, or proxy ALPN mismatch is a terminal proxy error. Phantom never falls back to a direct connection or from H2 to an H1 Upgrade. |

## Opening templates

The opening request is an ordered template of literal fields and typed
placeholders for values Phantom manages: the URI authority, the random key,
client cookies, and, with `websocket-deflate`, the compression offer. Literal
fields keep their order and casing.

| Source | Applies to |
| --- | --- |
| Built-in H1 or H2 template | Every H1 or H2 builder, when nothing else is set |
| Built-in H2 template | Every H3 builder without `headers`: no recipe has H3 opening fields |
| `WebSocketSettings` on the profile | Every H1 or H2 builder on that client; replaces the built-in templates |
| `WebSocketRequestBuilder::headers` | One connection; replaces the whole template. Fails under `websocket_with_profile_policy`. |

All validation finishes before network I/O.

| Rule | H1 | H2 and H3 |
| --- | --- | --- |
| Authority placeholder | Exactly one | Rejected |
| Key placeholder | Exactly one | Rejected |
| `Upgrade`, `Connection` | One valid `Upgrade: websocket`; one `Connection` containing `Upgrade` | Rejected |
| Version | 13 | Default field `sec-websocket-version: 13` |
| Literal `Host`, `Sec-WebSocket-Key` | Rejected | Rejected |
| Uppercase field names | Allowed | Rejected |
| Literal `Sec-WebSocket-Extensions` | Rejected; use the `permessage_deflate` placeholder | Rejected |
| Literal `Proxy-Authorization` | Rejected | Rejected |

On H2 and H3, the `:method`, `:authority`, `:scheme`, `:path`, and
`:protocol = websocket` pseudo-fields come from the request and the
extended-CONNECT pseudo-header order of the profile's HTTP/2 or HTTP/3
settings. The default ordinary fields are
`sec-websocket-version: 13`, the compression placeholder when enabled, and
the cookie placeholder.

## Response checks

| Check | H1 | H2 and H3 |
| --- | --- | --- |
| Success status | `101` over HTTP/1.1 | Any 2xx over the protocol of the request |
| Accept value | Exactly one matching `Sec-WebSocket-Accept` | `Sec-WebSocket-Accept` rejected |
| `Upgrade`, `Connection` | Valid tokens required | Rejected |
| Body framing or transfer coding | Rejected | Transfer coding rejected |
| Extensions | Only an offered extension; the compression response is parsed strictly before the codec is installed | Same |
| Subprotocol | At most one of the offered values | Same |

A duplicate, malformed, unknown, or contradictory compression selection
fails the handshake. Any other status is returned through
`WebSocketError::response`, with its streaming body and ordered fields.

## Profile connection policy

`WebSocketSettings` holds the ordered H1 and H2 templates, the
`permessage-deflate` offer, and a `WebSocketConnectionPolicy`.
`Client::websocket_with_profile_policy` applies the policy; the `websocket`
and `websocket_with_protocol` builders use only the templates. The policy
chooses once, before any WebSocket bytes are sent:

1. `ws://` always uses an HTTP/1.1 Upgrade.
2. For `wss://`, a pooled, reusable H2 session to the same origin and route
   whose peer enabled `SETTINGS_ENABLE_CONNECT_PROTOCOL` carries the
   WebSocket as a new extended CONNECT stream. Phantom checks the negotiated
   H1/H2 pool before the exact H2 pool, and opens nothing to look. On an
   HTTP proxy or SOCKS5 route it checks them only when
   `proxied_http2_session` is `WebSocketProxiedSession::Reuse`; with
   `Ignore` the WebSocket goes to step 3 as if no session existed.
3. Otherwise `without_http2_session` or `with_incapable_http2_session` names
   the new connection:
   - `Http1Upgrade`: a TLS connection offering `http1_alpn_protocols`, which
     must include `http/1.1` and not `h2`. An ALPS offer whose protocol is no
     longer offered is dropped from this connection's ClientHello; every
     other TLS field is unchanged.
   - `Http2ExtendedConnect`: a connection with the profile's ordinary TLS
     offer.

A rejection, refused stream, reset, missing peer setting, or ALPN mismatch on
the chosen connection is a typed error.

A WebSocket on a reused proxied session opens inside that session's tunnel,
so it sends no proxy CONNECT and no `Proxy-Authorization`. The route,
proxy credentials included, is part of the pool key: a WebSocket whose route
names other credentials never joins the session. Only a tunnel the proxy
accepted carries a session, so a CONNECT answered with `407` leaves nothing
to join.

## Browser recipes

| Recipe | Pooled capable H2 session | No H2 session | Session without the setting | Pooled session on a proxy route |
| --- | --- | --- | --- | --- |
| `chromium::v154_websocket` (Chrome 154, Edge 154, Brave 154, Opera 136, and Chrome 154 and Brave 153 for Android) | Extended CONNECT on it | New TLS connection offering only `http/1.1`; H1 Upgrade | Same as no session | Extended CONNECT on it, inside its tunnel (`Reuse`) |
| `firefox::v157_websocket` | Extended CONNECT on it | New connection offering `h2,http/1.1`; extended CONNECT | New TLS connection offering only `http/1.1`; H1 Upgrade | Extended CONNECT on it, inside its tunnel (`Reuse`) |

| Recipe | Refused CONNECT stream | Empty message with deflate | Handshake timeout |
| --- | --- | --- | --- |
| `chromium::v154_websocket` | Reopen once on the same session | Compressed, RSV1 set | 240 seconds |
| `firefox::v157_websocket` | Reported to the caller | Uncompressed, RSV1 clear | 20 seconds |

Both recipes reuse capable H2 sessions on proxy routes. This policy and
the handshake timers are source-defined; tunnelled `wss://` openings remain
uncaptured.

`WebSocketSettings::handshake_timeout` limits the whole opening. You can
replace it for one connection with
`WebSocketRequestBuilder::handshake_timeout`. Neither recipe sets a
`WebSocketRetryPolicy`.

The paired H2 recipes set the extended-CONNECT pseudo-header order and a
separate `extended_connect_priority`:

| H2 recipe | CONNECT priority | Ordinary request priority |
| --- | --- | --- |
| `chromium::v154_http2` | Exclusive on stream 0, weight 147 | Weight 256 |
| `firefox::v157_http2` | Non-exclusive on stream 0, weight 22 | Weight 42 |

The H1 and H2 templates set header order, spelling, and fixed values.
`User-Agent`, `Origin`, `Accept-Language`, and, for Firefox on H2,
`sec-fetch-storage-access` are caller slots. Some fields depend on whether the
WebSocket URL is [potentially
trustworthy](glossary.md#potentially-trustworthy): `wss://`, or `ws://` to a
loopback address, `localhost`, or a `.localhost` name.

| Field | Recipe | Trustworthy URL | Other `ws://` URL |
| --- | --- | --- | --- |
| `Accept-Encoding` | Both | `gzip, deflate, br, zstd` | `gzip, deflate` |
| `Sec-Fetch-Dest` | Firefox | `empty` | Not sent |
| `Sec-Fetch-Mode` | Firefox | `websocket` | Not sent |
| `Sec-Fetch-Site` | Firefox | `same-origin` | Not sent |

A field added with `WebSocketRequestBuilder::header` under one of these names
replaces the recipe's value in its position, for either kind of URL. Set
`Sec-Fetch-Site: cross-site` for a socket that a page on another site opens.
A WebSocket follows no redirect, so the opening URL alone decides. The
other fields keep their order for both kinds of URL.

Each paired H2 recipe sets its HPACK header compression choices in
`Http2Settings::hpack`:

| H2 recipe | Kept out of the dynamic table | Repeated static name | Huffman-codes a literal |
| --- | --- | --- | --- |
| `chromium::v154_http2` | `:method` and `:protocol` | Lower entry: `:method` 2, `:path` 4 | Only when that shortens it, so `CONNECT` and `13` go raw |
| `firefox::v157_http2` | None; both are indexed incrementally | Higher entry: `:method` 3, `:path` 5 | Always |

An HPACK encoder keeps these choices for the whole connection, so they apply
to ordinary requests on it too.

### Differences from the captures

The recipes differ in these ways:

- Firefox's stream `WINDOW_UPDATE` after CONNECT HEADERS, and the second H2
  connection it opens and closes when reusing a session, which on a proxy
  route would also mean a second tunnel.
- Chrome's `RST_STREAM(CANCEL)` after a rejection or an unoffered extension.
- Chrome's variable fragmentation of large uncompressed messages, and its
  compression offer on every opening (Phantom offers only when enabled).
- The `Cookie` field position, which no capture shows.

## Compression

The `websocket-deflate` feature enables RFC 7692 `permessage-deflate`.
Opt in for each connection with
`WebSocketRequestBuilder::permessage_deflate`.

| Setting | Default | Method |
| --- | --- | --- |
| Offer | `permessage-deflate; client_max_window_bits` | `offer_parameters` (any RFC-valid ordered combination, including no parameters and a bare or valued `client_max_window_bits`) |
| Server context takeover | Allowed | `server_no_context_takeover` |
| Client context takeover | Allowed | `client_no_context_takeover` |
| Server window | Not offered | `server_max_window_bits` (8 to 15) |
| Local encoder window cap | 15 bits; the offer is unchanged | `client_max_window_bits` (8 to 15) |
| Compression level | 6 | `compression_level` (0 to 9) |
| Empty messages | Compressed, RSV1 set | `compress_empty_messages`, or `WebSocketSettings::empty_message_compression` through `PerMessageDeflate::from_profile` |

- Duplicate parameters and invalid window widths fail before I/O.
- `WebSocket::negotiated_permessage_deflate` returns what the server
  selected.
- After negotiation every text and binary message is compressed. Ping, Pong,
  and Close frames never are.
- An uncompressed empty message is sent with RSV1 clear and an empty payload.
  Non-empty messages are compressed either way, so the encoder history is
  never skipped.
- If the two sides' compression state diverges, the connection ends rather
  than decoding later frames with a mismatched dictionary.
- Tracing records uncompressed byte counts, never payload contents.

## Next

- [WebSocket guide](../guides/websocket.md): open and shape a WebSocket;
  [compression](../guides/websocket-fields.md#compress-websocket-messages) has
  its own guide.
- [WebSocket browser evidence](../explanation/validation.md#websocket-browser-evidence):
  the captures behind the recipes.
- [Design](../explanation/design.md#websocket-and-sse): why the connection
  choice never falls back.
