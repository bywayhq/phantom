# HTTP/3 internals

Change one layer of Phantom's HTTP/3 path and keep the contracts of the
others. Each section says how its layer is built, bounded, and proven.

> For contributors working on QUIC, HTTP/3, QPACK, CONNECT-UDP, or the H3
> capture fixtures. To use HTTP/3 from an application, read
> [HTTP/3 and Alt-Svc](../guides/http3.md) instead.

Contents:

- [Stack boundary](#stack-boundary) and [profile components](#profile-components)
- On a connection: [QPACK ownership](#qpack-ownership),
  [request streams](#request-streams), [extended CONNECT](#extended-connect)
- Routes: [SOCKS5](#socks5-routes) and [CONNECT-UDP](#connect-udp-masque)
- Across connections: [pooling and Alt-Svc](#pooling-and-alt-svc),
  [setup retries](#setup-retries)
- Proof and tooling: [diagnostics](#diagnostics),
  [capture workflow](#capture-workflow), [vendored seams](#vendored-seams),
  [current limits](#current-limits)

Terms: H3, H2, and H1 are HTTP/3, HTTP/2, and HTTP/1.1. QUIC (RFC 9000) is the
UDP transport under HTTP/3. QPACK (RFC 9204) is HTTP/3 field compression; its
dynamic table is state that encoder and decoder keep in sync over two
dedicated streams. An [exact](../reference/glossary.md#exact-protocol) H3
request must use HTTP/3 and never falls back. A
[negotiated](../reference/glossary.md#negotiated-protocol) request starts over
TCP and lets ALPN pick H1 or H2; later requests to the origin can use H3
through [Alt-Svc](../reference/glossary.md#alt-svc).

## Stack boundary

Phantom's H3 path is a dedicated TLS 1.3 profile, Quinn for QUIC transport,
the private `phantom-quic-btls` crypto provider, and Hyperium's `h3` engine,
under Phantom-owned policy for connections, requests, QPACK, cancellation, and
diagnostics. The public API exposes Phantom types, never Quinn, BoringSSL, or
`h3` types. H3 does not go through a generic TCP transport abstraction, and it
never falls back to H2 or H1. Each route supplies its own UDP transport, and
every transport below Quinn is Phantom-owned except the direct socket.

```text
 phantom-http facade: Client, Route, H3 pool, Alt-Svc store, retries
   |
 phantom-net http3: Http3Connector, connection driver, request streams,
   |                QPACK policy, route UDP sockets
   |
 phantom-h3, phantom-h3-quinn, phantom-h3-datagram   (vendored h3)
   |
 phantom-quinn, phantom-quinn-proto (QUIC)  +  phantom-quic-btls (TLS 1.3)
   |
 UDP transport, chosen by the route:
   +-- direct:       Quinn's UDP socket
   +-- SOCKS5:       RFC 1928 UDP ASSOCIATE adapter; holds the TCP control
   |                 connection open for the association's lifetime
   +-- CONNECT-UDP:  socket carrying the inner QUIC connection over an
                     outer proxy connection
                       +-- H3 leg:        HTTP Datagrams (QUIC DATAGRAM frames)
                       +-- H2 or H1 leg:  DATAGRAM capsules on one TCP stream
```

## Profile components

The Chrome H3 recipe keeps four concerns separate:

1. the H3 ClientHello and the exact `h3` ALPN;
2. QUIC transport parameters, with their order, encoded widths, and GREASE
   policy;
3. local HTTP/3 SETTINGS and their order;
4. request pseudo-header order and QPACK policy.

Profiles apply captured values to live transport state. A value or
combination that Phantom cannot apply fails validation; it is never accepted
and ignored.

## QPACK ownership

The connection driver owns the QPACK encoder and decoder streams.

Receive-side dynamic state is bounded by the advertised table capacity,
blocked-stream limits, field-section limits, and decoder feedback. The decoded
field-section limit is the lower of the profile's advertised
`SETTINGS_MAX_FIELD_SECTION_SIZE` and a local 256 KiB ceiling.
`settings::builder` applies the ceiling after building the ordered SETTINGS
list, and the vendored `h3` builder emits that list unchanged, so the ceiling
never appears on the wire.

Before encoding a request, Phantom waits for the peer's SETTINGS, or on an
early-data connection uses the
[SETTINGS remembered with the ticket](#remembered-settings), and applies
bounded admission. It sends encoder instructions before the HEADERS frame that
depends on them. Request trailers, static or produced by a declared streaming
body, use the same ordered, connection-owned QPACK path as request headers.

The built-in Chrome profile reproduces the retained encoder and HEADERS bytes
of Chrome's first request. A profile that does not opt into dynamic encoding
stays stateless.

`Http3Settings::qpack_stream_order` and `qpack_encoder_stream` decide which
client stream each QPACK stream gets and when the encoder stream appears on
the wire. The Chrome recipe opens the decoder stream before the encoder
stream, so they are client streams 6 and 10, and holds the encoder stream's
type, with any instruction queued before the first request, such as the
table capacity, until that request's field section needs instructions. The
vendored `h3` builder applies both through `qpack_decoder_stream_first` and
`defer_qpack_encoder_stream`.

## Request streams

The one-shot `phantom_net::http3::send_request*` functions take
`Http3RequestSettings` with ordered `RequestHeader` input. They share
preparation with pooled requests, so their pseudo-header and field order
always come from the profile.

A final response may arrive before the request body has been sent. The upload
then continues alongside the response body (RFC 9114 section 4.1).

- A complete response resets an unfinished upload with
  `H3_REQUEST_CANCELLED`.
- A peer `STOP_SENDING` ends only the upload.
- A request-body failure after the response head fails the response body.
- A request accepts at most 8 informational responses. The ninth fails the
  request with a protocol error.
- An HTTP Datagram on an ordinary request is a protocol error until a public
  extension-specific API owns it.
- Datagrams for request streams the client has already closed are dropped
  silently (RFC 9297 section 2.1).

## Extended CONNECT

Extended CONNECT (RFC 9220) turns an HTTP/3 request stream into a tunnel for
another protocol. `phantom-net` can open these streams on a connection opened
by the same `Http3Connector`. `Http3ExtendedProtocol::WebSocket` is the only
protocol today, and the `phantom-http` facade does not expose it yet.

Request:

- The request is `CONNECT` with `:protocol`, `:scheme https`, `:authority`,
  and `:path`, in the order of the profile's
  `Http3RequestSettings::extended_connect_pseudo_header_order`. One order
  applies to every extended protocol.
- A profile without that order fails with a configuration error before I/O.
  Named browser recipes leave it unset until a capture backs it.
- Ordered fields follow the ordinary HTTP/3 request rules. `content-length` is
  rejected, because the tunnel has no request content.

Peer capability, from the peer's SETTINGS in ALPS or on the control stream:

- Without `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`, the request returns
  `Http3ErrorKind::ExtendedConnectUnavailable`. It opens no request stream and
  tries no other protocol.
- A control-stream value of 0 after an ALPS value of 1 closes the connection
  with `H3_SETTINGS_ERROR` (RFC 8441 section 3).
- The client sends no `SETTINGS_ENABLE_CONNECT_PROTOCOL` of its own, so its
  SETTINGS bytes do not change.

Response and stream:

- A 2xx response yields `Http3ExtendedConnectStream`: an `AsyncRead` and
  `AsyncWrite` byte stream over DATA frames. It buffers at most one received
  chunk and one queued frame.
- Shutdown sends FIN. Peer trailers are `InvalidData`.
- Dropping an incomplete stream resets only that stream with
  `H3_REQUEST_CANCELLED` (RFC 9220 section 3).
- The stream holds a connection lease, so the connection driver stays alive
  while the stream is open.
- A non-2xx final response is returned with its ordered fields and a readable
  body. A 101 is a protocol error. Informational responses are skipped.
- An HTTP Datagram associated with the stream aborts only that stream with
  `H3_DATAGRAM_ERROR` (RFC 9297 section 2).

The `http3.extended_connect.response_head` span records method, protocol,
extended protocol, status, and one outcome: `accepted`, `rejected`,
`capability_unavailable`, `protocol_error`, or `request_error`. Field values
are not recorded.

## SOCKS5 routes

Exact H3 accepts local-DNS `socks5://` and remote-DNS `socks5h://` routes.
The local-DNS path resolves the origin locally and fixes one IP target. The
remote-DNS path performs no local origin lookup, and sends the canonical
hostname in each RFC 1928 UDP request. Both establish a UDP ASSOCIATE,
optionally authenticated with RFC 1929, and keep the TCP control connection
open for the association's lifetime.

The relay address the proxy returns:

- a concrete address is used directly;
- an unspecified address is replaced with the established TCP proxy peer's
  IP, keeping the returned nonzero port;
- a domain address or a zero port is rejected.

The adapter rejects fragmented, malformed, wrong-target, and non-relay
datagrams. For remote DNS, it accepts replies from the exact domain or from an
IP on the same port, and maps accepted replies to one stable logical peer for
Quinn.

The complete route is part of pool identity, so compatible requests can reuse
the H3 connection and its association. Authentication, negotiation, and
rejection failures are typed and never trigger a fallback to another address.
Proxy TCP and QUIC setup can retry only through a fresh association on the
same configured route, under the exact-H3 setup policy. No failure can change
the route or protocol.

## CONNECT-UDP (MASQUE)

CONNECT-UDP (RFC 9298, part of the MASQUE work) lets a proxy relay UDP.
Phantom uses it to carry an exact-H3 connection to the origin (the inner
connection) through a connection to the proxy (the outer connection, or proxy
leg).

`Route::connect_udp` selects it. The proxy leg uses HTTP/3 by default.
`ConnectUdpProxy::with_http2_transport` selects HTTP/2 extended CONNECT, and
`with_http1_transport` selects HTTP/1.1 Upgrade. `phantom-net` exposes the
same paths as `Http3Connector::connect_connect_udp`,
`connect_connect_udp_with_basic_auth`, and `connect_connect_udp_over_tcp`.

No leg ever falls back to another leg, route, or protocol.

### Proxy template

`ConnectUdpProxy::new` takes an `https` URI template with `{target_host}` and
`{target_port}` in its path or query.

- Accepted expressions: simple (`{var}`) and form-style query (`{?var}`,
  `{&var}`).
- Rejected before I/O (RFC 9298 section 2): reserved, fragment, label, path-segment, and
  path-style operators; value modifiers; other variables; user information;
  fragments; non-ASCII characters; and spaces.
- The proxy authority is canonicalized.
- Values are percent-encoded outside the RFC 3986 `unreserved` set, so an
  IPv6 target is sent as `2001%3Adb8%3A%3A42` (RFC 9298 section 3).
- The target is always sent as text. Phantom performs no local lookup of the
  target.

The template scheme must be `https` on every leg; `http://` fails with
`ConnectUdpProxyConfigErrorKind::UnsupportedScheme`. RFC 9298 is looser:
section 2 requires only a non-empty scheme, and section 3.2 would permit
HTTP/1.1 over cleartext. Phantom requires `https` because:

- the HTTP/2 and HTTP/3 requests carry the template's scheme in `:scheme`
  (section 3.4), and Phantom does not speak cleartext HTTP/2;
- one template must name the same TLS-authenticated proxy whichever leg is
  selected;
- a plaintext proxy would expose Basic credentials.

### Connections and pooling

- Each inner connection gets a fresh outer connection to the proxy.
- The outer connection uses the client's proxy trust roots and the proxy host
  as SNI. The inner connection keeps the origin's trust roots, SNI, and
  authority.
- Disabled proxy certificate verification is rejected for this route on
  every leg.
- The leg and any credentials are part of `ConnectUdpProxy` equality, so they
  separate pool entries.

### HTTP/3 leg

Capability checks happen before a request stream opens. The proxy's SETTINGS
must carry `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (RFC 9220 section 3) and
`SETTINGS_H3_DATAGRAM = 1`, and its QUIC transport parameters must carry
`max_datagram_frame_size` (RFC 9297 section 2.1.1; RFC 9221 section 3).
Otherwise the request fails with
`ConnectUdpErrorKind::ExtendedConnectUnavailable` or `DatagramUnavailable`,
without origin I/O.

The request is extended CONNECT with `:protocol connect-udp`, the proxy
authority, and the expanded path, in the profile's extended CONNECT
pseudo-header order. A generated `capsule-protocol: ?1` field comes before the
route's ordered fields (RFC 9297 section 3.4; RFC 9298 section 3.4). A caller
`capsule-protocol` or `content-length` field is rejected before I/O.

Only a 2xx final response opens the tunnel.

- A 2xx is malformed if it is 204, 205, or 206, or if it carries
  `content-length`, `content-type`, or `transfer-encoding` (RFC 9297
  section 3.2).
- Any other final status aborts the request and returns
  `ConnectUdpErrorKind::Rejected`, with the status in
  `ConnectUdpError::status`.
- Phantom never sends datagrams before the response, although RFC 9298
  section 5 permits it.

UDP payloads travel with Context ID 0 in QUIC DATAGRAM frames.

- Received datagrams go to a per-stream queue of at most 256 payloads.
- Queue overflow, unknown or undecodable Context IDs, and datagrams that
  arrive before the stream is registered are dropped and counted (RFC 9297
  section 2.1; RFC 9298 sections 4 and 5).
- A Context ID 0 payload above 65,527 bytes aborts the stream with
  `H3_DATAGRAM_ERROR`.
- DATAGRAM capsules on the request stream feed the same queue. Unknown
  capsules are skipped without buffering (RFC 9297 section 3.2).
- A DATAGRAM capsule above 65,535 bytes, or a truncated final capsule, aborts
  the stream.
- The proxy's FIN or reset ends the tunnel.
- The HTTP/3 leg never sends DATAGRAM capsules.

### HTTP/2 and HTTP/1.1 legs

Each inner connection opens one dedicated TCP and TLS connection to the proxy
with the client profile's TLS offer, which must include `http/1.1`. The
HTTP/2 leg requires the proxy to select `h2`; the HTTP/1.1 leg requires
`http/1.1` or no ALPN. Any other selection fails with
`ConnectUdpErrorKind::UnsupportedProtocol`.

The HTTP/2 leg sends RFC 9298 section 3.4 extended CONNECT:

- `:protocol connect-udp`, `:scheme https`, the proxy authority, and the
  expanded path, in the HTTP/2 profile's extended CONNECT pseudo-header order,
  then `capsule-protocol: ?1` and the route's fields;
- a profile without that order fails with `Configuration` before I/O;
- HEADERS are sent only after the proxy's SETTINGS carry
  `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (RFC 8441 section 3). Otherwise the
  request fails with `ExtendedConnectUnavailable`;
- only a 2xx response that can start the Capsule Protocol opens the tunnel
  (RFC 9298 section 3.5; RFC 9297 section 3.2).

The HTTP/1.1 leg sends an RFC 9298 section 3.2 `GET`:

- origin form, with `Host`, `Connection: Upgrade`, `Upgrade: connect-udp`, and
  `Capsule-Protocol: ?1`, then the route's fields in their supplied spelling;
- only a 101 with `Connection` containing `upgrade`, exactly one
  `Upgrade: connect-udp`, and no `content-length`, `content-type`, or
  `transfer-encoding` opens the tunnel (RFC 9298 section 3.3);
- a 2xx or a malformed 101 fails with `Protocol`, and any other final status
  is `Rejected`;
- up to eight other 1xx responses are skipped;
- bytes after the 101 head start the capsule stream (RFC 9297 section 3.2).

On both legs, route fields named `Host`, `Connection`, `Upgrade`,
`Capsule-Protocol`, `Content-Length`, or `Transfer-Encoding` are rejected
before I/O. The HTTP/2 leg also rejects connection-specific fields.

Both directions carry DATAGRAM capsules (RFC 9297 section 3.5), each holding
Context ID 0 followed by the UDP payload.

- Received capsules share the HTTP/3 leg's 256-payload queue and drop rules.
  Unknown capsules are skipped.
- These close the stream and end the tunnel: a Context ID 0 payload above
  65,527 bytes, a capsule above 65,535 bytes, a truncated capsule, a read or
  write failure, or the proxy's FIN.
- At most 256 encoded capsules wait for the proxy stream. Later sends are
  dropped and counted, and QUIC recovers them.

### Proxy authentication

`ConnectUdpProxy::with_basic_auth` enables challenge-driven HTTP Basic proxy
authentication on every leg. It validates credentials the same way as
`HttpProxy::with_basic_auth`.

1. The first request omits credentials.
2. A 407 with a valid Basic challenge is retried exactly once, on a fresh
   proxy connection. `Proxy-Authorization` follows the route's fields; HTTP/2
   and HTTP/3 encode it as a never-indexed literal.
3. A second 407 fails with `ConnectUdpErrorKind::Authentication` and status
   407.

A malformed or non-Basic challenge also fails with `Authentication`. Without
credentials, a 407 is an ordinary `Rejected` status. With credentials
configured, a literal `Proxy-Authorization` route field is rejected before
I/O.
Credentials never appear in `Debug` output, errors, or diagnostics.

### Datagram capacity

A full inner client Initial packet is 1200 bytes (RFC 9000 section 14.1). On
the HTTP/3 leg's first request stream, the HTTP Datagram adds a one-byte
Quarter Stream ID and a one-byte Context ID, for 1202 bytes. Quinn reserves a
conservative 50 bytes of 1-RTT packet overhead for each DATAGRAM frame:

| Part | Bytes |
| --- | --- |
| Flags | 1 |
| Connection ID | 20 |
| Packet number | 4 |
| AEAD tag | 16 |
| Frame type and length bound | 9 |

The outer connection therefore uses a fixed initial and minimum path MTU of
1252 bytes, and never probes below it. Before I/O, the HTTP/3 leg's outer
profile must:

- send `SETTINGS_H3_DATAGRAM = 1`;
- advertise a `max_datagram_frame_size` of at least 1205 bytes (a 1-byte frame
  type, a 2-byte length, and the 1202-byte datagram);
- advertise a `max_udp_payload_size` of at least 1252 bytes.

Otherwise the request fails with `ConnectUdpErrorKind::Configuration`. After a
2xx response, if the proxy's datagram limit cannot carry 1202 bytes on the
tunnel's stream, the tunnel closes with
`ConnectUdpErrorKind::DatagramCapacity`. Paths that cannot carry 1252-byte UDP
payloads, including IPv6 minimum-MTU links, lose full-size inner packets; the
HTTP/3 leg never switches to DATAGRAM capsules.

The HTTP/2 and HTTP/1.1 legs have no outer datagram limit. A capsule carries
any payload up to the 65,527-byte Context ID 0 bound, and the inner connection
uses its own profile's MTU settings. These legs carry QUIC over TCP, so loss
recovery is nested (RFC 9298 section 6). Prefer the HTTP/3 leg when the proxy
supports it.

### CONNECT-UDP diagnostics

The `proxy.connect_udp` span records:

- `proxy_protocol` and `proxy_leg` (`h3`, `h2`, or `http/1.1`);
- each response `status`;
- `authentication_retry` and `proxy_attempts`, when credentials are
  configured;
- `outcome` (`accepted`, `rejected`, or `error`) and `error_kind`;
- when the tunnel ends, the drop counters `dropped_unknown_context`,
  `dropped_overflow`, `dropped_early`, `dropped_malformed`,
  `dropped_oversized`, and `dropped_send`.

Paths, field values, credentials, and payloads are not recorded.

Quinn sees one fixed logical peer, `192.0.2.1:443`. As with `quinn-udp`, the
only send error that can reach Quinn is `WouldBlock`; oversized or
undeliverable datagrams are dropped and counted. The socket holds the outer
connection or proxy stream. When that ends, the socket reports a receive
error, the inner endpoint stops, and the pool opens a fresh outer connection
for the next request.

### Failures and retries

CONNECT-UDP setup failures are `Http3ConnectorErrorKind::Proxy` errors whose
source is a `ConnectUdpError`. The facade reports them as
`RequestErrorKind::Proxy`, or as `Resolve` and `RuntimeUnavailable` for those
kinds.

Only two kinds of failure consume the exact-H3 setup retry budget: outer proxy
resolution, and outer QUIC or TCP connection failures. Each retry opens a
fresh outer connection and CONNECT-UDP request on the same route and leg.
Handshake, ALPN, SETTINGS, datagram, authentication, rejection, protocol, and
inner QUIC failures are terminal. No failure falls back to a direct
connection. CONNECT-UDP never learns or evicts Alt-Svc state.

The route is limited to exact H3. HTTP/1.1, HTTP/2, negotiated requests, and
WebSocket reject it with `UnsupportedRoute` before I/O. Still planned:
multiplexing several tunnels on one outer connection, proxy authentication
schemes other than Basic, and capture evidence for a browser's MASQUE
fingerprint.

## Pooling and Alt-Svc

Negotiated direct HTTPS requests can opt into a bounded Alt-Svc store. The
store learns from response fields and exact-origin H2 ALTSVC frames. A later
request can then use a fresh canonical `h3` alternative. Callers may export
and re-import that direct-route state; Phantom never persists it, or QUIC
tickets, itself.

An alternative changes where QUIC dials. The origin authority and certificate
identity stay the same. By default, a failed alternative setup is terminal and
evicts the advertisement, with no H1 or H2 fallback. An opt-in racing policy
instead races the alternative's setup against a delayed origin setup, and
marks a failed alternative broken; see
[Racing](../guides/http3-discovery.md#race-the-alternative-against-the-origin).

One pool entry per origin and route keeps connections for up to four
transport locations, so alternating exact-H3 and Alt-Svc H3 requests reuse
their own connections under the same admission bounds. Setup is serialized
per transport location, not per entry, and the slot table is never locked
across an await, so a slow setup to one location does not delay another.

Each location keeps one connection unless
`ClientBuilder::max_http3_connections_per_origin` allows more
(`session/http3_connections.rs`). With one, a request uses the location's
reusable connection or takes the connect turn; the pool computes no stream
room and wakes no waiter when a stream ends.

With more, the pool counts each request's stream from its lease until the
response body ends. It reads the server's `initial_max_streams_bidi` from
`Http3Connection::peer_initial_max_streams_bidi` once the handshake
completes, counts an absent or zero value as one stream, and does not track
the `MAX_STREAMS` credit the server grants later. A connection still waiting
for its early-data answer uses the limit another connection to the same
location reported. A request takes the least-loaded connection with room,
and only when none has room, and the location is below its limit, does it
take the location's connect turn. It chooses again once it holds the turn,
so requests queued behind a setup share the new connection.

While a request waits for the turn, a stream that ends on any of the entry's
connections wakes it to choose again. One `Notify` serves the whole entry,
so every waiter of every location wakes and rechecks under the slot lock; a
waiter keeps its pending turn, and so its place in the turn's first-in,
first-out queue, across those wakeups. A connection that is no longer
reusable, such as one draining after GOAWAY, leaves the slot table and stops
counting. The table holds at most four locations' worth of connections, and
evicts the least recently used beyond that.

### Session tickets

When the H3 TLS settings enable `session_tickets`, as the Chrome 154 and Edge
153 recipes do, the pool keeps the TLS 1.3 tickets a server issues and
presents one on the next QUIC connection to the same origin over the same
route. A resumed ClientHello adds the `pre_shared_key` extension, last, to
the recipe's offer, and `early_data` when the connection offers early data. A
TLS 1.3-only ClientHello carries no `session_ticket` extension, so the first
ClientHello of a connection is unchanged.

The H3 connector builds its TLS context through a hook that installs the QUIC
adapter's ticket delivery instead of the scoped-session callback used for TCP.
The key-log callback is installed on the same context, so key logging covers
resumed connections too. Tickets follow the same isolation as TLS tickets on
TCP:

- Each pool entry, meaning one origin and one route, derives its own
  connector through `Http3Connector::with_isolated_session_cache`, with its
  own ticket cache. A ticket learned directly is never presented through a
  proxy, and a ticket learned through one proxy is never presented directly
  or through another. The outer connection to a CONNECT-UDP proxy has a
  separate cache in the same entry. Separately built clients share nothing.
- A ticket is stored only after its connection authenticated the server, and
  is presented only for that verified server name.
- Each cache holds at most four tickets and evicts the least recently stored,
  so a client's total is bounded by its H3 pool capacity. Evicting a ticket
  only costs a full handshake later.
- Tickets are single-use, as BoringSSL marks every TLS 1.3 session, and
  expire at the server's ticket lifetime. An expired ticket is dropped and the
  connection makes a full handshake without error.
- If a handshake that presented a ticket fails, the entry repeats the attempt
  once with a full handshake over the same route and protocol, through
  `Http3Connector::without_ticket_offers`.

Whether a resumed connection offers early (0-RTT) data is profile data:
`QuicTransportSettings::early_data`, which `chromium::v154_quic` sets.
`QuicClientConfig::with_transport_profile` reads it, and `with_tls_profile`
clears it when the TLS settings disable `session_tickets`, since such a
connection never resumes. `ClientBuilder::http3_early_data(bool)` overrides it
through `Http3Connector::with_early_data` or `without_early_data`. The pool
keeps an origin connector without early data and, when the client offers
early data, an early-data twin that shares its ticket cache. A request's
first connection attempt uses the twin.

A new connection from the twin that presents a ticket permitting early data is
returned before its handshake completes, and the pool stores it at once, so
later requests to the same transport location share it instead of opening
their own. Every request on such a connection follows one rule
(`sends_before_handshake` in `crates/phantom/src/session/http3_pool.rs`):

- A replay-safe request (a safe method, no body, and no trailers) goes out
  as early data while the early data is unanswered, with the client hints
  known before the handshake. Under a dynamic QPACK policy it is encoded
  with the SETTINGS remembered with the ticket; see
  [Remembered SETTINGS](#remembered-settings). A connection that started
  without them holds such a request until the server's SETTINGS arrive, with
  the server's first flight.
- Every other request waits in the pool, within the connect timeout phase,
  for `Http3Connector::early_data_settled_on`, and keeps its body until
  then. It is then sent with the client hints the handshake's ALPS
  delivered.
- If the server accepted, the request is sent on the connection.
- If the server rejected the early data, Quinn has discarded every stream
  opened before the handshake (RFC 9001, section 4.6.2). The connection
  starts HTTP/3 again on the same QUIC connection, and stays pooled; see
  [Rejected early data](#rejected-early-data). A replay-safe request that
  went out early fails inside the pool as unprocessed
  (`Http3Unprocessed::EarlyDataRejected`) and is sent again on the
  connection, and the waiting requests are sent on it for the first time.
- If the handshake failed or its metadata was invalid, the connection is
  invalidated and every waiting request fails with that error; none is sent
  again, and no second connection is opened.
- If the connect timeout expires first, that request fails with a
  connect-phase timeout and the connection stays pooled for the others.

#### Remembered SETTINGS

A connection that offers early data starts from the server SETTINGS
remembered with its ticket, as RFC 9114 section 7.2.4.2 allows and Chromium
does; [QUIC resumption evidence](../explanation/validation.md#quic-resumption-and-0-rtt-evidence)
cites the Chromium source.

- `phantom-quic-btls` stores opaque application state with each ticket
  through a per-connection `ApplicationState`, which
  `QuicClientConfig::with_application_state` attaches. `connect` in
  `crates/phantom-net/src/http3/mod.rs` gives every connection from a
  connector that keeps tickets its own handle.
- The state is the SETTINGS frame from the server's control stream, as the
  HTTP/3 driver applied it, from the vendored
  `h3::client::Connection::peer_settings_to_remember`. It holds only the
  settings `h3` understands, so it stays under 150 bytes; the cache refuses
  state over 1 KiB.
- Tickets that arrive before those SETTINGS are held, at most two per
  connection, and stored once the driver records the SETTINGS. A connection
  that closes first, or whose SETTINGS fail validation, stores none of its
  tickets.
- The state lives in the ticket's cache entry, so it has the ticket's
  isolation and bounds: one cache per origin and route, at most four
  tickets, read back only for the same verified server name, and consumed
  with the ticket.
- A connection offers early data only with a ticket that carries state.
  `h3::client::Builder::remembered_peer_settings` then seeds the peer view
  and the QPACK encoder's table capacity and blocked-stream limit before the
  connection starts, so the encoder-stream instructions and the request
  HEADERS both go out in 0-RTT packets. The remembered SETTINGS stand in for
  the control stream's SETTINGS only as values: a control stream whose first
  frame is not SETTINGS is still an error.
- The server's SETTINGS, from ALPS or the control stream, must repeat a
  remembered nonzero QPACK table capacity (RFC 9204, section 3.2.3) and must
  not omit or lower a remembered blocked-stream, field-section, or
  WebTransport session limit, or disable a remembered extended CONNECT,
  HTTP Datagram, or WebTransport setting. Otherwise the driver closes the
  connection with `H3_SETTINGS_ERROR`, the code Chromium sends. For a
  changed or omitted QPACK table capacity, RFC 9204 section 3.2.3 names
  `QPACK_DECODER_STREAM_ERROR` instead; Phantom follows quiche, which uses
  `H3_SETTINGS_ERROR` for every remembered setting.
- State stored with a ticket that does not decode as SETTINGS closes the
  connection with `H3_INTERNAL_ERROR` and fails the request with a protocol
  error. It is not a handshake failure, so the pool does not repeat the
  attempt with a full handshake.
- If the server rejects the early data, the HTTP/3 session that started
  from the remembered SETTINGS is discarded with them, and the session that
  replaces it starts from nothing remembered.

#### Rejected early data

Chromium resends on the connection whose early data was rejected, and the
captures show the same stream numbers again in 1-RTT packets; see
[QUIC resumption evidence](../explanation/validation.md#quic-resumption-and-0-rtt-evidence).
Quinn cannot resend discarded streams, so Phantom starts a second HTTP/3
session on the connection instead.

- The connection driver checks the server's answer before each poll of
  HTTP/3. Quinn settles the answer and discards the streams in one step
  under its connection lock, so the driver never polls the discarded
  session, whose critical-stream errors would otherwise close the QUIC
  connection.
- `restart_after_rejected_early_data` in
  `crates/phantom-net/src/http3/mod.rs` checks the handshake metadata as a
  connection without early data does (the `h3` ALPN, the ALPS `ACCEPT_CH`
  entries, and the ALPS SETTINGS), builds a new session from the same
  profile, hands its driver to the connection's driver task, and swaps the
  connection's sender before it publishes the answer. The new session opens
  its control stream as client stream 2 and its QPACK streams as 6 and 10
  again.
- The new session starts without the remembered SETTINGS, so under dynamic
  QPACK it waits for the server's SETTINGS, which usually arrive with the
  handshake's last flight. Chromium keeps the remembered values after a
  rejection, retransmits the same encoder-stream bytes, and closes the
  connection with the transport error `INTERNAL_ERROR` if the server's new
  SETTINGS lower a remembered limit (quiche
  `http/quic_spdy_session.cc`, lines 1224-1289, and
  `quic_error_codes.cc`, lines 710-711). Phantom uses the server's new
  SETTINGS instead and does not close; Quinn offers no way to send that
  transport close.
- The early session opens request streams through `early_streams::Opener`
  in `crates/phantom-net/src/http3/early_streams.rs`. It opens a stream
  while the TLS handshake is running, when Quinn marks it a 0-RTT stream,
  and after the published answer is an acceptance, which follows the
  handshake metadata checks and the late ALPS SETTINGS. It refuses as soon
  as the connection driver has Quinn's rejection, without waiting for the
  published answer: a request waiting here holds the send lock, which the
  restart needs before it publishes. A request waiting for stream credit
  registers on both answers each time it waits, so an answer that arrives
  between two polls wakes it. After a rejection the opener fails without
  allocating a stream, so no request of the discarded session reaches the
  server in 1-RTT.
- A stream whose open raced the handshake's completion is held until the
  answer and reset, unused, if the early data was rejected or the request
  is dropped. The server then sees a reset of an empty stream, and that
  stream's number stays used: the new session's first request stream is the
  next one. Otherwise the new session numbers its request streams from 0.
- A request that takes the sender in that interval also waits for the
  answer first, and then uses the new session. `send_prepared_request`
  reports only a request that took the sender before the answer as
  unprocessed.
- Quinn discards the early streams and settles its answer in one step,
  under the connection's lock, but on its own task. On a multi-threaded
  runtime that step can land between any check of the answer and the next
  use of the connection, so the early session reads the answer again after
  each use that depends on it (`EarlySession` in `early_streams`).
- The handshake can complete while the early session is still starting.
  Once the handshake data is in, the session reads Quinn's answer before it
  opens another control or QPACK stream. After an acceptance the open goes
  ahead as a 1-RTT stream, and the session keeps client streams 2, 6, and
  10. After a rejection the open fails, so no 1-RTT stream takes a number,
  and the session's writes on its 0-RTT streams fail too. A close the
  session asks for after the handshake goes to `connect`: on a rejection it
  starts HTTP/3 on the connection with the metadata checks every session
  applies, opens its streams as client streams 2, 6, and 10, and publishes
  the rejection, so `sent_early_data` is true and `early_data_accepted` is
  `Some(false)`. On any other failure `connect` closes with the code the
  session chose.
- A rejection can land after the session decided to open a stream as a
  0-RTT one and before it opens it. The session reads the answer again
  after the open: a pending answer means the stream is a 0-RTT one. After a
  rejection, Quinn reports the rejection on a 0-RTT stream, and any other
  stream is a live 1-RTT stream on client stream 2. That stream is handed to
  the session that starts after the rejection, as its control stream.
  Every session still checks that its critical streams take client streams
  2, 6, and 10, and one that does not fails to start; the connection is
  closed with `H3_INTERNAL_ERROR` rather than started on other stream
  numbers.
- After the start, the driver can poll the early session after Quinn
  discarded its streams and before the driver read the answer. The session
  then fails and asks to close the connection. That close is held until the
  driver reads the answer, which it does again whenever the session ends:
  on a rejection the close is dropped and HTTP/3 starts again, and
  otherwise the connection closes with the session's code. The early
  session also accepts no server stream before Quinn accepted the early
  data, so a server stream that arrives in that interval stays for the
  session that replaces a rejected one.
- Every session applies the same start checks, in `check_start` and
  `apply_peer_alps`: a missing `h3` ALPN or malformed ALPS `ACCEPT_CH`
  closes the connection with `H3_GENERAL_PROTOCOL_ERROR`, and invalid ALPS
  SETTINGS close it with `H3_SETTINGS_ERROR`.
- The datagram router forgets the discarded session's stream order when the
  new session replaces it, and `peer_extensions` reads the new session's
  SETTINGS.

A resumed connection also advertises `initial_rtt_us` (`0x3127`) when the
transport profile lists `QuicTransportParameterKind::InitialRtt`, as
`chromium::v154_quic` does. The ticket cache keeps the round-trip time last
measured to each server name, at most four names. `phantom-net` records
Quinn's smoothed RTT through `QuicClientConfig::record_round_trip_time` when
a connection's handshake completes and again when its driver ends, but never
for a connection whose handshake did not complete. `start_session` takes the
ticket first, and passes the recorded value to the transport-parameter
encoder only when it presents one. The encoder writes a minimal-length
varint and permutes the parameter with the others; without a value it omits
the parameter, and the other parameters are ordered as on a fresh connection.

A connection that sends early data is built before its handshake delivers the
server's TLS metadata. When the handshake completes with the early data
accepted, the connection applies the same checks a connection without early
data applies before its first request: the exact `h3` ALPN, the ALPS
`ACCEPT_CH` entries, and the ALPS SETTINGS. The HTTP/3 driver applies the ALPS
SETTINGS through `h3::client::Connection::apply_peer_application_settings`,
from the vendored `late-application-settings.patch`, and reconciles them with
control-stream SETTINGS that arrived first. Only then does the connection
report its early data as accepted. If the metadata is invalid, the connection
is closed, and the requests on it fail with the same `Http3Error` a full
handshake reports. A request sent as early data went out before any ALPS was
known, so it carries no client hints requested through ALPS `ACCEPT_CH`;
requests sent after the handshake do.

Because the connection is pooled before its early data is answered, `n`
concurrent requests to one resumed location share one connection, as the
resumed Chrome 154 connection in the retained captures carried six
concurrent fetches. They wait for the location's connect turn only while the
connection is being opened, not while its handshake runs.

### Racing

Under `AltSvcPolicy::race`, one request runs two candidates:

- Before any I/O, Phantom validates both the H3 and the H1/H2 form of the
  request.
- Each candidate holds its own pool admission and makes at most one setup
  attempt. Both keep the request's origin authority, TLS name, and route.
- The request body, including a one-shot stream, is built only for the
  winner, and the request is dispatched once.
- Cancelling the request before a winner cancels both setups. The connect and
  total deadlines bound each setup and the whole race.
- When the alternative wins, a still-connecting origin setup is cancelled.

A raced setup offers early data when the client does, as Chromium's QUIC
job does, unless QUIC to the origin's own host and port failed a race and has
not connected since. A setup that resumes with early data returns its
connection before the handshake completes, as any early-data connection does
(see [Session tickets](#session-tickets)), so it can win at once, and a
replay-safe request on it goes out as early data. The alternative is
confirmed once the early-data answer shows a completed handshake: at once for
a response, which arrives only after the answer is settled, and after a
failed request within the request's connect and total deadlines. A failed
handshake follows
Chromium: QUIC to the origin is marked recently broken, and a request with no
body or an owned body is raced again once, without early data; a failed
alternative then loses to the origin and is marked broken as in any race. The
retry allows no early data, so it is never raced again, even when it wins on
a pooled connection whose own early data is unanswered.

When the origin wins, an alternative setup that has begun connecting keeps
running in the background, like Chromium's orphaned alternative job. If it
connects, the connection is pooled for later requests. If it fails, including
at the 4-second limit, the alternative is marked broken. A background setup
that resumed with early data connects before its handshake completes; it
confirms the alternative once that handshake completes, and marks nothing if
the handshake fails, as Chromium marks nothing for a session that carried no
request. Until it finishes, it keeps its H3 admission permit for the origin
and route.

A setup still waiting for admission, or for another setup to the same QUIC
location, has done no network work, so it is cancelled instead. The
background setup runs on the Tokio runtime that ran the request. If that
runtime is gone, the setup is dropped, nothing is pooled or marked broken,
and the next request races the alternative again.

Setups for one origin and route run one at a time per QUIC location. A request
to a location waits while another setup connects to that location, then
reuses the connection if that setup succeeded. Exact H3 to the origin's own
location does not wait for a background alternative setup.

## Setup retries

Caller-configured exact-H3 retries can repeat typed DNS, endpoint, or QUIC
connection setup before the request is dispatched. Every retry keeps the same
route and one total deadline. Loopback tests cover recovery for direct and
local-DNS SOCKS5 routes; see
[connection-retry evidence](../explanation/validation.md#connection-retry-evidence).

Opt-in status retry does not depend on the protocol and applies to exact H3,
but its loopback tests use H1 only. Protocol, post-dispatch, and negotiated
upgrade retry policies are not supported.

## Diagnostics

Qlog and NSS key logging are off by default. They are the `qlog` and
`keylog` features of `phantom-net`; the facade's `diagnostics` feature turns
on both and exposes `ClientBuilder::qlog_dir` and `ClientBuilder::key_log`.

- `qlog_dir` gives each new QUIC connection its own file, written by Quinn as
  events happen. The in-memory `QlogCapture` used by tests is single-use and
  bounded in bytes.
- The key-log callback writes validated TLS 1.3 records to a bounded,
  nonblocking queue that TCP and QUIC contexts share. It never performs file
  I/O or calls caller code; the caller drains the queue.

Packet analysis keeps only the protocol metadata needed for comparison. It
does not keep request payloads, plaintext, ciphertext, addresses, connection
IDs, packet numbers, or secrets.

## Capture workflow

The controlled Chrome workflow records one loopback H3 connection through the
first request. Its reference is authenticated packet contents, not a score
from a public fingerprinting service. It retains:

- the ordered QUIC transport-parameter extension;
- the reassembled ClientHello;
- the first control-stream SETTINGS frame;
- the QPACK encoder and decoder stream prefixes;
- the ordered decoded request fields.

The tools live in `scripts/capture/`, and
[Capture tools](../../scripts/capture/README.md) covers how to run them.

- `chrome_http3.py` orchestrates the controlled capture.
- `quic_packet_diff.py` authenticates bounded QUIC v1 packets and emits a
  payload-free summary.
- `compare_quic_flights.py` compares logical markers independently of packet
  boundaries, ACK placement, and retransmission.

Every retained fixture names the exact browser version, platform, launch
conditions, and normalization. Fresh random values may differ between
captures. Semantic order, membership, lengths, packet spaces, stream
boundaries, and request markers may not be discarded to obtain a match.

## Vendored seams

Phantom patches its vendored `h3` and Quinn forks only where the upstream API
cannot express a measured or safety-critical behavior:

- ordered H3 SETTINGS and bounded dynamic QPACK integration;
- starting an early-data connection from remembered peer SETTINGS, and
  exposing the peer's control-stream SETTINGS to remember;
- immediate stream cancellation through the Quinn adapter;
- a peer-SETTINGS readiness signal for extended CONNECT, and poll-driven
  request DATA for the extended CONNECT byte stream;
- QUIC key updates that close the connection instead of panicking when key
  derivation fails.

Each patch is recorded in its fork's patch series and checked by
`scripts/ci/check-vendor.sh`; see [Vendored forks](vendoring.md). The QUIC
key-schedule test vectors are reproduced and asserted in
`crates/phantom-quic-btls/src/key_schedule/tests.rs`.

## Current limits

- H3 routes are direct, local-DNS `socks5://`, remote-DNS `socks5h://`, and
  CONNECT-UDP. HTTP proxy and HTTP CONNECT routes for H3 are planned.
- Extension-specific datagram APIs are planned.
- The CONNECT-UDP limits are listed under
  [Failures and retries](#failures-and-retries).

[Coverage](../reference/coverage.md) has the current contract, and
[Validation](../explanation/validation.md) has the evidence requirements.

## Next

- [Vendored forks](vendoring.md): how to change the `h3` and Quinn patches.
- [Capture tools](../../scripts/capture/README.md): run `chrome_http3.py` and
  the QUIC comparison tools.
- [Coverage](../reference/coverage.md#http3): the HTTP/3 support contract.
