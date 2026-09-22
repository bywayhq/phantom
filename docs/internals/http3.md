# HTTP/3 internals

This page describes how Phantom's HTTP/3 path is built, bounded, and proven.
It is for contributors working on QUIC, HTTP/3, QPACK, CONNECT-UDP, or the H3
capture fixtures. To use HTTP/3 from an application, read
[HTTP/3 and Alt-Svc](../guides/http3.md) instead.

Terms used on this page:

- **H3, H2, H1**: HTTP/3, HTTP/2, and HTTP/1.1.
- **QUIC**: the UDP-based transport that carries HTTP/3 (RFC 9000).
- **QPACK**: HTTP/3 field compression (RFC 9204). Its dynamic table is shared
  state that the encoder and decoder keep in sync over two dedicated streams.
- **Exact H3**: a request that must use HTTP/3. It never falls back to H2 or
  H1.
- **Negotiated request**: a request that starts over TCP and lets ALPN pick
  H1 or H2. Later requests to the origin can use H3 through Alt-Svc.

## Stack boundary

Phantom's H3 path combines five parts:

- a dedicated TLS 1.3 profile;
- Quinn for QUIC transport;
- the private `phantom-quic-btls` crypto provider;
- Hyperium's `h3` engine;
- Phantom-owned policy for connections, requests, QPACK, cancellation, and
  diagnostics.

The public API exposes Phantom types, never Quinn, BoringSSL, or `h3` types.
H3 is not routed through a generic TCP transport abstraction, and it never
falls back to H2 or H1.

Each route supplies its own UDP transport:

| Route | UDP transport |
| --- | --- |
| Direct | Quinn's UDP socket |
| SOCKS5 (`socks5://`, `socks5h://`) | A Phantom-owned RFC 1928 UDP ASSOCIATE adapter that keeps the association's TCP control connection open |
| CONNECT-UDP | A Phantom-owned socket that carries the inner QUIC connection in HTTP Datagrams on an outer H3 connection, or in DATAGRAM capsules on an outer H2 or H1 request stream |

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
field-section limit is the lower of two values: the profile's advertised
`SETTINGS_MAX_FIELD_SECTION_SIZE`, and a local 256 KiB ceiling.
`settings::builder` applies the ceiling after building the ordered SETTINGS
list, and the vendored `h3` builder emits that list unchanged, so the ceiling
never appears on the wire.

Before encoding a request, Phantom waits for the peer's SETTINGS and applies
bounded admission. It sends encoder instructions before the HEADERS frame that
depends on them.

The built-in Chrome profile reproduces the retained encoder and HEADERS bytes
of Chrome's first request. A profile that does not opt into dynamic encoding
stays stateless.

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

### Request

- The request is `CONNECT` with `:protocol`, `:scheme https`, `:authority`,
  and `:path`, in the order given by the profile's
  `Http3RequestSettings::extended_connect_pseudo_header_order`. One order
  applies to every extended protocol.
- A profile without that order fails with a configuration error before I/O.
  Named browser recipes leave it unset until a capture backs it.
- Ordered fields follow the ordinary HTTP/3 request rules. `content-length` is
  rejected, because the tunnel has no request content.

### Peer capability

The client waits for the peer's SETTINGS, from ALPS or the control stream.

- Without `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`, the request returns
  `Http3ErrorKind::ExtendedConnectUnavailable`. It opens no request stream and
  tries no other protocol.
- A control-stream value of 0 after an ALPS value of 1 closes the connection
  with `H3_SETTINGS_ERROR` (RFC 8441 section 3).
- The client sends no `SETTINGS_ENABLE_CONNECT_PROTOCOL` of its own, so its
  SETTINGS bytes do not change.

### Response and stream

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

### Tracing

The `http3.extended_connect.response_head` span records method, protocol,
extended protocol, status, and one of these outcomes: `accepted`, `rejected`,
`capability_unavailable`, `protocol_error`, or `request_error`. Field values
are not recorded.

## CONNECT-UDP (MASQUE)

CONNECT-UDP (RFC 9298, part of the MASQUE work) lets a proxy relay UDP. Phantom
uses it to carry an exact-H3 connection to the origin (the inner connection)
through a proxy connection (the outer connection).

`Route::connect_udp` selects it. The outer connection, called the proxy leg,
uses HTTP/3 by default. `ConnectUdpProxy::with_http2_transport` selects
HTTP/2 extended CONNECT, and `with_http1_transport` selects HTTP/1.1 Upgrade.
`phantom-net` exposes the same paths as
`Http3Connector::connect_connect_udp`, `connect_connect_udp_with_basic_auth`,
and `connect_connect_udp_over_tcp`.

### Proxy template

`ConnectUdpProxy::new` takes an `https` URI template with `{target_host}` and
`{target_port}` in its path or query.

- Accepted expressions: simple (`{var}`) and form-style query (`{?var}`,
  `{&var}`).
- Rejected before I/O (RFC 9298 section 2): reserved, fragment, label,
  path-segment, and path-style operators; value modifiers; other variables;
  user information; fragments; non-ASCII characters; and spaces.
- The proxy authority is canonicalized.
- Values are percent-encoded outside the RFC 3986 `unreserved` set, so an
  IPv6 target is sent as `2001%3Adb8%3A%3A42` (RFC 9298 section 3).
- The target is always sent as text. Phantom performs no local lookup of the
  target.

The template scheme must be `https` on every leg. An `http://` template fails
with `ConnectUdpProxyConfigErrorKind::UnsupportedScheme`. RFC 9298 is looser:
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
- Disabled proxy certificate verification is rejected for this route on every
  leg.
- The leg and any credentials are part of `ConnectUdpProxy` equality, so they
  separate pool entries.
- A leg never falls back to another leg, route, or protocol.

### HTTP/3 leg

Capability checks happen before a request stream opens. The proxy's SETTINGS
must carry `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (RFC 9220 section 3) and
`SETTINGS_H3_DATAGRAM = 1`. Its QUIC transport parameters must carry
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
HTTP/2 leg requires the proxy to select `h2`. The HTTP/1.1 leg requires
`http/1.1` or no ALPN. Any other selection fails with
`ConnectUdpErrorKind::UnsupportedProtocol`, and Phantom never retries it on
another leg.

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

Both directions carry DATAGRAM capsules (RFC 9297 section 3.5). Each value is
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
I/O. Credentials never appear in `Debug` output, errors, or diagnostics.

### Datagram capacity

A full inner client Initial packet is 1200 bytes (RFC 9000 section 14.1). On
the HTTP/3 leg's first request stream, the HTTP Datagram adds a one-byte
Quarter Stream ID and a one-byte Context ID, for 1202 bytes.

Quinn reserves a conservative 50 bytes of 1-RTT packet overhead for each
DATAGRAM frame:

| Part | Bytes |
| --- | --- |
| Flags | 1 |
| Connection ID | 20 |
| Packet number | 4 |
| AEAD tag | 16 |
| Frame type and length bound | 9 |

The outer connection therefore uses a fixed initial and minimum path MTU of
1252 bytes, and never probes below it.

Before I/O, the HTTP/3 leg's outer profile must:

- send `SETTINGS_H3_DATAGRAM = 1`;
- advertise a `max_datagram_frame_size` of at least 1205 bytes (a 1-byte frame
  type, a 2-byte length, and the 1202-byte datagram);
- advertise a `max_udp_payload_size` of at least 1252 bytes.

Otherwise the request fails with `ConnectUdpErrorKind::Configuration`. After a
2xx response, if the proxy's datagram limit cannot carry 1202 bytes on the
tunnel's stream, the tunnel closes with
`ConnectUdpErrorKind::DatagramCapacity`.

Paths that cannot carry 1252-byte UDP payloads, including IPv6 minimum-MTU
links, lose full-size inner packets. The HTTP/3 leg never falls back to
DATAGRAM capsules.

The HTTP/2 and HTTP/1.1 legs have no outer datagram limit. A capsule carries
any payload up to the 65,527-byte Context ID 0 bound, and the inner connection
uses its own profile's MTU settings. These legs carry QUIC over TCP, so loss
recovery is nested (RFC 9298 section 6). Prefer the HTTP/3 leg when the proxy
supports it.

### Diagnostics

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

Only two kinds of failure consume the exact-H3 setup retry budget: outer
proxy resolution, and outer QUIC or TCP connection failures. Each retry opens
a fresh outer connection and CONNECT-UDP request on the same route and leg.
Handshake, ALPN, SETTINGS, datagram, authentication, rejection, protocol, and
inner QUIC failures are terminal.

No failure falls back to a direct connection or to another leg, route, or
protocol. CONNECT-UDP never learns or evicts Alt-Svc state.

The route is limited to exact H3. HTTP/1.1, HTTP/2, negotiated requests, and
WebSocket reject it with `UnsupportedRoute` before I/O. Still planned:
multiplexing several tunnels on one outer connection, proxy authentication
schemes other than Basic, and capture evidence for a browser's MASQUE
fingerprint.

## SOCKS5 routes

Exact H3 accepts local-DNS `socks5://` and remote-DNS `socks5h://` routes.

- The local-DNS path resolves the origin locally and fixes one IP target.
- The remote-DNS path performs no local origin lookup, and sends the
  canonical hostname in each RFC 1928 UDP request.

Both establish a UDP ASSOCIATE, optionally authenticated with RFC 1929, and
keep the TCP control connection open for the association's lifetime.

The relay address the proxy returns is handled as follows:

- A concrete relay address is used directly.
- An unspecified relay address is replaced with the established TCP proxy
  peer's IP, keeping the returned nonzero port.
- Domain relay addresses and zero ports are rejected.

The adapter rejects fragmented, malformed, wrong-target, and non-relay
datagrams. For remote DNS, it accepts replies from the exact domain or from an
IP on the same port, and maps accepted replies to one stable logical peer for
Quinn.

The complete route is part of pool identity, so compatible requests can
reuse the H3 connection and its association. Proxy authentication,
negotiation, and rejection failures are typed and never trigger a fallback to
another address. Proxy TCP and QUIC connection setup can advance or retry only
through a fresh association on the same configured route, under the exact-H3
setup policy. No failure can change the route or protocol.

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
[Racing](../guides/http3.md#racing).

One pool entry per origin and route keeps connections for up to four
transport locations. Alternating exact-H3 and Alt-Svc H3 requests therefore
reuse their own connections under the same admission bounds. Setup is
serialized per transport location, not per entry, and the slot table is never
locked across connection setup, so a slow setup to one location does not
delay another.

## Setup retries

Caller-configured exact-H3 retries can repeat typed DNS, endpoint, or QUIC
connection setup before the request is dispatched. Every retry keeps the same
route and one total deadline. Loopback tests cover recovery for direct and
local-DNS SOCKS5 routes; see
[connection-retry evidence](../explanation/validation.md#connection-retry-evidence).

Opt-in status retry does not depend on the protocol and applies to exact H3,
but its loopback tests use H1 only. Protocol, post-dispatch, and negotiated
upgrade retry policies are not supported.

## Current limits

- H3 routes: direct, local-DNS `socks5://`, remote-DNS `socks5h://`, and
  CONNECT-UDP. HTTP proxy and HTTP CONNECT routes for H3 are planned.
- Extension-specific datagram APIs are planned.
- Request trailers, both static and produced by a declared streaming body,
  use the same ordered, connection-owned QPACK path as request headers.

[Coverage](../reference/coverage.md) has the current contract, and
[Validation](../explanation/validation.md) has the evidence requirements.

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

## Diagnostics

Qlog and NSS key logging are off by default. They are the `qlog` feature of
`phantom-net` and the `keylog` feature of `phantom-quic-btls`; the
`phantom-http` facade exposes neither.

- A qlog capture is single-use and bounded in bytes.
- The key-log callback writes validated TLS 1.3 records to a bounded,
  nonblocking queue. It never performs file I/O or calls caller code.

Packet analysis keeps only the protocol metadata needed for comparison. It
does not keep request payloads, plaintext, ciphertext, addresses, connection
IDs, packet numbers, or secrets.

## Vendored seams

Phantom patches its vendored `h3` and Quinn forks only where the upstream API
cannot express a measured or safety-critical behavior:

- ordered H3 SETTINGS and bounded dynamic QPACK integration;
- immediate stream cancellation through the Quinn adapter;
- a peer-SETTINGS readiness signal for extended CONNECT, and poll-driven
  request DATA for the extended CONNECT byte stream;
- QUIC key updates that close the connection instead of panicking when key
  derivation fails.

Each patch is recorded in its fork's patch series and checked by
`scripts/ci/check-vendor.sh`; see [Vendored forks](vendoring.md). The QUIC
key-schedule test vectors are reproduced and asserted in
`crates/phantom-quic-btls/src/key_schedule/tests.rs`.
