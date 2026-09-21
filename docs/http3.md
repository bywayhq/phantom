# HTTP/3 internals

This document is for contributors working on QUIC, HTTP/3, QPACK, or their
capture fixtures. Application users should start with
[Getting started](getting-started.md).

## Stack boundary

Phantom's H3 path combines:

- a dedicated TLS 1.3 profile;
- Quinn for QUIC transport;
- the private `phantom-quic-btls` crypto provider;
- Hyperium's `h3` engine; and
- Phantom-owned connection, request, QPACK, cancellation, and diagnostic
  policy.

The public API exposes Phantom types rather than Quinn, BoringSSL, or `h3`
types. Direct H3 uses Quinn's UDP transport. Local-/remote-DNS SOCKS5 uses a
Phantom-owned RFC 1928 UDP ASSOCIATE adapter while retaining the association's
TCP control connection. CONNECT-UDP uses a Phantom-owned socket that carries
the inner QUIC connection in HTTP Datagrams on an outer H3 connection. H3 is
not routed through a generic TCP transport abstraction and does not fall back
to H2 or H1.

## Profile components

The Chrome H3 recipe keeps four concerns distinct:

1. the H3 ClientHello and exact `h3` ALPN;
2. QUIC transport parameters, ordering, widths, and GREASE policy;
3. local HTTP/3 SETTINGS and their order; and
4. request pseudo-header order and QPACK policy.

Profiles apply captured values to live transport state. Unsupported values or
combinations fail validation rather than being accepted and ignored.

## QPACK ownership

The connection driver owns encoder and decoder streams. Receive-side dynamic
state is bounded by advertised capacity, blocked-stream limits, field-section
limits, and decoder feedback. Request encoding waits for peer SETTINGS, applies
bounded admission, and sends encoder instructions before dependent HEADERS.

The built-in Chrome profile reproduces the retained first-request encoder and
HEADERS bytes. Profiles that do not opt into dynamic encoding retain stateless
behavior. A datagram on an ordinary request is a protocol error until a public
extension-specific API owns it.

## Capture workflow

The controlled Chrome workflow records one loopback H3 connection through the
first request. Its oracle is authenticated traffic, not a public fingerprint
score. It retains:

- the ordered QUIC transport-parameter extension;
- the reassembled ClientHello;
- the first control-stream SETTINGS frame;
- QPACK encoder and decoder prefixes; and
- the ordered decoded request fields.

Capture and comparison tools live in `scripts/capture/`:

- `chrome_http3.py` orchestrates the controlled capture;
- `quic_packet_diff.py` authenticates bounded QUIC v1 packets and emits a
  payload-free summary; and
- `compare_quic_flights.py` compares logical markers independently of packet
  cuts, ACK placement, and retransmission.

Every retained fixture names the exact browser version, platform, launch
conditions, and normalization. Fresh randomness may change; semantic order,
membership, lengths, packet spaces, stream boundaries, and request markers may
not be discarded to obtain a match.

## Diagnostics

Qlog and NSS key logging are default-off. A qlog capture is single-use and
byte-bounded. The key-log callback writes validated TLS 1.3 records to a
bounded nonblocking queue and never performs file I/O or invokes caller code.

Packet analysis retains only protocol metadata needed for comparison. It does
not retain request payloads, plaintext, ciphertext, addresses, connection IDs,
packet numbers, or secrets.

## Vendored seams

Phantom carries narrow patches where upstream APIs cannot express a measured
or safety-critical behavior:

- ordered H3 SETTINGS and bounded dynamic QPACK integration;
- immediate stream cancellation through the Quinn adapter;
- a peer-SETTINGS readiness signal for extended CONNECT, plus poll-driven
  request DATA for the extended CONNECT byte stream; and
- fallible QUIC key-update behavior that closes the connection instead of
  panicking after derivation failure.

Each patch is provenance-tracked and checked by `scripts/ci/check-vendor.sh`.
The QUIC key-schedule vectors are reproduced and asserted in
`crates/phantom-quic-btls/src/key_schedule/tests.rs`.

## Request streams

The one-shot `phantom_net::http3::send_request*` functions take
`Http3RequestSettings` with ordered `RequestHeader` input and use the same
preparation as pooled requests, so their pseudo-header and field order always
come from the profile.

A final response may arrive before the request body is sent. The upload then
continues beside the response body (RFC 9114 §4.1). A complete response resets
an unfinished upload with `H3_REQUEST_CANCELLED`, and a peer `STOP_SENDING`
ends only the upload. A request-body failure after the response head fails the
response body. At most 8 informational responses are accepted per request; the
ninth fails the request with a protocol error. Datagrams for request streams
the client has already closed are dropped silently (RFC 9297 §2.1).

## Extended CONNECT

`phantom-net` can open RFC 9220 extended CONNECT streams on a connection
opened by the same `Http3Connector`. `Http3ExtendedProtocol::WebSocket` is the
only protocol today, and the facade does not expose it yet.

- The request is `CONNECT` with `:protocol`, `:scheme https`, `:authority`,
  and `:path`, in the profile's
  `Http3RequestSettings::extended_connect_pseudo_header_order`. One order
  applies to every extended protocol. A profile without that order fails with
  a configuration error before I/O; named browser recipes leave it unset until
  a capture backs it.
- Ordered fields follow the ordinary HTTP/3 request rules, and
  `content-length` is rejected because the tunnel has no request content.
- The client waits for the peer's SETTINGS, from ALPS or the control stream.
  Without `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` it returns
  `Http3ErrorKind::ExtendedConnectUnavailable` without opening a request
  stream or trying another protocol. A control-stream zero after an ALPS one
  closes the connection with `H3_SETTINGS_ERROR` (RFC 8441 section 3). The
  client sends no ENABLE_CONNECT_PROTOCOL setting of its own, so local
  SETTINGS bytes are unchanged.
- A 2xx response yields `Http3ExtendedConnectStream`, an `AsyncRead` and
  `AsyncWrite` byte stream over DATA frames that buffers at most one received
  chunk and one queued frame. Shutdown sends FIN. Peer trailers are
  `InvalidData`. Dropping an incomplete stream resets only that stream with
  `H3_REQUEST_CANCELLED` (RFC 9220 section 3). The stream holds a connection
  lease, so the driver stays alive while it is open.
- A non-2xx response is returned with its ordered fields and a readable body;
  101 is a protocol error; informational responses are skipped.
- An HTTP Datagram associated with the stream aborts only that stream with
  `H3_DATAGRAM_ERROR` (RFC 9297 section 2).
- The `http3.extended_connect.response_head` span records method, protocol,
  extended protocol, status, and an outcome of `accepted`, `rejected`,
  `capability_unavailable`, `protocol_error`, or `request_error`. Field values
  are not recorded.

## CONNECT-UDP (MASQUE)

`Route::connect_udp` carries exact H3 through an RFC 9298 CONNECT-UDP proxy.
`phantom-net` exposes the same path as `Http3Connector::connect_connect_udp`.

- `ConnectUdpProxy::new` takes an `https` URI template with `{target_host}`
  and `{target_port}` in its path or query. Simple (`{var}`) and form-style
  query (`{?var}`, `{&var}`) expressions are accepted. Reserved, fragment,
  label, path-segment, and path-style operators, value modifiers, other
  variables, user information, fragments, non-ASCII, and spaces are rejected
  before I/O (RFC 9298 section 2). The proxy authority is canonicalized.
  Values are percent-encoded outside RFC 3986 `unreserved`, so an IPv6 target
  is sent as `2001%3Adb8%3A%3A42` (RFC 9298 section 3). The target is always
  sent as text; Phantom performs no local target lookup.
- Each inner connection gets a fresh outer H3 connection to the proxy. The
  outer connector uses the H3 profile with the client's proxy trust roots and
  the proxy host as SNI; the inner connection keeps origin trust, SNI, and
  authority. Disabled proxy verification is rejected for this route.
- Before a request stream opens, the proxy's SETTINGS must carry
  `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (RFC 9220 section 3) and
  `SETTINGS_H3_DATAGRAM = 1`, and its QUIC transport parameters must carry
  `max_datagram_frame_size` (RFC 9297 section 2.1.1; RFC 9221 section 3).
  Otherwise the request fails with
  `ConnectUdpErrorKind::ExtendedConnectUnavailable` or `DatagramUnavailable`
  without origin I/O.
- The request is extended CONNECT with `:protocol connect-udp`, the proxy
  authority, and the expanded path, in the profile's extended CONNECT
  pseudo-header order. A generated `capsule-protocol: ?1` field precedes the
  route's ordered fields (RFC 9297 section 3.4; RFC 9298 section 3.4). A
  caller `capsule-protocol` or `content-length` field is rejected before I/O.
- Only a 2xx final response opens the tunnel. A 2xx that is 204, 205, or 206,
  or that carries `content-length`, `content-type`, or `transfer-encoding`, is
  malformed (RFC 9297 section 3.2). Any other final status aborts the request
  and returns `ConnectUdpErrorKind::Rejected` with `ConnectUdpError::status`.
  Phantom never sends optimistic datagrams before the response, although
  RFC 9298 section 5 permits them.
- UDP payloads use Context ID 0 in QUIC DATAGRAM frames. Received datagrams go
  to a per-stream queue of at most 256 payloads. Overflow, unknown Context IDs,
  undecodable Context IDs, and datagrams that arrive before the stream is
  registered are dropped and counted (RFC 9297 section 2.1; RFC 9298 sections
  4 and 5). A Context ID 0 payload above 65,527 bytes aborts the stream with
  `H3_DATAGRAM_ERROR`. DATAGRAM capsules on the request stream feed the same
  queue, and unknown capsules are skipped without buffering (RFC 9297 section
  3.2). A DATAGRAM capsule above 65,535 bytes or a truncated final capsule
  aborts the stream, and the proxy's FIN or reset ends the tunnel. Phantom
  never sends DATAGRAM capsules.
- Quinn sees one fixed logical peer, `192.0.2.1:443`. As with `quinn-udp`,
  only `WouldBlock` could reach Quinn from a send; oversized or undeliverable
  datagrams are dropped and counted. The socket holds the outer connection
  lease. When the outer connection or request stream ends, the socket reports
  a receive error, the inner endpoint stops, and the pool opens a fresh outer
  connection for the next request.
- The `proxy.connect_udp` span records `proxy_protocol`, `status`, `outcome`
  (`accepted`, `rejected`, or `error`), `error_kind`, and, when the tunnel
  ends, `dropped_unknown_context`, `dropped_overflow`, `dropped_early`,
  `dropped_malformed`, `dropped_oversized`, and `dropped_send`. Paths, field
  values, and payloads are not recorded.

### Datagram capacity

A full inner client Initial is 1200 bytes (RFC 9000 section 14.1). On the
outer connection's first request stream, the HTTP/3 Datagram adds a one-byte
Quarter Stream ID and a one-byte Context ID, for 1202 bytes. Quinn reserves a
conservative 50 bytes of 1-RTT packet overhead per DATAGRAM frame: 1 flag byte,
a 20-byte connection ID, a 4-byte packet number, a 16-byte AEAD tag, and a
9-byte frame type and length bound. The outer connection therefore uses a
fixed initial and minimum path MTU of 1252 bytes and never probes below it.

Before I/O, the outer profile must send `SETTINGS_H3_DATAGRAM = 1`, advertise a
`max_datagram_frame_size` of at least 1205 bytes (1-byte frame type, 2-byte
length, and the 1202-byte datagram), and advertise a `max_udp_payload_size` of
at least 1252 bytes. Otherwise the request fails with
`ConnectUdpErrorKind::Configuration`. After a 2xx response, if the proxy's
datagram limit cannot carry 1202 bytes on the tunnel's stream, the tunnel is
closed with `ConnectUdpErrorKind::DatagramCapacity`. Paths that cannot carry
1252-byte UDP payloads, including IPv6 minimum-MTU links, lose full-size inner
packets; there is no fallback to DATAGRAM capsules.

### Failures and retries

CONNECT-UDP setup failures are `Http3ConnectorErrorKind::Proxy` errors whose
source is a `ConnectUdpError`. The facade reports `RequestErrorKind::Proxy`,
or `Resolve` and `RuntimeUnavailable` for those kinds. Only outer proxy
resolution and outer QUIC connection failures consume the exact-H3 setup retry
budget, and each retry opens a fresh outer connection and CONNECT-UDP request
on the same route. Handshake, SETTINGS, datagram, rejection, protocol, and
inner QUIC failures are terminal. No failure falls back direct or to another
route or protocol, and CONNECT-UDP never learns or evicts Alt-Svc state.

The route is limited to exact H3. HTTP/1.1, HTTP/2, negotiated requests, and
WebSocket reject it with `UnsupportedRoute` before I/O. Proxy authentication,
several tunnels multiplexed on one outer connection, and capture evidence for a
browser's MASQUE fingerprint remain planned.

## Current limits

H3 accepts direct routes, local-DNS `socks5://`, remote-DNS `socks5h://`, and
CONNECT-UDP. The local-DNS path resolves the origin locally and fixes one IP
target. The remote-DNS path performs no local origin lookup and sends the
canonical hostname in each RFC 1928 UDP request. Both establish an optionally
RFC 1929-authenticated UDP ASSOCIATE and retain the TCP control connection for
the association lifetime. A concrete relay address is used directly. An
unspecified relay address is replaced only with the established TCP proxy peer
IP while retaining the returned nonzero port; domain relay addresses and zero
ports are rejected. The adapter rejects fragmented, malformed, wrong-target,
and non-relay datagrams. For remote DNS, exact-domain or same-port IP replies
are accepted, and the adapter maps accepted replies to one stable logical peer
for Quinn.

The complete route remains part of pool identity, and compatible requests can
reuse the H3 connection and its association. Proxy authentication,
negotiation, and rejection failures are typed and are not address-fallback
candidates. Proxy TCP and QUIC connection setup may advance or retry only
through a fresh association on the same configured route, under the exact-H3
setup policy; no failure can change the route or protocol. Exact H3 also
accepts RFC 9298 CONNECT-UDP routes; see
[CONNECT-UDP (MASQUE)](#connect-udp-masque). HTTP proxy and CONNECT routes for
H3 and extension-specific datagram APIs remain planned. Negotiated direct HTTPS
requests can opt into a bounded Alt-Svc store, learned from response fields
and exact-origin H2 ALTSVC frames, and use a fresh canonical `h3` alternative
on a later request. Callers may export and re-import that direct-route state;
Phantom never persists it or QUIC tickets itself. One origin-and-route pool
entry keeps connections for up to four transport locations, so alternating
exact H3 and Alt-Svc H3 requests reuse their own connections under the same
admission bounds. The QUIC dial location changes, while origin
authority and certificate identity do not; setup failure is terminal and
evicts the advertisement without an H1/H2 fallback.

Caller-configured exact-H3 retries may repeat typed DNS, endpoint, or QUIC
connection setup before request dispatch while preserving one route and total
deadline. Status, protocol, post-dispatch, and negotiated upgrade retry
policies remain unsupported. Static and declared streaming-body-produced
request trailers use the same ordered, connection-owned QPACK path. See
[Coverage](coverage.md) for the current contract and [Validation](validation.md)
for evidence requirements.
