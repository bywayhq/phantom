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
types. Direct H3 uses Quinn's UDP transport. Local-DNS `socks5://` uses a
Phantom-owned RFC 1928 UDP ASSOCIATE adapter while retaining the association's
TCP control connection. H3 is not routed through a generic TCP transport
abstraction and does not fall back to H2 or H1.

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
- immediate stream cancellation through the Quinn adapter; and
- fallible QUIC key-update behavior that closes the connection instead of
  panicking after derivation failure.

Each patch is provenance-tracked and checked by `scripts/ci/check-vendor.sh`.
The QUIC key-schedule vectors are reproduced and asserted in
`crates/phantom-quic-btls/src/key_schedule/tests.rs`.

## Current limits

H3 accepts direct routes and local-DNS `socks5://`. The SOCKS5 path resolves the
origin locally, establishes an optionally RFC 1929-authenticated RFC 1928 UDP
ASSOCIATE for one IP target, and retains the TCP control connection for the
association lifetime. A concrete relay address is used directly. An
unspecified relay address is replaced only with the established TCP proxy peer
IP while retaining the returned nonzero port; domain relay addresses and zero
ports are rejected. The adapter rejects fragmented, malformed, wrong-target,
and non-relay datagrams.

The complete route remains part of pool identity, and compatible requests can
reuse the H3 connection and its association. Proxy authentication,
negotiation, and rejection failures are typed and are not address-fallback
candidates. Proxy TCP and QUIC connection setup may advance or retry only
through a fresh association on the same configured route, under the exact-H3
setup policy; no failure can change the route or protocol. Remote-DNS
`socks5h://`, HTTP proxy and CONNECT routes for H3, CONNECT-UDP/MASQUE,
Alt-Svc/H3 upgrade, extended CONNECT, and extension-specific datagram APIs
remain planned.

Caller-configured exact-H3 retries may repeat typed DNS, endpoint, or QUIC
connection setup before request dispatch while preserving one route and total
deadline. Status, protocol, post-dispatch, and negotiated upgrade retry
policies remain unsupported. Static and declared streaming-body-produced
request trailers use the same ordered, connection-owned QPACK path. See
[Coverage](coverage.md) for the current contract and [Validation](validation.md)
for evidence requirements.
