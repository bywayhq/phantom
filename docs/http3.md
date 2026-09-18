# HTTP/3 internals

This document is for contributors working on QUIC, HTTP/3, QPACK, or their
capture fixtures. Application users should start with
[Getting started](getting-started.md).

## Stack boundary

Phantom's direct H3 path combines:

- a dedicated TLS 1.3 profile;
- Quinn for QUIC transport;
- the private `phantom-quic-btls` crypto provider;
- Hyperium's `h3` engine; and
- Phantom-owned connection, request, QPACK, cancellation, and diagnostic
  policy.

The public API exposes Phantom types rather than Quinn, BoringSSL, or `h3`
types. H3 is not routed through a generic TCP transport abstraction and does
not fall back to H2 or H1.

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

H3 is direct-only. Caller-configured exact-H3 retries may repeat typed DNS,
endpoint, or QUIC connection setup before request dispatch while preserving one
route and total deadline. Status, protocol, post-dispatch, and negotiated
upgrade retry policies remain unsupported. UDP proxy routes, Alt-Svc upgrade,
trailers produced by a streaming request body, and extension-specific datagrams
remain planned. See
[Coverage](coverage.md) for the current contract and [Validation](validation.md)
for evidence requirements.
