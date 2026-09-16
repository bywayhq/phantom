# HTTP/3 Quinn/BoringSSL architecture audit

This note records the evidence and implementation boundary for the first
forced-HTTP/3 client slice. It is not a new public API proposal.

## Decision

Use Quinn's existing crypto-provider interface with a private,
client-only `phantom-quic-btls` adapter. Adapt and harden the official
`quinn-rs/quinn-boring` implementation rather than implementing QUIC crypto
from scratch or introducing a second BoringSSL build.

Use two narrow, default-preserving `quinn-proto` patches for provider-contract
gaps only. In 0.11.18, `Session::next_1rtt_keys` has no error channel, and Quinn
unwraps its result both when installing 1-RTT keys and when replenishing the
next key phase. `Session::initial_keys` is also infallible even though an
external provider can fail to derive or construct Initial keys. BoringSSL key
derivation and key construction are fallible, so the stock contracts cannot
provide panic-free failure propagation. The patches must convert provider
failure into a bounded connect error or `INTERNAL_ERROR` before inserting a
connection, changing Retry state, changing key phase, or emitting a packet;
they must not add fingerprint controls.

No Quinn patch is needed for transport-parameter ordering. The provider
receives Quinn's semantic `TransportParameters` before BoringSSL constructs
ClientHello, and `TransportParameters::write` is public. The adapter can
serialize the values, parse the resulting QUIC varint TLVs, remove Quinn's
generated reserved parameter, validate the semantic fields, and re-encode the
final ordered bytes with profile-owned GREASE and supported opaque parameters.
This preserves Quinn's state-machine semantics while putting the observable
TLS extension bytes at the correct boundary.

Implementation is staged. The first standards-conforming provider bring-up
feeds Quinn's stock serialized parameters to BoringSSL so callback ownership
and the crypto state machine can be tested without profile reshaping. The
profile-owned serializer is the following slice and remains required before
the Chrome differential can pass; the stock path is not presented as browser
parity.

Carry one narrow, default-preserving `h3` patch now. Both the published release
and audited upstream revision construct outbound SETTINGS in library-defined
order, always include several zero-valued settings, and cannot configure QPACK
table capacity or blocked streams. The patch accepts a concrete ordered list
of `(identifier, value)` pairs, validates it, and has the existing frame
encoder preserve that order. It does not branch on a browser family. The exact
source, archive checksum, canonical patch, refresh procedure, and focused tests
live in `vendor/h3/PHANTOM.md`.

That serialization patch is deliberately not selected by the root workspace
yet. The audited revision's response path still calls `qpack::decode_stateless`.
Advertising Chrome's captured nonzero QPACK capacity and blocked-stream count
before wiring the encoder stream, bounded blocked-section state, decoder
acknowledgements, insert-count feedback, and stream cancellation would promise
behavior the client cannot honor. A static-only integration must advertise
QPACK `0/0` and cannot satisfy the Chrome H3 acceptance gate.

This produces the smallest useful vertical slice:

1. Direct UDP only; forced H3 with no TCP or protocol fallback.
2. BoringSSL TLS 1.3 through Quinn's provider seam.
3. One capture-backed QUIC TLS/transport/H3 profile.
4. Request headers, an optional streaming request body, streaming response
   body, trailers, cancellation, and bounded shutdown.
5. Exact differential fixtures for ClientHello, QUIC transport parameters,
   and the first H3 control-stream SETTINGS frame.

Connection racing, Alt-Svc discovery, pooling, 0-RTT, migration, WebTransport,
and proxied UDP are deliberately outside this slice.

## Dependency baseline

Pin exact identities in the lockfile; do not use version ranges for the forked
sources.

| Component | Audited identity | Use |
| --- | --- | --- |
| `quinn` | `0.11.12` | `default-features = false`, `runtime-tokio`; enable `qlog` only when the feature is exposed by Phantom |
| `quinn-proto` | `0.11.18` | Provenance-tracked fork with fallible Initial and key-update patches; `default-features = false` |
| `quinn-udp` | `0.5.15` | Stock version selected by Quinn 0.11 |
| `h3` | crate version `0.0.8`, fork base `hyperium/h3@1f3d5295833ad454343f25d55633fb6bee1027b2` | Use the provenance-tracked SETTINGS and dormant QPACK-codec patches; do not select the runtime until its QPACK guard is complete |
| `h3-quinn` | crate version `0.0.10`, same repository revision as `h3` | Keep unchanged unless dependency unification requires its manifest to point at the forked sibling |
| `btls`, `btls-sys`, `tokio-btls` | `0xARYA/btls@78b8c24a3388973d1d33c523995d311d766a1026` | One BoringSSL lineage; prefix symbols on Linux, and use the reviewed unprefixed build on Apple/Windows until native prefixing supports Mach-O/COFF |
| adapter reference | `quinn-rs/quinn-boring@8aeaa43a82ffa75cb4621a7fb1211c10f047d02e` (`0.2.0`, unreleased) | Copy/adapt reviewed client-side code; do not depend on it unchanged |

`quinn-boring`'s published `0.1.0` is too old, while its current source uses
Cloudflare's `boring`/`boring-sys` crates and a different foreign-types
generation. A Cargo package alias is therefore not a safe substitution for an
adapter against Phantom's pinned `btls` lineage. The current reference also
contains client-path panics and an unimplemented `peer_identity`; those must
not be copied as-is.

The `quinn-proto 0.11.18` pin also avoids older 0.11 patch levels affected by
the 2026 remote-memory-exhaustion advisory and includes the bounded
`TooManyChunks` handling from Quinn's current 0.11 line.

## Existing seams are sufficient

`quinn-proto 0.11.18` exposes these provider contracts:

- `crypto::ClientConfig::start_session(version, server_name, params)`;
- `crypto::Session` for handshake I/O, negotiated parameters, key epochs,
  Retry integrity, peer identity, and exporters;
- `HeaderKey`, `PacketKey`, `HmacKey`, and `HandshakeTokenKey`.

Quinn can be built without rustls. `EndpointConfig::default` is not available
without a built-in crypto feature, so `phantom-quic-btls` must supply the
BoringSSL-backed HMAC key to `EndpointConfig::new`. Quinn also exposes
`Endpoint::new_with_abstract_socket` and `AsyncUdpSocket`; those are adequate
future seams for SOCKS5 UDP ASSOCIATE and CONNECT-UDP/MASQUE. The direct slice
should use Quinn's normal UDP socket and should not introduce a Phantom socket
trait.

The pinned BoringSSL headers already provide the complete legacy QUIC API:

- `SSL_QUIC_METHOD` read-secret, write-secret, handshake-data, flush, and alert
  callbacks;
- `SSL_set_quic_method`/`SSL_CTX_set_quic_method`;
- `SSL_set_quic_transport_params` and
  `SSL_get_peer_quic_transport_params`;
- `SSL_provide_quic_data`, `SSL_process_quic_post_handshake`, encryption-level
  queries, handshake-flight limits, early-data context, and the legacy
  transport-parameter codepoint switch.

`btls-sys` generates bindings for these symbols. No BoringSSL C/C++ patch is
required. The isolated adapter now owns the callback table, state, traffic
secret copies, output publication, alerts, flight limits, panic boundary, and
the private client `SSL` session. The owner enforces TLS 1.3, exact `h3` ALPN,
peer and hostname verification, copied transport parameters, no BIO, and no
resumption or early data. A concrete Quinn `ClientConfig`/`Session` adapter now
serializes access to that private, thread-affine owner and exposes only owned
handshake data and peer identity.

Quinn requires usable key-update support in the first provider slice. As soon
as it installs the 1-RTT keys, its connection state requests the next 1-RTT key
pair from the crypto session. Treating `next_1rtt_keys` as optional would move
a provider omission into an infallible Quinn path. By contrast, 0-RTT can be
disabled explicitly for this slice; its acceptance state is consulted only
when early keys exist.

## Adapter boundary and remaining additions

`phantom-quic-btls` should be an explicitly audited FFI crate and expose only a
concrete Quinn client configuration to `phantom-net`. Keep all backend types
private to the backend.

The provider now implements:

- installing the context/session QUIC callback table;
- copying read and write secrets into redacted, zeroizing storage;
- buffering handshake output by encryption level and publishing it only at
  `flush_flight`;
- bounded flight accounting and copied alert state; and
- QUIC v1 initial secrets, HKDF expansion, packet AEAD, header protection,
  Retry integrity, repeated key updates, endpoint HMAC, and exporters;
- verified DNS-name handshakes with exact `h3` ALPN and copied peer transport
  parameters; and
- owned leaf-first peer certificate chains with explicit size and count limits.

The next slice must connect this provider to a forced-H3 request path while
keeping transport-parameter serialization capture-driven and private.

Quinn's `read_crypto` callback supplies bytes without an encryption level, so
the level is backend state rather than a public adapter argument. Its
`write_crypto` path queues returned bytes in the packet-number space captured
before the call. The adapter therefore retains future-level flights until the
corresponding keys have been returned and installed.

The completed key-schedule slice maps TLS 1.3 suite identifiers `0x1301`,
`0x1302`, and `0x1303` to SHA-256 or SHA-384 and the packet/header algorithms.
It derives `quic key`, `quic iv`, `quic hp`, and `quic ku`, owns traffic
secrets in zeroizing types with redacted formatting, and advances application
traffic secrets repeatedly. Header-protection keys do not update.

Reuse the existing Phantom TLS profile-to-BoringSSL translation at its
`SslContextBuilder` boundary so TCP and QUIC cannot drift. QUIC must have an
explicit TLS 1.3 profile and ALPN `h3`; TCP-only settings must fail validation
instead of being silently ignored. Add the standard QUIC transport parameters
extension (57) to the profile extension vocabulary.

The first provider explicitly disables resumption and 0-RTT. Those require a
separate replay and session-cache policy and are not prerequisites for a
one-RTT forced-H3 path.

For outbound transport parameters, the adapter should:

1. Call stock `TransportParameters::write`.
2. Parse the complete TLV sequence with strict length and duplicate checks.
3. Remove Quinn's reserved GREASE entry.
4. Check every profile-declared standard value against Quinn's serialized
   value. Configuration which lies about the live transport fails before I/O.
5. Emit captured standard fields, supported opaque fields, and generated
   GREASE using the profile-owned permutation policy and supplied entropy.
6. Feed only those final bytes to `SSL_set_quic_transport_params`.

Keep this encoder private and initially support only the encodings proven by a
retained capture. The provider boundary owns the final bytes, so later evidence
can add a non-canonical varint-width control without changing Quinn or the
facade. Unknown parameters must not be injected until their peer-visible
semantics are understood.

The subsequent Chrome 152 capture found that QUIC transport-parameter order is
randomized across fresh connections. Consequently, one captured order is an
exact seeded fixture, not a canonical browser order. The adapter needs both an
exact deterministic seed path for regression tests and a normal entropy source
for production; multi-seed tests assert the stable parameter set, supported
widths, one GREASE entry, and non-constant order. See `docs/http3-capture.md`.

## Unsafe-code audit boundary

All new unsafe code belongs in `phantom-quic-btls`; `phantom-net` and profile
crates remain safe Rust. Each unsafe block needs the local invariant it relies
on. The review must cover:

- An `Ssl` handle and pinned `Box<CallbackState>` stored as disjoint fields.
  SSL ex-data contains only the stable callback-state pointer, with documented
  callback lifetime, serialization, and teardown ordering. The callback state
  must not own the `Ssl`: callbacks run during a mutable `SSL_do_handshake`
  operation, and recovering a pointer to a larger state which also owns that
  `Ssl` would risk overlapping mutable access to the same object.
- Callback pointers and lengths, including null-plus-zero inputs. Copy secrets,
  handshake data, peer parameters, and certificate material before the
  callback or SSL borrow ends.
- No unwinding across C. Callback failures become BoringSSL failure returns and
  a stored terminal handshake error.
- Raw `SSL*`, `SSL_CTX*`, `EVP_AEAD_CTX`, HKDF, AES, and ChaCha calls, including
  the basis for all `Send`/`Sync` implementations.
- Cipher pointers being valid only for the callback and accepted only for
  supported QUIC TLS 1.3 suites.
- Packet-number, nonce, tag-length, sample-length, and output-capacity bounds.
- Mandatory next-generation 1-RTT keys, key-phase transitions, and
  zeroization; tracing, qlog, and error formatting must never contain key
  material.

Replace reference-code `unwrap`, `panic`, and `todo` sites on runtime paths.
Validate version and algorithm support in `start_session`; callback failures
are stored and surfaced by the current fallible handshake operation. The
patched Quinn key-update boundary propagates later traffic-secret derivation
failures directly, because no subsequent handshake operation is guaranteed.

`write_handshake` only drains previously buffered output and keys.
`read_handshake` owns fallible BoringSSL progression, peer-parameter parsing,
and copied peer identity. `handshake_data` transitions once. A later key-update
failure is returned through the patched provider boundary; dummy, stale, zero,
or partially derived keys are never installed.

The callback bridge treats `flush_flight` as a publication boundary, accepts
null-plus-zero only where BoringSSL permits an empty byte slice, copies all
callback inputs before returning, and tolerates read/write secrets arriving in
either order. No callback may unwind across C or re-enter SSL. Output uses
BoringSSL's maximum-flight guidance, checked length arithmetic, and fallible
reservation.

BoringSSL explicitly documents `SSL` as single-threaded. The private owner is
`Send` because moving its unique owner transfers all access; it is deliberately
not `Sync`. Quinn requires its crypto session to be `Send + Sync`, so the Quinn
adapter must serialize every handshake, post-handshake, exporter, metadata,
identity, and teardown access through one mutex or equivalent call gate. A Rust
wrapper's broader marker traits do not override the C library's contract.

DNS names use SNI and hostname verification. IP literals require the existing
TCP path's distinct IP verification behavior and no SNI; until that is wired,
the H3 configuration must reject IP literals rather than treating them as DNS
names.

## H3 patch and request lifecycle

Base the fork on the exact `hyperium/h3` revision above, not crates.io `0.0.8`
alone. The published release predates later request-cancellation and receive
path fixes. Open or recently fixed upstream reports also show the regression
surface: dropped request streams, a connection error arriving with already
buffered bytes, and transport errors collapsed to `io::ErrorKind::Other`.

The fork should make one behavior change: a validated ordered SETTINGS source
used by the existing encoder. Defaults stay byte-for-byte upstream. Validate
unique identifiers, QUIC-varint bounds, forbidden HTTP/2-only identifiers, and
values constrained by RFC 9114. Do not expose a generic frame injection API.

Runtime selection additionally requires dynamic QPACK receive support as one
coherent capability: consume encoder-stream instructions, cap memory and
blocked field sections by the advertised limits, resume newly decodable
sections, and send acknowledgements, insert-count increments, and cancellation
on the decoder stream. Tests must cover invalid instructions, critical-stream
failure, cancellation races, and resource ceilings. Do not expose a partial
combination of nonzero QPACK settings and stateless decoding.
The concrete ownership, limits, and staged integration are recorded in
[`qpack-design.md`](qpack-design.md).

The direct request path owns the Quinn connection driver, H3 driver, and
endpoint lifetime. Require negotiated ALPN `h3`. Dropping or cancelling a
response body must stop the receive stream and reset the send stream with
`H3_REQUEST_CANCELLED`; driver and endpoint shutdown are bounded. A forced-H3
error is returned as H3/QUIC context and never causes an H2/H1 attempt.

Multiplexing begins above the crypto provider. Quinn owns concurrent
bidirectional and unidirectional streams, and `h3-quinn` adapts those streams
to the H3 engine. The provider supplies a verified connection and key epochs;
it does not implement request admission, stream limits, GOAWAY, or pooling.

## Verification gates

Before integration, require focused tests for:

- RFC 9001 initial-secret, packet-protection, header-protection, Retry, and key
  update vectors;
- transport-parameter parsing/reordering, malformed lengths, duplicates,
  GREASE replacement, semantic mismatch, and exact fixture bytes;
- ordered H3 SETTINGS, forbidden/duplicate identifiers, and default-preserving
  behavior when no ordered settings are supplied;
- QPACK encoder-stream processing, bounded blocked sections, decoder feedback,
  cancellation, invalid instructions, and memory/resource ceilings before any
  nonzero QPACK capability is advertised;
- a local forced-H3 request with streaming body, response, and trailers;
- cancellation/reset, flow-control backpressure, fragmented frames/varints,
  oversized headers, stalled peers, invalid peer parameters, Retry, version
  negotiation, and a connection error in the same read batch as valid bytes;
- proof that all direct-H3 failures make zero TCP connection attempts;
- normalized packet differential against the retained browser capture, plus
  the existing external observers.

Add spans for DNS, UDP/QUIC connect, TLS handshake, negotiated ALPN, peer
parameters, H3 SETTINGS, request time-to-first-byte, body completion,
cancellation, and shutdown. qlog and NSS key logging are explicit diagnostic
options with bounded writers. Normal logs contain neither payloads, header
values, proxy credentials, nor secrets.

The adapter, patched Quinn provider contract, and focused vendored dependency
gates run under the repository's normal warnings-as-errors and formatting
checks. A complete forced-H3 integration gate remains pending because the SSL
session is now adapted to Quinn, but the HTTP/3 request path does not exist.

## Fork trigger

The existing `quinn-proto` patches are limited to recoverable Initial and
key-update error propagation. Do not add observable transport behavior to them
until a retained differential proves a requirement the crypto provider cannot control:
packetization, ACK timing/encoding, connection-ID lifecycle, congestion
control, pacing, or a transport parameter whose value must diverge from
Quinn's live semantics. Exact transport-parameter ordering, GREASE, and
supported opaque entries remain insufficient reasons to extend the fork.

## Sources inspected

- Quinn 0.11 provider and transport-parameter sources:
  <https://github.com/quinn-rs/quinn/tree/0.11.12>
- Official BoringSSL provider reference:
  <https://github.com/quinn-rs/quinn-boring/tree/8aeaa43a82ffa75cb4621a7fb1211c10f047d02e>
- Hyperium H3 audited base:
  <https://github.com/hyperium/h3/tree/1f3d5295833ad454343f25d55633fb6bee1027b2>
- H3 lifecycle/error reports inspected:
  [#262](https://github.com/hyperium/h3/issues/262),
  [#330](https://github.com/hyperium/h3/issues/330),
  [#338](https://github.com/hyperium/h3/issues/338),
  [#351](https://github.com/hyperium/h3/issues/351), and
  [#353](https://github.com/hyperium/h3/issues/353)
- Quinn 0.11 resource-limit fixes inspected:
  [#2785](https://github.com/quinn-rs/quinn/issues/2785) and
  [#2809](https://github.com/quinn-rs/quinn/issues/2809)
- `httpcloak` QUIC/H3 profile and regression history:
  <https://github.com/sardanioss/httpcloak>
- BrowserOxide stock-Quinn H3 path:
  <https://github.com/yfedoseev/browser_oxide>
- hello.js QUIC/H3 implementation:
  <https://github.com/unreleased/hellojs>
- wreq protocol support and dependency layout:
  <https://github.com/0x676e67/wreq>
