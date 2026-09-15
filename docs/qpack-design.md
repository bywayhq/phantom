# Dynamic QPACK integration

Phantom's pinned Hyperium H3 revision contains a stateful QPACK codec, but its
HTTP/3 client path still uses stateless encoding and decoding. The ordered
SETTINGS patch can reproduce Chrome's control-stream bytes; it does not make
the advertised nonzero QPACK capacity or blocked-stream count true. Phantom
therefore advertises QPACK `0/0` until the complete client-side loop below is
implemented and bounded.

## Ownership

The H3 connection driver owns the QUIC encoder and decoder stream handles.
Shared connection state owns the QPACK encoder/decoder state, bounded pending
instruction queues, blocked response sections, and wake coordination. Cloned
request senders share that state; they do not own critical streams.

Outbound encoding holds the codec lock only long enough to produce a field
section and any encoder instructions. Required instructions must be accepted
by the bounded queue before the corresponding HEADERS bytes can be published.
If that cannot be guaranteed, the request uses a literal/static encoding that
has no unpublished dependency.

Inbound sections with missing dynamic references retain their complete
encoded HEADERS bytes by request stream and required insert count. They are
retried when encoder-stream inserts advance. Limits apply to distinct blocked
streams and retained encoded bytes, not merely to the number of field
sections.

The driver continuously:

- consumes peer encoder and decoder instructions, including instructions
  fragmented at any byte boundary;
- drains locally queued instructions with QUIC flow-control backpressure;
- sends header acknowledgements after successful dynamic decoding;
- sends insert-count increments as peer inserts are processed; and
- sends stream cancellation when a blocked or dynamically decoded request is
  reset, dropped, or abandoned.

Malformed encoder instructions map to `QPACK_ENCODER_STREAM_ERROR`; malformed
decoder instructions map to `QPACK_DECODER_STREAM_ERROR`. A closed, reset, or
duplicated critical stream closes the H3 connection deterministically.

## Resource contract

Every negotiated value is also a local resource ceiling:

- decoder table capacity never exceeds Phantom's advertised
  `SETTINGS_QPACK_MAX_TABLE_CAPACITY`;
- blocked accounting counts each request stream once, using its maximum
  outstanding required insert count;
- blocked stream count never exceeds the advertised
  `SETTINGS_QPACK_BLOCKED_STREAMS`;
- retained encoded HEADERS bytes have a separate connection-wide ceiling;
- decoded field sections obey `SETTINGS_MAX_FIELD_SECTION_SIZE`; and
- pending encoder and decoder instruction queues have finite byte limits.

Insert-count increments use the complete QPACK prefixed-integer domain. Zero,
overflow, or advancement beyond the number of inserted entries is a protocol
error. Acknowledgement and cancellation remove every applicable outstanding
block and repair blocked-stream accounting.

## Delivery slices

1. Harden the dormant codec in isolation: distinct-stream accounting, complete
   acknowledgement/cancellation cleanup, validated insert counts, local table
   capacity, decoded-size limits, and fragmented instruction parsing.
2. Add semantic QPACK settings and connection state. Defaults remain `0/0`,
   peer settings apply once, and the emitted SETTINGS view cannot disagree
   with the runtime limits.
3. Drive critical streams while HEADERS remain stateless. Prove bounded queues,
   backpressure, fragmentation, duplicate streams, malformed instructions,
   and FIN/reset error mapping.
4. Enable client outbound dynamic encoding. Prove queue-before-HEADERS ordering,
   shared state across cloned senders, safe literal fallback, concurrency, and
   capture differentials.
5. Enable client inbound dynamic decoding for response headers and trailers.
   Prove park/unblock, acknowledgement, cancellation, count and byte ceilings,
   and no hangs under reset races.
6. Enable Chrome's captured nonzero settings only after adversarial integration
   tests and packet differentials pass. Server-side dynamic QPACK remains a
   separate capability.

## Why not replace the H3 stack

Current Hyperium already provides the transport-neutral QPACK table and
instruction machinery needed for this work. Its runtime integration is
missing, but replacing Quinn and H3 would also replace packetization, recovery,
and transport seams that Phantom has already audited. Cloudflare quiche's
dynamic QPACK support is likewise incomplete, while Mozilla Neqo's mature
QPACK state machine is coupled to Neqo transport. Neqo remains a useful design
and test reference—and a possible future Firefox backend—not a drop-in codec
for the first Quinn path.

Primary references:

- [RFC 9204: QPACK](https://www.rfc-editor.org/rfc/rfc9204.html)
- [Hyperium H3](https://github.com/hyperium/h3/tree/1f3d5295833ad454343f25d55633fb6bee1027b2)
- [Hyperium buffered-close issue 338](https://github.com/hyperium/h3/issues/338)
- [quiche dynamic-QPACK issue 1447](https://github.com/cloudflare/quiche/issues/1447)
- [Mozilla Neqo QPACK encoder](https://github.com/mozilla/neqo/blob/main/neqo-qpack/src/encoder.rs)
