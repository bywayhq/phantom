# Dynamic QPACK integration

Phantom's pinned Hyperium H3 revision now connects its stateful QPACK decoder
to client response headers and trailers. The engine can advertise nonzero
decoder capacity and blocked-stream limits honestly. Phantom profiles still
advertise QPACK `0/0` until the captured Chrome settings complete packet
differentials; this is a profile-validation gate, not an engine limitation.

## Ownership

The H3 connection driver owns the QUIC encoder and decoder stream handles and
the outbound encoder. Shared connection state owns the inbound decoder,
bounded decoder-feedback queue, blocked response sections, and wake
coordination. Cloned request senders share that state; they do not own critical
streams.

Outbound encoding holds the codec lock only long enough to produce a field
section and any encoder instructions. Required instructions must be accepted
by the bounded queue before the corresponding HEADERS bytes can be published.
If that cannot be guaranteed, the request uses a literal/static encoding that
has no unpublished dependency.

Each request reserves one cancellation instruction for its receive lifetime.
Inbound HEADERS separately reserve encoded-byte and acknowledgement capacity
as soon as the declared frame length is available, before the payload is fully
buffered. One active section is owned by each request stream. Sections with
missing dynamic references retain their encoded bytes and latest task waker;
they are retried when encoder-stream inserts advance. Dropping a receive
future preserves that state, while dropping, resetting, or stopping the stream
queues exactly one cancellation instruction. Clean receive completion releases
the request reservation without sending cancellation.

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
- encoded HEADERS are limited to 1 MiB each; encoded sections and reserved
  blocked read-ahead share an 8 MiB connection ceiling;
- at most 64 KiB of later response bytes are retained while a section is
  blocked, with oversized transport chunks rejected before buffering; that
  reservation remains until the buffered bytes are consumed or the stream is
  dropped; and
- decoded field sections obey `SETTINGS_MAX_FIELD_SECTION_SIZE`; and
- queued, reserved, and in-flight decoder feedback share a 64 KiB ceiling.

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
3. Drive critical streams while HEADERS remain stateless. Prove bounded codec
   buffers and feedback, fragmentation, malformed instructions, and FIN error
   mapping. Complete.
4. Enable client inbound dynamic decoding for response headers and trailers.
   Prove park/unblock, acknowledgement, cancellation, count and byte ceilings,
   dropped-future persistence, and no hangs under reset races. Complete.
5. Enable client outbound dynamic encoding. Prove queue-before-HEADERS ordering,
   shared state across cloned senders, safe literal fallback, concurrency, and
   capture differentials. This is not required to advertise inbound decoder
   limits because QPACK settings are directional.
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
