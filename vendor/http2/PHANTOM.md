# Phantom vendor notes: http2

**Audience:** maintainers auditing or refreshing Phantom's HTTP/2 dependency.
This file records provenance, local behavior changes, the refresh procedure,
and required checks. It is not integration documentation.

The files listed in `patches/series` are the canonical local changes, in
application order. Change those patches and replay them; do not make an
unrecorded edit to the vendored crate.

This directory is the complete crates.io source for `http2` version `0.5.20`.

- Crates.io archive SHA-256: `92d3114be2f413b2e491e686b93a28cda30c355cffc8d091a57f8be4b1342896`
- Upstream repository: <https://github.com/0x676e67/http2>
- Upstream crate license and readme remain in `LICENSE` and `README.md`.

## Publish identity

`publish-identity.patch` is always the last entry in `patches/series`. It
renames the package (`http2` becomes `phantom-http2` at `0.5.20-phantom.6`),
keeps the upstream library name so source, tests, and examples are unchanged,
and points the repository metadata at Phantom. It removes the upstream
documentation link, keeps Cargo's reserved archive files out of the packaged
crate, and records the upstream package, version, and source archive under
`[package.metadata.phantom]`. The standalone `Cargo.lock` is packaging metadata
outside the patches and follows the renamed package. It changes no Rust source.

Phantom depends on this package only through the renamed package with an exact
version and a path, so the stock package cannot be selected in its place and no
root `[patch]` table is required. When refreshing, regenerate this patch after
the source patches. Increase the `-phantom.N` suffix whenever the fork's
content changes without an upstream version change, and update the exact pins
in the root `Cargo.toml` and in every renamed dependent.

## Why this patch exists

`http::HeaderMap` preserves duplicate values for a field name but cannot retain
the global interleaving of different field names. That prevents an HTTP/2
client from reproducing an observed browser order such as `x-a: a1`, `x-b: b1`,
`x-a: a2`.

The patch adds `http2::ext::OrderedHeaders`, consumes it when a client request
is converted into its initial HEADERS frame, and emits the supplied ordinary
fields after the configured pseudo-headers. The additive
`SendStream::send_ordered_trailers` path applies the same representation to
trailing HEADERS, including interleaved duplicates and never-indexed sensitive
values. Before encoding, a reconstructed
`HeaderMap` must equal the request's post-middleware semantic map. This checks
names, values, duplicate counts, and per-name value order while intentionally
ignoring global name order that `HeaderMap` cannot represent. A mismatch uses
the existing `UserError::MalformedHeaders` path. Requests without the extension
and trailers sent through the original method retain the upstream `HeaderMap`
iterator.

The ordinary `SendRequest` path clears request extensions before converting
the request into a frame. It now retains `OrderedHeaders` across that cleanup;
the real client-handshake regression proves the public sender preserves the
interleaved order on the wire, rather than testing only the lower conversion.

Inbound HPACK decoding also records ordinary fields in their original global
order, including interleaved duplicates, and attaches `OrderedHeaders` to
received requests and responses. Informational responses retain the same
sidecar. Pseudo-headers remain represented by the existing semantic fields and
are not included in the ordered ordinary-field list.

The real-client regression also exposed an upstream idle-close race: dropping
the final stream can queue an implicit reset while removing the last stream
reference. The connection now polls the open state before starting its idle
close so that queued reset is flushed. A duplex client/server regression proves
the peer observes the reset before connection shutdown.

The same patch contains the complete idle-close correction discovered by the
real-connection regressions. The client polls the open connection before
requesting idle close, and the transition becomes one-shot. This preserves a
queued final reset and avoids a repeated self-wake when GOAWAY cannot yet be
buffered.

Inbound SETTINGS decoding retains both the minimum and final
`SETTINGS_HEADER_TABLE_SIZE` values when an ordered frame repeats that setting.
Applying both values lets the existing HPACK encoder emit the required
minimum-then-final dynamic-table-size updates at the start of its next field
block instead of silently collapsing the transition to the last value.

Inbound header blocks use separate encoded-byte, fragment-count, empty-fragment,
and decoded-size bounds. The encoded budget allows the maximum HPACK Huffman
expansion without relying on the peer to fill every frame. Decoded size remains
cumulative after the ordinary response limit is crossed, so splitting fields
across CONTINUATION frames cannot reset the connection-abuse threshold. Total
fragments use a quarter-minimum-frame work estimate with a fixed 16,384-frame
CPU ceiling; tiny-fragment chains beyond that ceiling are treated as abuse.

The `unstable` client builder also accepts peer HTTP/2 SETTINGS learned through
a transport parameter, such as TLS ALPS, before any HTTP/2 bytes are received.
The seed is applied before the first request can be opened and counts as the
peer's initial SETTINGS, but it is not acknowledged on the HTTP/2 wire. Without
a seed, the first peer frame must remain a non-ACK SETTINGS frame. Seeded and
wire SETTINGS share the same validation and application path: client-side
`SETTINGS_ENABLE_PUSH = 1` is rejected, extended CONNECT cannot be disabled
after it becomes enabled, and `SETTINGS_NO_RFC7540_PRIORITIES` cannot change
after the peer's initial settings. A peer that disables RFC 7540 priorities
suppresses both PRIORITY frames and the priority fields on HEADERS from the
first request onward.

The client sender also exposes a race-free readiness future for RFC 8441. It
distinguishes an initial peer setting that disables extended CONNECT from a
peer whose initial settings have not arrived yet, resolves immediately for an
ALPS seed, and wakes every waiter when wire settings are applied or the
connection fails. The existing synchronous setting snapshot remains available
for callers that do not need that lifecycle guarantee.

Upstream discards every frame type it does not know, including the RFC 7838
section 4 ALTSVC frame (type `0xa`). `altsvc-frames.patch` decodes that frame
and exposes it to clients without changing connection behavior. A malformed
ALTSVC frame is ignored, never a connection or stream error: a payload shorter
than `Origin-Len`, an `Origin-Len` beyond the payload, a stream-0 frame with an
empty origin, a request-stream frame with a non-empty origin, or an origin or
field value larger than 16 KiB. The ordinary frame-size limit still applies
first, exactly as it did to the previously unknown type. Servers ignore ALTSVC.
A client ignores a request-stream frame unless that stream is open and still
awaiting final response headers, and ignores ALTSVC before the peer's initial
SETTINGS, where upstream never observed it.

Upstream configures the request pseudo-header order and RFC 7540 HEADERS
priority only on the client builder, so every stream on a connection shares
them. An RFC 8441 extended CONNECT captured from a browser uses its own
pseudo-header order and priority on the same session as ordinary requests.
`headers-frame-overrides.patch` adds `http2::ext::HeadersFrameOverrides`, an
optional per-request pseudo-header order and stream dependency. The ordinary
`SendRequest` path removes it before clearing request extensions and uses each
set value in place of the connection default for that request's HEADERS frame
only. A peer that disabled RFC 7540 priorities still suppresses the priority
fields. Requests without the extension keep the connection defaults, and HPACK
state remains connection-wide.

Accepted client frames wait in one connection-owned queue bounded to 16 frames;
the oldest frame is dropped first. When final response headers arrive, the
queue's stream-0 frames and that stream's frames are removed in arrival order
and attached to the response as `http2::ext::AltSvcFrames`. Each frame is
therefore delivered with exactly one response. The extension carries the
origin only for stream-0 frames and the raw field value; interpreting either is
the caller's responsibility.

The canonical patch changes these files:

- `.cargo-ok`: preserves the marker in the active Cargo-vendored snapshot.
- `Cargo.toml` and `Cargo.toml.orig`: enable Tokio's test-only `time` feature.
- `src/ext.rs`: define the owned ordered-header extension used by outbound and
  inbound messages, plus the outbound semantic check, and the per-request
  HEADERS overrides.
- `src/client.rs`: configure and await initial peer settings, preserve ordered
  headers, and start idle close only after polling the open connection.
- `src/client/tests.rs`: contain focused semantic, wire, and lifecycle
  regressions for ordered headers and trailers, idle close, peer SETTINGS
  transitions, and extended-CONNECT readiness.
- `src/codec/framed_read.rs`: preserve RFC connection error codes for malformed
  frame lengths and HPACK decoding failures, and bound complete header-block
  work without rejecting maximum-expansion Huffman values that fit the decoded
  limit.
- `src/codec/framed_write.rs` and `src/codec/mod.rs`: provide test-only hooks
  that model a full codec write buffer.
- `src/frame/headers.rs`: select the exact outbound iterator, retain exact
  inbound ordinary-field order, and preserve cumulative decoded-size
  accounting across HPACK fragments.
- `src/frame/settings.rs`: expose the parsed no-RFC-7540-priorities value and
  retain minimum/final header-table-size transitions.
- `src/proto/connection.rs`: make idle close one-shot, seed peer settings, and
  enforce the first-frame SETTINGS rule when no seed is present.
- `src/proto/settings.rs`: validate and apply seeded and wire peer settings
  through the same transition rules without ACKing a seed, including ordered
  HPACK minimum/final size changes.
- `src/proto/streams/recv.rs`: attach decoded ordinary-field order to received
  requests, final responses, and informational responses.
- `src/proto/streams/streams.rs`: retain ordered headers across extension
  cleanup, apply per-request pseudo-header order and priority overrides, enqueue verified ordered request trailers, apply seeded limits before
  stream 1, wake initial-peer-settings waiters, and suppress RFC 7540 priority
  output when directed by the peer.
- `src/share.rs`: expose the additive ordered-trailer send operation.

The canonical source, manifest, and test deltas are listed in
`patches/series`. `ordered-headers.patch` contains the observable-order and
lifecycle work. `rfc-error-codes.patch` maps invalid SETTINGS and PING lengths
to `FRAME_SIZE_ERROR` and HPACK decoding failures to `COMPRESSION_ERROR`, as
required by RFC 9113. The patches remain separate from the complete vendor
snapshot so a candidate release can be tested without reconstructing changes
by hand. `extended-connect-readiness.patch` adds the initial-peer-settings
waiter used to gate RFC 8441 requests. `ordered-header-table-updates.patch`
preserves repeated peer table limits through the next HPACK field block. `continuation-bounds.patch`
separates header-block resource ceilings and fixes cumulative decoded-size
accounting across CONTINUATION frames. `altsvc-frames.patch` adds
`src/frame/altsvc.rs` and the `Kind::AltSvc`/`Frame::AltSvc` decode and encode
arms (`src/frame/{head,mod}.rs`, `src/codec/framed_{read,write}.rs`), the
public `ext::AltSvc`/`ext::AltSvcFrames` types (`src/ext.rs`), connection
dispatch (`src/proto/connection.rs`), client-only queueing
(`src/proto/streams/streams.rs`), response attachment
(`src/proto/streams/recv.rs`), and its regressions in `src/client/tests.rs`.
`headers-frame-overrides.patch` adds the per-request HEADERS overrides
(`src/ext.rs`, `src/proto/streams/streams.rs`) and a wire regression proving
they apply to one request while the next keeps the connection defaults
(`src/client/tests.rs`).

## Security backports

The fork is based on h2 0.4.15 and does not carry later upstream fixes on its
own. `empty-data-frame-budget.patch` backports the fix for RUSTSEC-2026-0258
(GHSA-q83h-524g-xf6h, unbounded small and empty DATA frames), combining
hyperium/h2 #935 (h2 0.4.16), #940 (0.4.17), #945 and #946 (0.4.19):

- <https://rustsec.org/advisories/RUSTSEC-2026-0258.html>
- <https://github.com/hyperium/h2/pull/935> (`193833e`)
- <https://github.com/hyperium/h2/pull/940> (`c12d782`)
- <https://github.com/hyperium/h2/pull/945> (`3850acd`)
- <https://github.com/hyperium/h2/pull/946> (`c7e89e9`)

A non-final DATA frame with an empty decoded payload, including a padded one,
is released for flow control and discarded instead of queued. At most 100 such
frames are accepted over the connection's lifetime. Other non-final frames
smaller than 256 bytes charge `256 - len` against a connection budget, larger
frames replenish it, and reading or discarding a buffered small frame returns
its charge. The budget is half the initial target connection window, with a
minimum of 25,600 bytes. Exhausting either limit sends
`GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames")`. Final DATA frames are never
charged. The configurable `data_frame_budget` builder option from #942 is not
ported because Phantom does not expose it. The patch changes
`src/proto/{mod,connection}.rs`, `src/proto/streams/{counts,mod,recv,streams}.rs`,
and the builders in `src/{client,server}.rs`, and carries upstream's unit tests.
Upstream's own dropped-`RecvStream` flow-control release (#930) is not part of
this backport.

The patch also ports #940's connection regressions from
`tests/h2-tests/tests/stream_states.rs` into `src/client/tests.rs`, with a
raw-frame peer in place of upstream's mock, because the published crate omits
upstream's integration-test crate. Both run under the default 65,535-byte
connection window, so the budget is 32,767 bytes and each charged one-byte
frame costs 255. `many_small_final_data_frames_do_not_exhaust_budget` buffers
one final DATA frame on each of 200 streams without reading them, and
`dropping_buffered_data_frames_releases_budget` drops 200 bodies that still
hold a buffered non-final frame. Each then requires the client to answer a
PING without having sent GOAWAY. Charging final frames, or keeping a dropped
body's charges, exhausts the budget and fails the corresponding test with
`GOAWAY(ENHANCE_YOUR_CALM)`.

## Local receive limits

Upstream decodes up to 16 MiB of response header list when the local SETTINGS
omit `SETTINGS_MAX_HEADER_LIST_SIZE`, which browser profiles such as Firefox
and Safari do. `local-header-list-limit.patch` adds the client builder option
`local_max_header_list_size`. It is never advertised, so the SETTINGS frame is
unchanged. The codec keeps the advertised value (or the 16 MiB default) and
the local value separately and applies the lower one, including when the
local SETTINGS are acknowledged, so a peer cannot raise it. The header-block
byte, CONTINUATION, and fourfold connection-abuse bounds derive from that
effective limit exactly as they do from the advertised setting.

The advertised and local limits both count RFC 9113 section 6.5.2 decoded size:
name plus value plus 32 bytes per field. Phantom sets the local limit to
393,216, the default of Firefox's `network.http.max_response_header_size`, but
Firefox applies that value to other quantities. `Http2Session::RecvHeaders` sums
the encoded HPACK bytes of a HEADERS frame and its CONTINUATION frames,
excluding padding and priority, and answers an excess with
`GOAWAY(PROTOCOL_ERROR)` for the whole connection.
`nsHttpTransaction::ProcessData` fails the request once its decoded head,
serialized as a status line and `name: value\r\n` lines, exceeds the value. The
ceilings therefore match only approximately: a list of many small fields reaches
Phantom's first, because 32 bytes per field exceeds Firefox's 4. Sources, at
mozilla-central `4d5216592535`:

- <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/Http2Session.cpp#l1577>
- <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/nsHttpTransaction.cpp#l2823>

A client response over the effective limit still resets the stream with
`PROTOCOL_ERROR`, as before. The stream records the cause, and the error
returned from the response future reports
`http2::Error::is_header_list_too_large()`, so callers can classify it without
any change to the frames sent. The patch changes `src/client.rs`,
`src/codec/{framed_read,mod}.rs`, `src/error.rs`, and
`src/proto/streams/{recv,stream,streams}.rs`, and adds a codec unit test
proving the advertised setting cannot raise the local ceiling.

Upstream queues every informational (1xx) response on its stream until the
caller polls, with no count. `informational-response-limit.patch` adds the
client builder option `max_informational_responses`, unlimited by default.
Each client stream counts informational heads as they are received, so the
queue is bounded even while the response future is not polled. The first head
over the limit resets the stream with `ENHANCE_YOUR_CALM` and the error
reports `http2::Error::is_too_many_informational_responses()`. The patch
changes `src/client.rs`, `src/server.rs` (which leaves the limit unset),
`src/error.rs`, `src/proto/connection.rs`, and
`src/proto/streams/{counts,mod,recv,stream}.rs`, and adds client regressions
for the limit and one head beyond it in `src/client/tests.rs`.

Upstream h2 0.4.17 also caps the HPACK encoder table at 4 KiB whatever the
peer's `SETTINGS_HEADER_TABLE_SIZE` (hyperium/h2 #941, `67734f8`,
<https://github.com/hyperium/h2/pull/941>). That change is deliberately not
ported, because it would change request bytes. Chromium's
`SpdySession::HandleSetting` passes the peer value through
`BufferedSpdyFramer` and `SpdyFramer::UpdateHeaderEncoderTableSize` to quiche
`HpackEncoder::ApplyHeaderTableSizeSetting`. That encoder's upper bound is
`SIZE_MAX` unless `HpackEncoder::SetHeaderTableSizeBound` is called, and
neither `net/spdy/spdy_session.cc` nor `net/spdy/buffered_spdy_framer.cc`
calls it. Firefox's `Http2Session` passes the value to
`Http2Compressor::SetMaxBufferSize`, which also adopts it unchanged. Both
announce the new size in a dynamic-table-size update at the start of the next
field block and then index against the larger table. Sources, at Chromium
`d4f1d250d580`, quiche `535a2730e77d`, and mozilla-central `4d5216592535`:

- <https://github.com/chromium/chromium/blob/d4f1d250d580d9f9c801148b870b997e9e7ccc25/net/spdy/spdy_session.cc#L2347-L2350>
- <https://github.com/google/quiche/blob/535a2730e77d47e0dc03746555cc9c34b17bc9e9/quiche/http2/core/spdy_framer.cc#L1355-L1357>
- <https://github.com/google/quiche/blob/535a2730e77d47e0dc03746555cc9c34b17bc9e9/quiche/http2/hpack/hpack_encoder.cc#L124-L138>
- <https://github.com/google/quiche/blob/535a2730e77d47e0dc03746555cc9c34b17bc9e9/quiche/http2/hpack/hpack_encoder.cc#L163-L173>
- <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/Http2Session.cpp#l1870>
- <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/Http2Compression.cpp#l1428>

With the cap, a peer advertising 65,536 would get no update, and later blocks
would diverge once the client's own entries exceed 4 KiB. The exposure is
small. The table allocates nothing in proportion to its maximum and holds only
fields the client itself encodes. Phantom limits each request to 100 fields
and 32 KiB, and a field larger than the table is never inserted. Phantom's
regressions pin the uncapped update for 65,536 and 2^32 - 1.

## HPACK encoder identity

RFC 7541 leaves three encoder choices open that every decoder resolves the same
way but that are visible on the wire, and the retained WebSocket captures under
`fixtures/websocket/` show observed clients making them differently:

- Whether a field is inserted into the dynamic table. Chrome 154 and Edge 153
  send `:method: CONNECT` and `:protocol: websocket` as literals without
  indexing on every run; Firefox 156 indexes both incrementally.
- Which entry names a field whose name appears twice in the static table.
  Chrome and Edge name `:method` with entry 2 and `:path` with entry 4;
  Firefox names them with entries 3 and 5, on every request rather than only
  on extended CONNECT.
- Whether a literal string is Huffman-coded. Over all 27 retained captures,
  Chrome's and Edge's 774 coding decisions are exactly the cases where the
  coded form is strictly shorter, and Firefox codes all 831 of its strings.
  Ties are common: `CONNECT`, `13`, `*/*`, `?0`, `?1`, and `1` all code to
  their own raw length. Upstream always codes, so it matches Chromium on no
  tie.

`hpack-encoder-profile.patch` adds `http2::ext::HpackEncoderProfile` and the
client builder option `hpack_encoder_profile`. It states the three choices for
the whole connection, which is where they live in an HPACK encoder, and the
handshake adopts the profile before the initial SETTINGS frame is buffered so
that no entry can reach the dynamic table under a different choice. Each choice
defaults to the upstream behavior, so a connection that sets nothing encodes
byte-for-byte as before.

A listed pseudo-header joins the nghttp2-derived list that already keeps
`:path` and `cookie` out of the dynamic table, so it is sent as an index when
its name and value both match a static entry, and otherwise as a literal
without indexing naming the static entry when one matches. Unlike that list, a
listed pseudo-header need not have a static name: `:protocol` has none and is
then sent with a literal name. The static-name choice moves only the name-only
fallbacks for `:method`, `:path`, and `:scheme`; a full value match is still
sent as its own index, so `:method: GET` stays entry 2 under both choices.
Only the `:method` and `:path` fallbacks are observed; `:scheme` follows the
same rule because it is the same static-table shape, not because a capture
shows it.

The patch changes `src/ext.rs`, `src/hpack/{encoder,table}.rs`,
`src/hpack/huffman/mod.rs` (an encoded-length helper the length rules need),
`src/codec/{framed_write,mod}.rs`, and `src/client.rs`, and adds encoder unit
tests plus a client regression proving the builder option reaches the first
HEADERS block on the wire.

## Cookie crumbs

RFC 9113 section 8.2.3 lets a client split the `cookie` field into one field
per cookie so that each can be indexed on its own. Upstream sends `cookie`
whole and, following nghttp2, never inserts it into the dynamic table. The
retained two-request captures under `fixtures/cookies/` show both observed
encoders splitting it, with different rules:

- Chrome 154 and Edge 153 send each crumb as a literal with incremental
  indexing naming static entry 32, and as an index on the next request. This
  is quiche `HpackEncoder::CookieToCrumbs`, which trims spaces and tabs at
  both ends, splits at every `;`, and skips one space after it, followed by
  its default indexing policy, which indexes every ordinary field.
- Firefox 156 sends a crumb shorter than 20 bytes as a never-indexed literal
  and indexes a longer one; the captures straddle the boundary with crumbs
  of 19 and 20 bytes. `Http2Compressor::EncodeHeaderBlock` splits at every
  `"; "` and passes `neverIndex` for a crumb shorter than 20 bytes.

Sources, at quiche `535a2730e77d` and mozilla-central `4d5216592535`:

- <https://github.com/google/quiche/blob/535a2730e77d47e0dc03746555cc9c34b17bc9e9/quiche/http2/hpack/hpack_encoder.cc#L253-L283>
- <https://github.com/google/quiche/blob/535a2730e77d47e0dc03746555cc9c34b17bc9e9/quiche/http2/hpack/hpack_encoder.cc#L72-L83>
- <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/Http2Compression.cpp#l1140>

`cookie-crumbs.patch` adds `http2::ext::CookieCrumbs` (`Whole`, `IndexAll`,
`NeverIndexShort`) and `HpackEncoderProfile::cookie_crumbs`. The encoder
splits each `cookie` value, including a further nameless value of the same
field, and encodes the crumbs in order at the field's position. For a crumb,
the `cookie` entry on the nghttp2-derived never-index list is lifted, and the
crumb's sensitivity comes from the rule rather than from the field: `IndexAll`
never marks a crumb sensitive, and `NeverIndexShort` marks exactly the crumbs
shorter than 20 bytes. A slice of a valid field value is always a valid
value; should a crumb still fail to convert, a debug assertion fires and the
field is sent once, whole. The default `Whole` encodes byte for byte as
before.

The name index a crumb carries once a `cookie` entry is in the dynamic table,
and the size above which a crumb is not indexed, belong to the encoder as a
whole; [HPACK indexing rules](#hpack-indexing-rules) covers them.

The patch changes `src/ext.rs` and `src/hpack/{encoder,table}.rs`, and adds
encoder unit tests for both split rules, the indexing of each crumb, the
sensitivity override, a nameless further value, and the unchanged default.

## HPACK indexing rules

The encoder profile above leaves the rest of the indexing policy upstream's:
which ordinary fields enter the dynamic table, which entry names a literal,
how large an indexed field may be, and when a table size setting is
announced. Each browser decides some of these differently from upstream,
and the Firefox captures show it: replaying every retained Firefox HTTP/2
session with only the profile above reproduces 3 of 27 connections, and at
least one HEADERS block of each other connection differs. The Chromium-family
captures hold no field that separates the Chromium rules from upstream's, so
those rules rest on source.

The rules come from the browsers' encoders:

- Firefox 156 (`Http2Compressor::ProcessHeader` and `EncodeHeaderBlock`,
  mozilla-central `4d5216592535`) scans the static table and then the dynamic
  table from newest to oldest. The first entry that matches name and value is
  sent as an index; otherwise a literal names the last entry with the name,
  which is the oldest dynamic entry when one exists. `:path` is always a
  literal without indexing, even `/`, named by the matching entry.
  `authorization` and a crumb under 20 bytes are never-indexed literals.
  Every other field is inserted unless its entry size exceeds half the table,
  or the table is under 128 bytes. `HuffmanAppend` codes every string, an
  empty one as `0x80`. `SetMaxBufferSize` queues a size update for every
  received `SETTINGS_HEADER_TABLE_SIZE`, even one equal to the current size,
  and announces the lowest value first when it is below the last one.
- Chromium 154 pins quiche `80bf9559d3a4` in `DEPS`; its `hpack_encoder.cc`
  and `hpack_header_table.cc` are identical to those at `535a2730e77d`, cited
  above. `HpackEncoder::EncodeRepresentations` sends a match of name and
  value as an index, and its default policy indexes every ordinary field and
  `:authority`; it has no never-indexed form. `HpackHeaderTable::GetByName`
  prefers the static entry and then the newest dynamic one, and
  `TryAddEntry` evicts to make room for a field of any size, emptying the
  table for one larger than it. `ApplyHeaderTableSizeSetting` ignores a
  setting equal to the current one. Chromium's `net/spdy` sets no indexing
  policy.

Sources:

- <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/Http2Compression.cpp#l1037>
- <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/Http2Compression.cpp#l1365>
- <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/Http2Compression.cpp#l1428>
- <https://github.com/chromium/chromium/blob/154.0.8037.58/DEPS#L452>
- <https://github.com/google/quiche/blob/80bf9559d3a4c08dde4b85abc46d190a88ffef64/quiche/http2/hpack/hpack_encoder.cc#L72-L83>
- <https://github.com/google/quiche/blob/80bf9559d3a4c08dde4b85abc46d190a88ffef64/quiche/http2/hpack/hpack_encoder.cc#L140-L160>
- <https://github.com/google/quiche/blob/80bf9559d3a4c08dde4b85abc46d190a88ffef64/quiche/http2/hpack/hpack_header_table.cc#L27-L41>
- <https://github.com/google/quiche/blob/80bf9559d3a4c08dde4b85abc46d190a88ffef64/quiche/http2/hpack/hpack_header_table.cc#L140-L153>

`hpack-indexing-rules.patch` adds five profile choices and one Huffman rule to
`http2::ext`, each defaulting to the upstream behavior:

- `FieldIndexing`: `Nghttp2` keeps upstream's list (`age`, `authorization`,
  `content-length`, `etag`, `if-modified-since`, `if-none-match`,
  `location`, `set-cookie`) out of the table; `All` indexes every ordinary
  field; `NeverIndexAuthorization` marks `authorization`, and any nameless
  further value of it, sensitive and indexes the rest. `:path`, and a
  `cookie` sent whole, stay out under every rule.
- `NameReference`: `Upstream`; `StaticThenNewest`; `OldestDynamic`, the
  oldest dynamic entry with the name, otherwise the static entry that
  `StaticNameIndex` picks. A non-upstream rule resolves every reference
  against the table as it stands before the field changes it, which is the
  table the peer resolves it against (RFC 7541 section 4.4), so a literal
  may name an entry its own insertion evicts.
- `UnindexedMatch`: `Index` sends a field kept out of the table that matches
  an entry as that index; `Literal` sends it as a literal naming the entry.
- `IndexingLimit`: `ThreeQuarters` (upstream), `Half`, or `Unlimited`. An
  `Unlimited` field larger than the table is sent with incremental indexing,
  empties the table, and is not inserted.
- `SizeUpdates`: `WhenChanged` (upstream) or `EverySetting`.
- `HuffmanCoding::AlwaysIncludingEmpty`: codes every string and flags an
  empty one.

A caller's sensitive field is a never-indexed literal under every rule,
though Chromium has no such form. Upstream sent a sensitive field that
matched a static entry, or an entry inserted before the field was marked, as
that entry's index; the patch sends a never-indexed literal naming the entry
instead, under the default profile too. After an oversized field, a nameless
further value names a static entry again and spells out a dynamic name, which
no longer resolves.

The patch changes `src/ext.rs` and `src/hpack/{encoder,table}.rs`, and
extends `src/hpack/test/fuzz.rs`. Its encoder unit tests decode every block
they check with the crate's own decoder. They cover both name references,
including the Firefox cookie sequence and a literal that names the entry its
own insertion evicts; the literal match of `:path: /`; both size limits and
the oversized field with its further values; each field rule; a sensitive
field matching a static and a dynamic entry; repeated and unchanged size
settings; and the flagged empty string. The default-profile identity test
still passes. The fuzz test also runs under a random profile, with `cookie`
values of several crumbs, and requires the decoder to read back every field,
each crumb as its own field. `crates/phantom-net/src/http2/tests/hpack_replay.rs` replays
every retained Chromium-family and Firefox HTTP/2 session and compares each
HEADERS block with the capture byte for byte.

## Stream limit before SETTINGS

Upstream's client builder already sets the first stream ID
(`Builder::initial_stream_id`, under the `unstable` feature) and the number
of streams opened before the peer's SETTINGS arrive
(`Builder::initial_max_send_streams`). Phantom uses both: Firefox 156 starts
each connection at stream 3, and both Chromium and Firefox open at most 100
streams until the peer states `SETTINGS_MAX_CONCURRENT_STREAMS`.

Upstream lifts the initial limit to `usize::MAX` when the peer's initial
SETTINGS omit the setting, because RFC 9113 section 5.1.2 leaves the peer's
limit unbounded until it states one. Neither browser does. Chromium's
`SpdySession` starts at `kInitialMaxConcurrentStreams`, 100, and changes the
limit only in `HandleSetting` for `SETTINGS_MAX_CONCURRENT_STREAMS`, which it
also lowers to at most 256. Firefox's `Http2Session` starts at
`network.http.http2.default-concurrent`, 100, and changes it only on the same
setting. Sources, at Chromium tag `154.0.8037.58` and mozilla-central
`4d5216592535`:

- <https://github.com/chromium/chromium/blob/154.0.8037.58/net/spdy/spdy_session.h#L82-L84>
- <https://github.com/chromium/chromium/blob/154.0.8037.58/net/spdy/spdy_session.cc#L837>
- <https://github.com/chromium/chromium/blob/154.0.8037.58/net/spdy/spdy_session.cc#L2355-L2358>
- <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/Http2Session.cpp#l236>
- <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/Http2Session.cpp#l1880>

`retained-stream-limit.patch` adds the client builder option
`retain_initial_max_send_streams`. When set, initial SETTINGS without the
setting leave the initial limit in place; a stated value, initial or later,
replaces it as before, and seeded peer settings count as the initial
SETTINGS. The default leaves upstream's behavior unchanged, and servers never
set it. The 256 ceiling is not modeled. The patch changes `src/client.rs`,
`src/server.rs`, `src/proto/connection.rs`, and
`src/proto/streams/{counts,mod}.rs`. Its regressions in `src/client/tests.rs`
hold a raw peer's SETTINGS back: two requests open and the third waits,
SETTINGS without the setting keep it waiting, and a stated limit of three
opens it; without the option, the same SETTINGS open it. A third regression
pins upstream's `initial_stream_id` numbering from 3, which Phantom relies
on.

## Refreshing the vendor copy

Phantom resolves this directory as `phantom-http2`, so `cargo fetch` never
downloads the upstream registry source. Download the exact crates.io archive
directly.

1. Choose the reviewed version and its checksum from the crates.io index. For
   the currently vendored release, create an isolated staging directory and
   verify the archive with the platform's standard SHA-256 command:

   ```sh
   http2_version=0.5.20
   expected_checksum=92d3114be2f413b2e491e686b93a28cda30c355cffc8d091a57f8be4b1342896
   refresh_dir=$(mktemp -d "${TMPDIR:-/tmp}/phantom-http2.XXXXXX")
   archive="$refresh_dir/http2-$http2_version.crate"

   curl --fail --location \
     --output "$archive" \
     "https://static.crates.io/crates/http2/http2-$http2_version.crate"

   if command -v shasum >/dev/null 2>&1; then
     actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
   else
     actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
   fi
   test "$actual_checksum" = "$expected_checksum"

   tar -xzf "$archive" -C "$refresh_dir"
   candidate="$refresh_dir/http2-$http2_version"
   ```

   `shasum` covers macOS and `sha256sum` covers typical Linux environments.
   Stop if neither command exists or if the checksum comparison fails.

2. Check and apply the canonical patch series in order:

   ```sh
   while IFS= read -r patch; do
     if [ "$patch" = ordered-headers.patch ]; then
       git -C "$candidate" apply --check --unidiff-zero \
         "$PWD/vendor/http2/patches/$patch"
       git -C "$candidate" apply --unidiff-zero \
         "$PWD/vendor/http2/patches/$patch"
     else
       git -C "$candidate" apply --check \
         "$PWD/vendor/http2/patches/$patch"
       git -C "$candidate" apply \
         "$PWD/vendor/http2/patches/$patch"
     fi
   done < "$PWD/vendor/http2/patches/series"
   ```

   A failed dry application is expected evidence that the upstream source
   changed around the patch. Review and regenerate the patch; do not apply it
   with rejected hunks or fuzz.

3. Copy the patched candidate to `vendor/http2.next`, and update the version
   and checksum in this file. Keep the current directory as a rollback copy
   while testing:

   ```sh
   test ! -e vendor/http2.next
   cp -R "$candidate" vendor/http2.next
   cp vendor/http2/PHANTOM.md vendor/http2.next/PHANTOM.md
   mkdir -p vendor/http2.next/patches
   cp vendor/http2/patches/series vendor/http2/patches/*.patch \
     vendor/http2.next/patches/
   mv vendor/http2 "$refresh_dir/http2.previous"
   mv vendor/http2.next vendor/http2
   ```

4. Update the exact `phantom-http2` pins in the root `Cargo.toml` and in
   `vendor/wreq-proto`'s identity patch, refresh the lockfiles, prove the
   selected source, and run the required checks:

   ```sh
   cargo metadata --format-version 1 >/dev/null
   cargo tree -i phantom-http2 --locked
   ```

   `cargo tree` must show `phantom-http2 v$http2_version-phantom.N` at
   `vendor/http2`, below `phantom-wreq-proto`. Confirm that the `Cargo.lock`
   diff changes only the `phantom-http2` package entry before committing. If any check fails, move the failed
   `vendor/http2` directory aside, move `$refresh_dir/http2.previous` back to
   `vendor/http2`, and restore the reviewed lockfile change before retrying.

## Required checks

```sh
scripts/ci/check-vendor.sh http2
cargo fmt --manifest-path vendor/http2/Cargo.toml --all --check
cargo check --manifest-path vendor/http2/Cargo.toml --all-targets --all-features --locked
cargo test --manifest-path vendor/http2/Cargo.toml --all-features client::tests
cargo test --manifest-path vendor/http2/Cargo.toml --all-features --lib -- --skip hpack::test::fixture
cargo tree -i phantom-http2 --locked
cargo +1.85.0 check --workspace --all-targets --locked
```

The published crate excludes `fixtures/**`, although its generated fixture test
functions remain in `src/hpack/test`. Running the unfiltered library suite from
the crates.io source therefore reports those missing files as failures. The
second test command above runs every packaged non-fixture unit test.
