# Phantom vendor notes: h3

**Audience:** maintainers auditing or refreshing Phantom's HTTP/3 dependency.
This file records provenance, local behavior changes, the refresh procedure,
and focused checks. It is not integration documentation.

The files listed in `patches/series` are the canonical local changes, in
application order. Change those patches and replay them; do not make an
unrecorded edit to the vendored snapshot.

This directory is a complete source snapshot of the exact Hyperium H3 commit
recorded below. The `h3` and `h3-quinn` packages are the dependency boundary
used by Phantom; the other workspace packages remain so the upstream manifests
and focused package tests work without packaging rewrites.

- Upstream commit: `1f3d5295833ad454343f25d55633fb6bee1027b2`
- Upstream repository: <https://github.com/hyperium/h3>
- Source archive:
  <https://codeload.github.com/hyperium/h3/tar.gz/1f3d5295833ad454343f25d55633fb6bee1027b2>
- Complete source archive SHA-256:
  `a30747c0c9f35a57c03c17619e7231eb7f94a4629f3644228219280850d57183`
- Package versions: `h3 0.0.8`, `h3-quinn 0.0.10`
- The upstream MIT license remains in `LICENSE`.

## Publish identity

`publish-identity.patch` is always the last entry in `patches/series`. It
renames the package (`h3` becomes `phantom-h3` at `0.0.8-phantom.4`,
`h3-datagram` becomes `phantom-h3-datagram` at `0.0.2-phantom.4`, `h3-quinn`
becomes `phantom-h3-quinn` at `0.0.10-phantom.4`), keeps the upstream library
name so source, tests, and examples are unchanged, and points the repository
metadata at Phantom. It removes the upstream documentation link, keeps Cargo's
reserved archive files out of the packaged crate, and records the upstream
package, version, and source archive under `[package.metadata.phantom]`.
Internal `h3`, `h3-datagram`, `quinn`, and `quinn-proto` dependencies,
including those of the unpublished `h3-webtransport` and `examples` members and
`h3`'s test dependencies, point at the renamed packages so the standalone
workspace exercises the same QUIC stack as Phantom. It changes no Rust source.

Phantom depends on this package only through the renamed package with an exact
version and a path, so the stock package cannot be selected in its place and no
root `[patch]` table is required. When refreshing, regenerate this patch after
the source patches. Increase the `-phantom.N` suffix whenever the fork's
content changes without an upstream version change, and update the exact pins
in the root `Cargo.toml` and in every renamed dependent.

## Why this patch exists

Upstream builds the outbound SETTINGS frame from individual builder fields in
library-defined order. It also generates its own GREASE entry and always emits
several zero-valued settings. That API cannot reproduce an observed ordered
SETTINGS frame containing concrete extension and GREASE values.

The patch adds `h3::client::Builder::ordered_settings`. It accepts a borrowed
slice of `(identifier, value)` pairs, validates the complete list, and copies it
into the existing fixed-size SETTINGS representation. When present, that list
is emitted in the supplied order with canonical QUIC varint widths. It is the
complete wire list: upstream automatic GREASE and ordinary settings assembly
are bypassed. When absent, the upstream conversion path is unchanged.

Validation rejects:

- duplicate identifiers;
- identifiers or values outside the QUIC varint range, and a locally
  advertised QPACK table capacity above the engine's implementation limit;
- HTTP/2-only reserved identifiers `0x2` through `0x5`, plus upstream's
  existing invalid identifier `0x0`;
- values other than zero or one for the supported boolean CONNECT, datagram,
  and WebTransport settings; and
- more than the upstream representation's eight entries.

Supplied settings that already have a connection-level semantic field also
update that existing view. This keeps header limits and extension flags
consistent with the emitted frame without introducing browser-family policy
into the engine. The semantic view now also retains the QPACK table-capacity
and blocked-stream settings and defaults both to zero when omitted. Blocked
streams preserve every HTTP/3 QUIC variable-length integer. Locally advertised
table capacity is validated against the engine's `2^30 - 1` implementation
limit before runtime construction; peer settings retain the full QUIC varint
range. WebTransport enforcement remains separate from QPACK runtime support.

## Dynamic HEADERS runtime

The client response and trailer paths share the decoder owned by the connection
driver. Dynamic sections park until encoder-stream inserts satisfy their
required insert count. A dropped receive future preserves its section; stream
drop, reset, and `stop_sending` queue one cancellation instruction. Successful
dynamic decoding queues a header acknowledgement. The request-lifetime
cancellation reservation remains active after response headers, covering
abandonment before unseen trailers.

Resource ownership is explicit:

- declared HEADERS lengths reserve capacity before payload buffering;
- individual encoded sections are limited to 1 MiB; sections and reserved
  blocked read-ahead share an 8 MiB connection ceiling;
- later response bytes buffered while blocked are limited to 64 KiB per
  stream, including a pre-buffer check for oversized transport chunks; the
  reservation follows those buffered bytes until consumption or stream drop;
  and
- queued, reserved, and in-flight decoder feedback share a 64 KiB ceiling.

The codec reconstructs required insert counts from the locally advertised
maximum capacity, even before the peer's capacity update arrives. Distinct
blocked streams obey `SETTINGS_QPACK_BLOCKED_STREAMS`; fragmented instructions,
partial feedback writes, invalid instructions, critical-stream closure, future
cancellation, and reset wakeups have focused regressions.

The Chrome profile uses its captured nonzero inbound QPACK limits after a live
raw control-stream differential. Its explicit dynamic request policy waits for
peer SETTINGS, then uses a connection-owned encoder. Stateless request encoding
remains the default for other profiles.

## Ordered request fields

`h3::ext::RequestPseudoHeaderOrder` and `h3::ext::OrderedHeaders` carry an
outgoing request's declared pseudo-header and ordinary-field order without
changing its semantic `http::Request`. The request encoder validates that each
pseudo-header exists exactly once and that the ordinary sidecar matches the
request `HeaderMap` by name, duplicate value order, and sensitivity marker.
Invalid sidecars return a local request error before a QUIC request stream is
opened; they do not close the HTTP/3 connection.

The header iterator emits every pseudo-header first in the declared order,
followed by ordinary fields in exact sidecar order. The focused QPACK regression
fixes the resulting stateless field-section bytes for an interleaved duplicate.
Sensitivity participates in sidecar agreement and round-trips through decoded
headers. Sensitive values use QPACK's N bit and are never inserted or indexed.

## Ordered response fields

QPACK decoding retains ordinary response fields in their original global
order, including interleaved duplicates and sensitivity markers. The client
attaches that order as `h3::ext::OrderedHeaders` in the response extensions
without changing the semantic `HeaderMap`. Pseudo-headers remain represented
by the existing response status and are excluded from the ordered sidecar.

`patches/ordered-response-headers.patch` is deliberately separate from the
outbound request-order patch so upgrades can review the inbound API and decoder
changes independently.

`patches/ordered-response-send.patch` extends the same sidecar to server
responses. Phantom uses that narrow seam in end-to-end tests to prove the
public client retains interleaved QPACK response fields instead of observing a
`HeaderMap`-normalized test fixture.

`h3-quinn` now polls Quinn's cancel-safe chunk read directly instead of moving
the receive stream into a stored future. This keeps `stop_sending` immediately
available while a read is pending, so cancellation retains its chosen HTTP/3
error code instead of falling through to Quinn's implicit code zero. The read
remains zero-copy and does not allocate a boxed future per poll.

## HTTP/3 application settings

`h3::client::Builder::peer_application_settings` accepts authenticated peer
application settings copied from the completed TLS handshake. An empty value
remains distinct from an absent value and retains the control-stream SETTINGS
requirement. A nonempty value may contain unknown frames and at most one valid
HTTP/3 SETTINGS frame; known-forbidden frames are rejected.

Those settings initialize the peer semantic view and QPACK limits before a
request can start. A SETTINGS frame sent first on the control stream may repeat
compatible values or increase limits; reductions and conflicts close with
`H3_SETTINGS_ERROR`.
Malformed payloads, forbidden frames, multiple SETTINGS frames, and invalid or
repeated settings fail before HTTP/3 opens streams. Local ordered SETTINGS
remain independent and unchanged.

`patches/application-settings.patch` contains the engine and regression-test
delta for this seam.

A client that sends early (0-RTT) data builds its connection before the
handshake delivers the peer's application settings.
`h3::client::Connection::apply_peer_application_settings` applies them to the
running connection with the same payload validation. When control-stream
SETTINGS arrived first, the two are reconciled under the rules above, so the
result matches a connection built with the same application settings. A
malformed payload, a conflict, or a second application closes the connection
with `H3_SETTINGS_ERROR`. `patches/late-application-settings.patch` contains
this delta and its regression tests.

Likewise, do not advertise a nonzero `WEBTRANSPORT_MAX_SESSIONS` until the
connection path enforces that limit and has bounded lifecycle tests. Exact
serialization is not sufficient evidence that the advertised capability is
implemented.

The retained Chrome fixture is recorded at
`fixtures/http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt` in
the Phantom repository. A unit regression fixes its complete control-stream prefix,
including setting order and the concrete GREASE identifier/value widths.

The stateful QPACK encoder can be configured from peer table-capacity and
blocked-stream settings. It stages inserts before encoding a field section, so
new entries use the final Base and relative references. Encoder-stream strings
use Huffman coding only when it shortens the value. The default stateless field
section encoder retains its existing byte representation.

The optional live path reserves a bounded command slot before opening a
request stream. The connection driver owns the encoder, caps its table and
instruction buffers, writes instructions before releasing dependent HEADERS,
and uses a publication lease to cancel references only before HEADERS enqueue.
Peer limits above local strategy ceilings are clamped rather than allocated.

The local QPACK decoder stream has an opt-in deferred-visibility policy. The
stream handle is still reserved during connection setup and retains the same
critical-stream lifecycle, but its type byte is written only when decoder
feedback exists. Header and feedback bytes share one bounded poll budget, and
only feedback bytes advance QPACK accounting. The default remains upstream's
eager stream type.

Ordered request trailers retain duplicate and cross-name field order plus
sensitivity markers. Their trailing HEADERS section uses the same bounded,
connection-owned outbound QPACK command path as the initial request section,
including publication and cancellation accounting for multiple sections on one
request stream. Stateless configurations keep their existing encoder path.

## QPACK stream order

Upstream opens the control stream, then the QPACK encoder stream, then the
decoder stream, so on QUIC they are client streams 2, 6, and 10, and it writes
each stream type when the connection starts. Chromium opens the decoder stream
before the encoder stream, so its encoder is stream 10, and writes a QPACK
stream's type only with its first instruction (quiche
`http/quic_spdy_session.cc` lines 1629-1676 and `qpack/qpack_send_stream.cc`
lines 32-51 at the revision Chromium 154 pins).

`h3::client::Builder::qpack_decoder_stream_first` opens the decoder stream
second and the encoder stream third. `defer_qpack_encoder_stream` reserves the
encoder stream but holds its type in the outbound QPACK driver. Instructions
queued before the first field section that needs them, such as the table
capacity from peer or remembered SETTINGS, are held too, and all of them are
written after the type ahead of that field section's HEADERS. A connection
that encodes no such field section never writes to the stream. Both default to
upstream's behavior. `patches/qpack-chromium-stream-order.patch` contains this
delta and its regression tests.

## Remembered SETTINGS for early data

RFC 9114 section 7.2.4.2 lets a client that sends 0-RTT data start from the
server SETTINGS of the connection that issued its session ticket, and
Chromium does. Upstream has no way to seed peer SETTINGS before the control
stream delivers them, or to read the control-stream frame back.

`h3::client::Connection::peer_settings_to_remember` returns the SETTINGS
frame received on the peer's control stream, encoded, once the connection
has applied it. It holds only the settings the engine understands.
`h3::client::Builder::remembered_peer_settings` accepts that frame, with the
payload validation of `peer_application_settings`, on a later connection.
The remembered values initialize the peer semantic view and the dynamic
QPACK encoder's table capacity and blocked-stream limit, and mark peer
SETTINGS ready, so a dynamic request encodes at once and its encoder
instructions precede its HEADERS. They do not count as the control stream's
SETTINGS: a control stream whose first frame is not SETTINGS still fails
with `H3_MISSING_SETTINGS`.

SETTINGS that arrive later, on the control stream or through late
application settings, must stay compatible with the remembered ones. A
remembered nonzero QPACK table capacity must be repeated exactly (RFC 9204,
section 3.2.3); a remembered blocked-stream limit, field-section limit, or
WebTransport session limit must be neither omitted nor reduced; and a
remembered enabled extended CONNECT, HTTP Datagram, or WebTransport setting
must be neither omitted nor disabled. A violation closes the connection with
`H3_SETTINGS_ERROR` and nothing is offered to remember. For the QPACK table
capacity this departs from RFC 9204 section 3.2.3, which names
`QPACK_DECODER_STREAM_ERROR`; Chromium's quiche closes with
`H3_SETTINGS_ERROR` for every remembered setting, and the engine matches it
so the close looks the same on the wire. Chromium's quiche
checks the first three and not the extension settings. The engine does not
know whether the server accepted the early data, so it applies these checks
either way; its caller does not reuse a connection whose early data was
rejected.

`patches/remembered-settings.patch` contains this delta and its regression
tests.

## Extended CONNECT readiness

RFC 9220 section 3 reuses RFC 8441's `SETTINGS_ENABLE_CONNECT_PROTOCOL`
(`0x08`). A client may send `:protocol` only after receiving that setting with
value one. Upstream records whether peer SETTINGS arrived but exposes no way to
wait for them, and a control-stream zero could silently replace an ALPS-seeded
one.

`h3::client::SendRequest::peer_settings` returns an owned `PeerSettings`
handle. `PeerSettings::ready` resolves as soon as peer SETTINGS are known,
either from nonempty ALPS application settings or from the control stream, and
wakes every waiter. A connection error resolves each waiter with that error
instead of leaving it pending. The handle does not borrow the sender, so a
caller can wait without serializing unrelated requests.

RFC 8441 section 3 forbids sending zero after one. A control-stream
`SETTINGS_ENABLE_CONNECT_PROTOCOL = 0` after an ALPS-seeded one therefore closes
with `H3_SETTINGS_ERROR`, matching the existing rule that control-stream
settings may not reduce ALPS values. Enabling the setting on the control stream
after ALPS omitted it remains accepted. Default builder behavior is unchanged.

`patches/extended-connect-readiness.patch` contains the engine and
regression-test delta for this seam.

## Poll-driven request DATA

Upstream sends request DATA only through `async fn send_data`, which borrows
the stream for the whole write. A byte-stream adapter implementing
`AsyncWrite` would have to own that future and could no longer reset the
stream when it is dropped mid-write.

The client send half now also exposes `poll_ready`, `start_send_data`, and
`poll_finish`. They are thin wrappers over the QUIC send stream: one DATA frame
is queued only after the previous frame has been written, so at most one frame
is buffered. `poll_finish` ends the stream without the GREASE frame that
`finish` may send first. The async methods are unchanged.

`patches/poll-send-data.patch` contains the engine and regression-test delta
for this seam.

The canonical source and test deltas are stored in the exact application order
listed by `patches/series`. `PHANTOM.md`, the series file, the patch files, and
the tracked standalone-workspace `Cargo.lock` are packaging metadata and are
deliberately excluded from those patches. The lockfile is force-added because
the upstream snapshot ignores workspace lockfiles; vendor CI still requires it
with `--locked` so dependency resolution remains reproducible.

## Refreshing the vendor copy

1. Choose a reviewed upstream commit and download its source archive into an
   isolated directory. Verify its SHA-256 before extracting it:

   ```sh
   h3_revision=1f3d5295833ad454343f25d55633fb6bee1027b2
   expected_checksum=a30747c0c9f35a57c03c17619e7231eb7f94a4629f3644228219280850d57183
   refresh_dir=$(mktemp -d "${TMPDIR:-/tmp}/phantom-h3.XXXXXX")
   archive="$refresh_dir/h3-$h3_revision.tar.gz"

   curl --fail --location --output "$archive" \
     "https://codeload.github.com/hyperium/h3/tar.gz/$h3_revision"

   if command -v shasum >/dev/null 2>&1; then
     actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
   else
     actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
   fi
   test "$actual_checksum" = "$expected_checksum"
   tar -xzf "$archive" -C "$refresh_dir"
   candidate="$refresh_dir/h3-$h3_revision"
   ```

2. Dry-apply the canonical patch series to the pristine source. A failure means
   an upstream boundary changed and needs review; do not accept fuzz or
   rejected hunks.

   ```sh
   patch_root="$PWD/vendor/h3/patches"
   while IFS= read -r patch; do
     if test "$patch" = ordered-response-headers.patch; then
       git -C "$candidate" apply --check --unidiff-zero "$patch_root/$patch"
       git -C "$candidate" apply --unidiff-zero "$patch_root/$patch"
     else
       git -C "$candidate" apply --check "$patch_root/$patch"
       git -C "$candidate" apply "$patch_root/$patch"
     fi
   done < "$patch_root/series"
   ```

3. Copy the patched candidate to `vendor/h3.next`, copy this file, the patch
   series, and the canonical patches into it, then swap it with `vendor/h3`
   while retaining the previous directory until all checks pass. Update the
   commit, archive URL, checksum, and package versions above.

4. Run the focused checks below. After workspace integration, also prove the
   lockfile selects `phantom-h3` and `phantom-h3-quinn` from this directory and inspect the
   lockfile diff before committing.

## Focused checks

```sh
scripts/ci/check-vendor.sh h3
cargo fmt --manifest-path vendor/h3/Cargo.toml -p phantom-h3 -p phantom-h3-datagram -p phantom-h3-quinn -p h3-webtransport -p examples --check
cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 config::tests
cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 client::builder::tests
cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 proto::frame::tests
cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 qpack::
cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 qpack_
cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 remembered_settings
cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 proto::headers::tests
cargo clippy --manifest-path vendor/h3/Cargo.toml --workspace --all-targets --all-features -- -D warnings
cargo check --manifest-path vendor/h3/Cargo.toml -p phantom-h3-quinn --all-features
cargo check --manifest-path vendor/h3/Cargo.toml -p h3-webtransport --all-features
```

The integration checkout owns workspace-wide checks and lockfile verification.
