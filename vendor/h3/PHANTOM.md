# Phantom patch notes

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

Likewise, do not advertise a nonzero `WEBTRANSPORT_MAX_SESSIONS` until the
connection path enforces that limit and has bounded lifecycle tests. Exact
serialization is not sufficient evidence that the advertised capability is
implemented.

The retained Chrome 152 fixture is recorded at
`fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt` in the
Phantom repository. A unit regression fixes its complete control-stream prefix,
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

The canonical source and test deltas are stored in
`patches/ordered-settings.patch`, `patches/qpack-codec.patch`,
`patches/qpack-critical-streams.patch`, `patches/qpack-dynamic-client.patch`,
`patches/cancel-safe-recv.patch`, `patches/ordered-request-headers.patch`,
`patches/qpack-request-encoder.patch`,
`patches/qpack-live-request-runtime.patch`,
`patches/qpack-lazy-decoder-stream.patch`, and
`patches/ordered-response-headers.patch`.
`PHANTOM.md` and the patch files are
packaging metadata and are deliberately excluded from those patches.

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

2. Dry-apply the canonical patches to the pristine source. A failure means an
   upstream boundary changed and needs review; do not accept fuzz or rejected
   hunks.

   ```sh
   git -C "$candidate" apply --check \
     "$PWD/vendor/h3/patches/ordered-settings.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/h3/patches/ordered-settings.patch"
   git -C "$candidate" apply --check \
     "$PWD/vendor/h3/patches/qpack-codec.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/h3/patches/qpack-codec.patch"
   git -C "$candidate" apply --check \
     "$PWD/vendor/h3/patches/qpack-critical-streams.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/h3/patches/qpack-critical-streams.patch"
   git -C "$candidate" apply --check \
     "$PWD/vendor/h3/patches/qpack-dynamic-client.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/h3/patches/qpack-dynamic-client.patch"
   git -C "$candidate" apply --check \
     "$PWD/vendor/h3/patches/cancel-safe-recv.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/h3/patches/cancel-safe-recv.patch"
   git -C "$candidate" apply --check \
     "$PWD/vendor/h3/patches/ordered-request-headers.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/h3/patches/ordered-request-headers.patch"
   git -C "$candidate" apply --check \
     "$PWD/vendor/h3/patches/qpack-request-encoder.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/h3/patches/qpack-request-encoder.patch"
   git -C "$candidate" apply --check \
     "$PWD/vendor/h3/patches/qpack-live-request-runtime.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/h3/patches/qpack-live-request-runtime.patch"
   git -C "$candidate" apply --check \
     "$PWD/vendor/h3/patches/qpack-lazy-decoder-stream.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/h3/patches/qpack-lazy-decoder-stream.patch"
   git -C "$candidate" apply --check --unidiff-zero \
     "$PWD/vendor/h3/patches/ordered-response-headers.patch"
   git -C "$candidate" apply --unidiff-zero \
     "$PWD/vendor/h3/patches/ordered-response-headers.patch"
   ```

3. Copy the patched candidate to `vendor/h3.next`, copy this file and the
   canonical patches into it, then swap it with `vendor/h3` while retaining the
   previous directory until all checks pass. Update the commit, archive URL,
   checksum, and package versions above.

4. Run the focused checks below. After workspace integration, also prove the
   lockfile selects `h3` and `h3-quinn` from this directory and inspect the
   lockfile diff before committing.

## Focused checks

```sh
scripts/ci/check-vendor.sh h3
cargo fmt --manifest-path vendor/h3/Cargo.toml --all --check
cargo test --manifest-path vendor/h3/Cargo.toml -p h3 config::tests
cargo test --manifest-path vendor/h3/Cargo.toml -p h3 client::builder::tests
cargo test --manifest-path vendor/h3/Cargo.toml -p h3 proto::frame::tests
cargo test --manifest-path vendor/h3/Cargo.toml -p h3 qpack::
cargo test --manifest-path vendor/h3/Cargo.toml -p h3 qpack_
cargo test --manifest-path vendor/h3/Cargo.toml -p h3 proto::headers::tests
cargo clippy --manifest-path vendor/h3/Cargo.toml --workspace --all-targets --all-features -- -D warnings
cargo check --manifest-path vendor/h3/Cargo.toml -p h3-quinn --all-features
cargo check --manifest-path vendor/h3/Cargo.toml -p h3-webtransport --all-features
```

The integration checkout owns workspace-wide checks and lockfile verification.
