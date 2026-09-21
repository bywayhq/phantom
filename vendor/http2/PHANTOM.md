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
renames the package (`http2` becomes `phantom-http2` at `0.5.20-phantom.1`),
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
  inbound messages, plus the outbound semantic check.
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
  cleanup, enqueue verified ordered request trailers, apply seeded limits before
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
