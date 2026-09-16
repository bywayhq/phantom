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
- identifiers or values outside the QUIC varint range;
- HTTP/2-only reserved identifiers `0x2` through `0x5`, plus upstream's
  existing invalid identifier `0x0`;
- values other than zero or one for the supported boolean CONNECT, datagram,
  and WebTransport settings; and
- more than the upstream representation's eight entries.

Supplied settings that already have a connection-level semantic field also
update that existing view. This keeps header limits and extension flags
consistent with the emitted frame without introducing browser-family policy
into the engine. The semantic view now also retains the QPACK table-capacity
and blocked-stream settings, defaults both to zero when omitted, and preserves
every value representable by an HTTP/3 QUIC variable-length integer. This
state is bootstrap for later runtime integration; it does not add QPACK or
WebTransport enforcement.

## Integration guard: dynamic QPACK is not wired

Do **not** select this vendor dependency for Phantom's Chrome runtime path only
because the retained SETTINGS prefix can be reproduced. At this revision, the
response path still uses `qpack::decode_stateless`; advertising Chrome's
nonzero `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (`0x1 = 65536`) and
`SETTINGS_QPACK_BLOCKED_STREAMS` (`0x7 = 100`) can therefore promise peer
behavior the engine does not yet honor.

Runtime integration is blocked until it implements and bounds all of the
following together:

- QPACK encoder-stream instruction processing;
- blocked-section tracking and limits;
- decoder acknowledgements, stream cancellation, and insert-count feedback;
  and
- adversarial tests for blocked streams, invalid instructions, cancellation,
  and memory/resource ceilings.

The dormant stateful codec and its semantic SETTINGS bootstrap are hardened by
`patches/qpack-codec.patch`. The codec counts blocked streams by distinct
stream ID, releases all tracked sections on cancellation, validates decoder
feedback and peer capacity updates, enforces decoded field-section limits, and
preserves fragmented critical-stream instructions across input buffers. The
SETTINGS layer retains peer and local QPACK values, including values from an
exact ordered SETTINGS frame. It does not reinterpret protocol-valid wire
values as allocation policy; resource ceilings belong where the future runtime
allocates table and blocked-section state. Both remain deliberately
disconnected from the HTTP/3 connection driver. The explicit encoded-byte
ceiling for parked blocked HEADERS belongs to the future runtime registry that
owns those bytes; the codec does not retain blocked field sections and
therefore cannot enforce that aggregate limit honestly.

A static-table-only integration must advertise both QPACK settings as zero and
must not claim Chrome wire parity. The exact Chrome regression in this patch is
an encoder proof, not an assertion that the rest of the captured QPACK behavior
is implemented.

Likewise, do not advertise a nonzero `WEBTRANSPORT_MAX_SESSIONS` until the
connection path enforces that limit and has bounded lifecycle tests. Exact
serialization is not sufficient evidence that the advertised capability is
implemented.

The retained Chrome 152 fixture is recorded at
`fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt` in the
Phantom repository. A unit regression fixes its complete control-stream prefix,
including setting order and the concrete GREASE identifier/value widths.

The canonical source and test deltas are stored in
`patches/ordered-settings.patch` and `patches/qpack-codec.patch`. `PHANTOM.md`
and the patch files are packaging metadata and are deliberately excluded from
those patches.

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
cargo fmt --manifest-path vendor/h3/Cargo.toml --all --check
cargo test --manifest-path vendor/h3/Cargo.toml -p h3 config::tests
cargo test --manifest-path vendor/h3/Cargo.toml -p h3 client::builder::tests
cargo test --manifest-path vendor/h3/Cargo.toml -p h3 proto::frame::tests
cargo test --manifest-path vendor/h3/Cargo.toml -p h3 qpack::
cargo clippy --manifest-path vendor/h3/Cargo.toml -p h3 --lib --all-features -- -D warnings
cargo check --manifest-path vendor/h3/Cargo.toml -p h3-quinn --all-features
```

The integration checkout owns workspace-wide checks and lockfile verification.
