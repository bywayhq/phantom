# Phantom patch notes

This directory is the complete crates.io source for `quinn-proto` version
`0.11.18`.

- Crates.io archive SHA-256:
  `a9746dbde176634f4f2f1faf2404e30a31b2bc1e9cafb5329c95d8177a18c9fc`
- Crates.io archive:
  <https://static.crates.io/crates/quinn-proto/quinn-proto-0.11.18.crate>
- Upstream repository: <https://github.com/quinn-rs/quinn>
- Upstream crate licenses remain in `LICENSE-APACHE` and `LICENSE-MIT`.

## Why this patch exists

`crypto::Session::next_1rtt_keys` was infallible apart from an `Option`. A
provider whose key derivation can fail could not report that failure without
panicking or silently substituting different behavior.

The patch changes that method to return
`Result<Option<KeyPair<Box<dyn PacketKey>>>, TransportError>`. The stock rustls
provider retains its prior behavior inside `Ok`. Quinn treats provider errors
and an unexpected `Ok(None)` as `INTERNAL_ERROR`.

Initial 1-RTT installation and explicit, automatic, and peer-triggered key
updates all derive the replacement pair before changing current keys or the key
phase. An automatic failure aborts packet construction. Timestamped paths send
a transport close with the existing keys. The timestamp-free public
`force_key_update` path terminates locally and reports the same error to the
application.

Focused tests inject deterministic failures at the first 1-RTT derivation and
at each update path. They verify `INTERNAL_ERROR`, unchanged key state, and no
automatic-update packet emission. The patch does not add a BoringSSL Session
implementation.

The canonical source and test delta is stored in
`patches/fallible-key-updates.patch`. `PHANTOM.md` and the patch file are
packaging metadata and are not part of that patch.

## Refreshing the vendor copy

1. Download and verify the reviewed crate archive in an isolated directory:

   ```sh
   quinn_proto_version=0.11.18
   expected_checksum=a9746dbde176634f4f2f1faf2404e30a31b2bc1e9cafb5329c95d8177a18c9fc
   refresh_dir=$(mktemp -d "${TMPDIR:-/tmp}/phantom-quinn-proto.XXXXXX")
   archive="$refresh_dir/quinn-proto-$quinn_proto_version.crate"

   curl --fail --location --output "$archive" \
     "https://static.crates.io/crates/quinn-proto/quinn-proto-$quinn_proto_version.crate"

   if command -v shasum >/dev/null 2>&1; then
     actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
   else
     actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
   fi
   test "$actual_checksum" = "$expected_checksum"

   tar -xzf "$archive" -C "$refresh_dir"
   candidate="$refresh_dir/quinn-proto-$quinn_proto_version"
   ```

2. Dry-apply and apply the canonical patch. A failed dry application requires
   review and patch regeneration; do not accept fuzz or rejected hunks.

   ```sh
   git -C "$candidate" apply --check \
     "$PWD/vendor/quinn-proto/patches/fallible-key-updates.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/quinn-proto/patches/fallible-key-updates.patch"
   ```

3. Copy the patched candidate to `vendor/quinn-proto.next`, then copy this file
   and the canonical patch into it. Keep the current directory as a rollback
   copy until all checks pass. Update the version, archive URL, checksum, and
   patch when refreshing.

4. Refresh and inspect the workspace selection:

   ```sh
   cargo update -p quinn-proto --precise "$quinn_proto_version"
   cargo tree -i quinn-proto --locked
   ```

   The tree must select `quinn-proto v$quinn_proto_version` from
   `vendor/quinn-proto`. The lockfile diff should only remove the registry
   source and checksum from that package entry.

## Focused checks

```sh
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked tests::key_update
cargo clippy --manifest-path vendor/quinn-proto/Cargo.toml --all-targets --all-features --locked -- -D warnings
cargo check -p phantom-quic-btls --all-targets --locked
```

The integration checkout owns workspace-wide gates.
