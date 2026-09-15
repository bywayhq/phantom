# Phantom patch notes

This directory is the `btls` wrapper package from the exact upstream commit
recorded below. It deliberately does not vendor the `btls-sys` package or
BoringSSL submodule; those remain pinned to the same upstream commit by the
workspace lockfile.

- Upstream commit: `129887582a538b8f4dcf371d15c953335312ca37`
- Upstream repository: <https://github.com/0x676e67/btls>
- Source archive: <https://codeload.github.com/0x676e67/btls/tar.gz/129887582a538b8f4dcf371d15c953335312ca37>
- Complete source archive SHA-256:
  `e77c9cafe8158b8c6e8f7979a461e122e06379285a9f0ab4d68797293dfd9767`
- Upstream package license remains in `LICENSE`.

## Why this patch exists

The upstream safe wrapper can enable ALPS only with an empty application
settings value, although its pinned BoringSSL C API accepts distinct protocol
and settings byte strings. It also does not expose the peer settings query.

The patch is additive:

- `SslRef::add_application_settings_with_payload` passes both byte strings to
  `SSL_add_application_settings`.
- `SslRef::peer_application_settings` combines
  `SSL_has_application_settings` and `SSL_get0_peer_application_settings` into
  `Option<&[u8]>`, preserving the difference between no negotiation and a
  negotiated empty value.
- `src/ssl/test/alps.rs` proves absent, negotiated-empty, and nonempty
  bidirectional values over TLS 1.3 with ALPN `h2`.

The canonical machine-applicable change is `patches/alps-settings.patch`. It
contains only the wrapper API and its upstream-style tests; packaging changes
remain separate.

The existing one-argument `add_application_settings` remains compatible and
delegates to the new method with an empty payload.

`Cargo.toml` materializes the upstream workspace-inherited package fields and
dependencies so this package can be used independently. `README.md` materializes
the exact repository-level file targeted by upstream's package symlink. The
`btls-sys` dependency remains pinned to the same upstream commit.

## Refreshing the vendor copy

1. Download the reviewed upstream commit into an isolated directory and verify
   its complete archive before extracting it:

   ```sh
   btls_revision=129887582a538b8f4dcf371d15c953335312ca37
   expected_checksum=e77c9cafe8158b8c6e8f7979a461e122e06379285a9f0ab4d68797293dfd9767
   refresh_dir=$(mktemp -d "${TMPDIR:-/tmp}/phantom-btls.XXXXXX")
   archive="$refresh_dir/btls-$btls_revision.tar.gz"

   curl --fail --location --output "$archive" \
     "https://codeload.github.com/0x676e67/btls/tar.gz/$btls_revision"
   actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
   test "$actual_checksum" = "$expected_checksum"
   tar -xzf "$archive" -C "$refresh_dir"
   candidate="$refresh_dir/btls-$btls_revision/btls"
   ```

   On Linux, use `sha256sum` when `shasum` is unavailable.

2. Compare `candidate` with `vendor/btls`. Expected differences are
   `patches/alps-settings.patch`, the standalone manifest values, the
   materialized `README.md`, and this file. The checked-in wrapper sources and
   tests should exactly equal the candidate plus the canonical patch.

   The scheduled candidate probe performs this staging from an exact detached
   git revision. It copies only the upstream `btls` wrapper, materializes the
   workspace-inherited manifest fields, replaces the wrapper README symlink
   with its repository target, and pins the standalone `btls-sys` dependency
   to that same revision. These packaging adaptations are separate from
   `patches/alps-settings.patch`; failure to apply that patch is reported as
   source drift requiring review.

3. Replace the wrapper package only, reapply those reviewed changes, and update
   the revision and checksums here and in the root manifests. Do not copy the
   BoringSSL submodule into this directory.

4. Prove Cargo selected one wrapper and that `btls-sys` and `tokio-btls` still
   resolve to the reviewed upstream revision:

   ```sh
   cargo tree -i btls --locked
   cargo tree -i btls-sys --locked
   cargo tree -i tokio-btls --locked
   ```

## Required checks

```sh
cargo fmt --manifest-path vendor/btls/Cargo.toml --all --check
cargo clippy --manifest-path vendor/btls/Cargo.toml --all-targets --features prefix-symbols -- -D warnings
cargo test --manifest-path vendor/btls/Cargo.toml ssl::test::alps
cargo +1.85.0 check --manifest-path vendor/btls/Cargo.toml --all-targets --features prefix-symbols
```

Do not replace the feature selection with `--all-features`: upstream declares
`fips` and `rpk` mutually exclusive. `prefix-symbols` is the configuration used
by Phantom on Linux. Omit it on Apple platforms, matching Phantom's
target-specific dependency selection; upstream currently skips the archive
rewrite needed to link prefixed symbols there. The scheduled probe runs on
Linux and therefore uses `prefix-symbols`.
