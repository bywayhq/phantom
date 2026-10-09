# Phantom vendor notes: tokio-btls

**Audience:** maintainers auditing or refreshing Phantom's async TLS adapter.
This file records provenance, the local changes, and the replay check. It is
not integration documentation.

The files listed in `patches/series` are the canonical local changes, in
application order. Change those patches and replay them; do not make an
unrecorded edit to the vendored crate.

## Upstream baseline

This directory is the `tokio-btls` package from the reviewed btls dependency
fork, the same revision that supplies `btls-sys`.

- Reviewed dependency fork: <https://github.com/bywayhq/btls>
- Reviewed dependency commit: `f478ea16a4b2f6ebbd221ce7cafdec10a32028eb`
- Source archive:
  <https://codeload.github.com/bywayhq/btls/tar.gz/f478ea16a4b2f6ebbd221ce7cafdec10a32028eb>
- Complete source archive SHA-256:
  `e9c2fd9f12a995afc8adcd31b86effa9d767570d9e4e52efee68b5ffc2d626cf`
- The `tokio-btls` tree is identical in this archive and in the earlier
  reviewed commit `c48fddb13539e06fadedfac6039570598ff89864`: the commits
  between them change only `btls-sys`, its native patches, the fork's CI, the
  `btls` wrapper, and its tests. Only the archive and its checksum moved with
  the `btls-sys` pin, and `publish-identity.patch` follows the `phantom-btls`
  version; the other patches are unchanged.
- Upstream licenses remain in `LICENSE-APACHE` and `LICENSE-MIT`.

## Why this fork exists

Phantom patches the `btls` wrapper, and `tokio-btls` depends on it. Without a
fork, `tokio-btls` would resolve the wrapper from the dependency fork instead of
`vendor/btls`.

- `standalone-manifest.patch` materializes the workspace-inherited package and
  dependency fields from the fork's root manifest so the package builds
  outside that workspace.
- `early-data-reset.patch` adds `SslStream::ssl_mut`, as the synchronous
  `btls` stream has. Phantom's TCP client needs it to call
  `SslRef::reset_early_data_reject` after a server rejects its early data; the
  upstream adapter exposes only a shared reference. It is the one Rust source
  change.
- `publish-identity.patch` renames the package to `phantom-tokio-btls` at
  `0.5.6-phantom.6`, keeps the `tokio_btls` library name, points `btls` at
  `phantom-btls` by exact version and path, removes the upstream documentation
  link, keeps Cargo's reserved archive files out of the packaged crate, and
  records the upstream source under `[package.metadata.phantom]`.

`Cargo.lock` pins the standalone vendor check. It is packaging metadata and is
not part of the patches.

## Required check

`scripts/ci/check-vendor.sh tokio-btls` downloads the checksummed fork archive,
replays every entry in `patches/series` on its `tokio-btls` directory, compares
the result with this directory, and checks the crate against the renamed
`btls`.
