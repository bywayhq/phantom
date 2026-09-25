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
- Reviewed dependency commit: `ce81167653e2d8878f2e9b2218a15b9bc8351a53`
- Source archive:
  <https://codeload.github.com/bywayhq/btls/tar.gz/ce81167653e2d8878f2e9b2218a15b9bc8351a53>
- Complete source archive SHA-256:
  `5f181d89782afdc03c775fc10c77612ab72eaabfd2f6b25c6a77602b3de086f5`
- Upstream licenses remain in `LICENSE-APACHE` and `LICENSE-MIT`.

## Why this fork exists

Phantom patches the `btls` wrapper, and `tokio-btls` depends on it. Without a
fork, `tokio-btls` would resolve the wrapper from the dependency fork instead of
`vendor/btls`. This fork carries no Rust source change.

- `standalone-manifest.patch` materializes the workspace-inherited package and
  dependency fields from the fork's root manifest so the package builds
  outside that workspace.
- `publish-identity.patch` renames the package to `phantom-tokio-btls` at
  `0.5.6-phantom.3`, keeps the `tokio_btls` library name, points `btls` at
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
