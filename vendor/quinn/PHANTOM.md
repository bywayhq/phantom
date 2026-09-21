# Phantom vendor notes: quinn

**Audience:** maintainers auditing or refreshing Phantom's QUIC endpoint
dependency. This file records provenance, the local change, and the replay
check. It is not integration documentation.

The files listed in `patches/series` are the canonical local changes, in
application order. Change those patches and replay them; do not make an
unrecorded edit to the vendored crate.

## Upstream baseline

Upstream: `quinn` 0.11.12 from crates.io.

- Crates.io archive SHA-256:
  `4051e23e9185c255a7e33ef59cdbca87a22d359052eecd22fc6b901fb37d9d11`
- Upstream repository: <https://github.com/quinn-rs/quinn>
- Upstream licenses remain in `LICENSE-APACHE` and `LICENSE-MIT`.

## Why this fork exists

Phantom patches `quinn-proto`, and `quinn` depends on it. A stock `quinn` would
pull the stock `quinn-proto` from crates.io, which has different transport
parameter and key-update behavior. This fork carries no source change: its only
patch renames the package and points its `proto` dependency at
`phantom-quinn-proto` by exact version and path.

## Publish identity

`publish-identity.patch` renames the package to `phantom-quinn` at
`0.11.12-phantom.1`, keeps the `quinn` library name, and points the repository
metadata at Phantom. It removes the upstream documentation link, keeps Cargo's
reserved archive files out of the packaged crate, records the upstream source
under `[package.metadata.phantom]`. The standalone `Cargo.lock` is packaging
metadata outside the patches and follows the renamed dependency. When
refreshing, keep the `phantom-quinn-proto` pin identical to the root
`Cargo.toml` and increase the `-phantom.N` suffix whenever the fork's content
changes without an upstream version change.

## Required check

`scripts/ci/check-vendor.sh quinn` downloads the checksummed upstream crate,
replays every entry in `patches/series`, compares the result with this
directory, and checks the crate against the renamed `quinn-proto`.
