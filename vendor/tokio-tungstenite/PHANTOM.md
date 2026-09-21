# Phantom vendor notes: tokio-tungstenite

**Audience:** maintainers auditing or refreshing Phantom's async WebSocket
adapter. This file records provenance, the local change, and the replay check.
It is not integration documentation.

The files listed in `patches/series` are the canonical local changes, in
application order. Change those patches and replay them; do not make an
unrecorded edit to the vendored crate.

## Upstream baseline

Upstream: `tokio-tungstenite` 0.30.0 from crates.io.

- Crates.io archive SHA-256:
  `17a073bfed563fa236697a068031408a93cd9522e08abf9933ead3e73411bd71`
- Upstream repository: <https://github.com/snapview/tokio-tungstenite>
- Upstream license remains in `LICENSE`.

## Why this fork exists

Phantom patches `tungstenite`, and `tokio-tungstenite` depends on it. A stock
`tokio-tungstenite` would pull the stock `tungstenite` from crates.io. This fork
carries no source change: its only patch renames the package and points its
`tungstenite` dependency at `phantom-tungstenite` by exact version and path.
Phantom uses only `WebSocketStream`; replacing the adapter with Phantom-owned
code would add maintenance without changing the wire behavior.

## Publish identity

`publish-identity.patch` renames the package to `phantom-tokio-tungstenite` at
`0.30.0-phantom.1`, keeps the `tokio_tungstenite` library name, and points the
repository metadata at Phantom. It removes the upstream documentation link,
adds this file and the patches to the packaged crate, records the upstream
source under `[package.metadata.phantom]`. The standalone `Cargo.lock` is
packaging metadata outside the patches. When refreshing, keep the
`phantom-tungstenite` pin identical to the root `Cargo.toml`.

## Required check

`scripts/ci/check-vendor.sh tokio-tungstenite` downloads the checksummed
upstream crate, replays every entry in `patches/series`, compares the result
with this directory, and checks the crate against the renamed `tungstenite`.
