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
carries no behavioral source change: its identity patch renames the package and
points its `tungstenite` dependency at `phantom-tungstenite` by exact version
and path. Phantom uses only `WebSocketStream`; replacing the adapter with
Phantom-owned code would add maintenance without changing the wire behavior.

## Handshake waker gate

Phantom builds the adapter without default features, so the `handshake`
feature is off. Upstream 0.30.0 still compiles the crate-private `SetWaker`
trait and its `AllowStd` implementation, whose only users are
`handshake`-gated, and rustc reports `trait SetWaker is never used`.
`handshake-set-waker.patch` gates the trait and its implementation behind the
same `handshake` feature. Builds with that feature compile the same code as
upstream. Upstream `master` still has the ungated trait as of this patch; drop
the patch when a refresh brings an upstream fix.

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
