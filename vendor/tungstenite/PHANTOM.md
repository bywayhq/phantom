# Phantom vendor notes: tungstenite

**Audience:** maintainers auditing or refreshing Phantom's WebSocket engine.
This file records provenance, local behavior changes, and the replay check. It
is not integration documentation.

The files listed in `patches/series` are the canonical local changes, in
application order. Change those patches and replay them; do not make an
unrecorded edit to the vendored crate.

## Publish identity

`publish-identity.patch` is always the last entry in `patches/series`. It
renames the package (`tungstenite` becomes `phantom-tungstenite` at
`0.30.0-phantom.1`), keeps the upstream library name so source, tests, and
examples are unchanged, and points the repository metadata at Phantom. It
removes the upstream documentation link, keeps Cargo's reserved archive files
out of the packaged crate, and records the upstream package, version, and
source archive under `[package.metadata.phantom]`. It changes no Rust source.

Phantom depends on this package only through the renamed package with an exact
version and a path, so the stock package cannot be selected in its place and no
root `[patch]` table is required. When refreshing, regenerate this patch after
the source patches. Increase the `-phantom.N` suffix whenever the fork's
content changes without an upstream version change, and update the exact pins
in the root `Cargo.toml` and in every renamed dependent.

## Upstream baseline

Upstream: `tungstenite` 0.30.0 from crates.io.

- Crates.io archive SHA-256:
  `e48ac77174b19c110a50ab2128b24215ac9cb40e0e12e093fb602d175c569d22`
- Upstream repository: <https://github.com/snapview/tungstenite-rs>
- Upstream licenses remain in `LICENSE-APACHE` and `LICENSE-MIT`.

## Why this patch exists

The ordered patch series adds RFC 7692 `permessage-deflate` support derived
from upstream pull request 561, keeps frame and message payloads out of logs
and errors, makes client masking entropy failure an ordinary result, and
reports forbidden peer Close codes instead of rewriting them. A small
integration patch exposes ordered negotiation for Phantom's custom handshake,
rejects terminal raw-DEFLATE streams, and keeps an 8-bit negotiated window
within its wire bound. The final default-preserving patch adds an opt-in
per-message data fragment count, rejects overflow before decompression or
reassembly, and makes that receive failure terminal. The `deflate` feature
enables only its codec and HTTP value types; the separate `handshake` feature
still owns tungstenite's built-in handshake implementation.

## Required check

`scripts/ci/check-vendor.sh tungstenite` downloads the checksummed upstream
crate, replays every entry in `patches/series`, and compares the result with
this directory.
