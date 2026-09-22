# Vendored forks

This page is for maintainers. It describes the patched dependencies that live
under `vendor/` and how CI keeps downstream builds free of the stock packages.
Users adding Phantom to a project need only
[Adding Phantom to a project](../guides/downstream.md).

## Vendored forks

| Package | Upstream | Changes |
| --- | --- | --- |
| `phantom-btls` | `btls` wrapper 0.5.6 | Source patches and identity; see `vendor/btls/PHANTOM.md` |
| `phantom-tokio-btls` | `tokio-btls` 0.5.6 | Standalone manifest and identity only |
| `phantom-h3`, `phantom-h3-datagram`, `phantom-h3-quinn` | Hyperium `h3` commit `1f3d529` | Source patches and identity; see `vendor/h3/PHANTOM.md` |
| `phantom-http2` | `http2` 0.5.20 | Source patches and identity; see `vendor/http2/PHANTOM.md` |
| `phantom-quinn` | `quinn` 0.11.12 | Identity only |
| `phantom-quinn-proto` | `quinn-proto` 0.11.18 | Source patches and identity; see `vendor/quinn-proto/PHANTOM.md` |
| `phantom-tungstenite` | `tungstenite` 0.30.0 | Source patches and identity; see `vendor/tungstenite/PHANTOM.md` |
| `phantom-tokio-tungstenite` | `tokio-tungstenite` 0.30.0 | Warning-only source patch and identity; see `vendor/tokio-tungstenite/PHANTOM.md` |
| `phantom-wreq-proto` | `wreq-proto` 0.2.5 | Source patches and identity; see `vendor/wreq-proto/PHANTOM.md` |

Every fork is its checksummed upstream source plus the ordered patches in its
`patches/series`; `scripts/ci/check-vendor.sh <package>` replays and compares
them. Each fork keeps its upstream license files and library name. Fork
versions use the form `<upstream>-phantom.<n>` and are always pinned exactly.

Each `vendor/*/PHANTOM.md` defines how to audit and refresh that package. The
rules for accepting a vendored change are in
[Design](../explanation/design.md#dependency-policy).

## Downstream CI

Phantom's CI `Downstream` job runs `cargo deny --locked check bans` against
the stock names in `deny.toml`, then `scripts/ci/check-downstream.sh path git`.
That script builds throwaway path and git consumers that each declare Phantom
with one dependency line. For each it runs `cargo generate-lockfile`,
`cargo metadata --all-features --locked`, and `cargo check --all-features
--locked`, and fails if any stock package appears, any `phantom-*` fork
resolves from an unexpected source, or `btls-sys` resolves from anything but
the reviewed fork revision. The git consumer uses a local snapshot commit of
the checkout, not the GitHub remote.
