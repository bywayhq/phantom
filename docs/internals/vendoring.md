# Vendored forks

Phantom patches several dependencies to control wire behavior that their
upstream APIs cannot express. The patched copies live under `vendor/` as
renamed `phantom-*` packages. This page lists them and describes how CI proves
that a downstream build uses only these forks.

If you only want to add Phantom to a project, read
[Adding Phantom to a project](../guides/downstream.md) instead.

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

"Identity" is the rename to a `phantom-*` package name and version.

Each fork is its checksummed upstream source plus the ordered patches listed
in its `patches/series`. To prove that a fork matches its series, run:

```sh
scripts/ci/check-vendor.sh <package>
```

The script replays the series onto the upstream source and compares the
result with `vendor/`. On Windows, run it with the Git settings in
[AGENTS.md](../../AGENTS.md#windows-hosts).

Every fork keeps its upstream license files and library name. Fork versions
use the form `<upstream>-phantom.<n>`, and Phantom always pins them exactly.

Each `vendor/*/PHANTOM.md` explains how to audit and refresh that package.
[Design](../explanation/design.md#dependency-policy) states when a vendored
change is acceptable.

## Downstream CI

A downstream build must never pick up a stock package in place of a fork,
because the stock package would silently drop the patched wire behavior.
The `Downstream` job in Phantom's CI checks this in two steps.

1. `cargo deny --locked check bans advisories` checks the workspace graph.
   The `bans` check rejects the stock package names listed in `deny.toml`.
2. `scripts/ci/check-downstream.sh path git` builds two throwaway consumers.
   Each declares Phantom with one dependency line and no `[patch]` table: one
   as a path dependency, one as a git dependency. The git consumer points at
   a local snapshot commit of the checkout, not the GitHub remote.

For each consumer the script runs `cargo generate-lockfile`,
`cargo metadata --all-features --locked`, and
`cargo check --all-features --locked`. It fails when any of these hold:

- a stock package appears in the graph;
- a `phantom-*` fork is missing, appears more than once, or resolves from a
  source other than the consumer's own (path or git);
- `btls-sys` resolves from anything but the reviewed fork revision.
