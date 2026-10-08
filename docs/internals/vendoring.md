# Vendored forks

Change a patched dependency through its recorded patches, then run its checks.
Phantom uses these copies for connection behavior the upstream APIs cannot set.

To use Phantom in an application, read
[Adding Phantom to a project](../guides/downstream.md).

## Vendored forks

The patched copies live under `vendor/` as renamed `phantom-*` packages.
An identity patch gives a package its `phantom-*` name and version.

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

Every fork keeps its upstream license files and library name. Fork versions
use the form `<upstream>-phantom.<n>`, and Phantom always pins them exactly.
[Design](../explanation/design.md#dependency-policy) states when a vendored
change is acceptable.

## Change or refresh a fork

Each fork starts with upstream source verified by checksum. The patches in
`patches/series` apply in order. Read its `vendor/*/PHANTOM.md` first for the
source revision, refresh steps and required checks.

1. Change a patch in the series, or add one, and replay the series. Never
   leave an unrecorded edit under `vendor/`.
2. Keep `publish-identity.patch` last in the series, and regenerate it after
   the source patches.
3. When the fork's content changes without an upstream version change, raise
   the `-phantom.<n>` suffix and update the exact pins in the root
   `Cargo.toml` and in each renamed dependent's identity patch.
4. Record the upstream version, checksum, and the reason for each patch in
   the package's `PHANTOM.md`.
5. Check that the fork matches its series:

   ```sh
   scripts/ci/check-vendor.sh <package>
   ```

   The script replays the series onto the upstream source, compares the
   result byte for byte with `vendor/`, and runs the package's focused checks.
   On Windows, run it with the Git settings in
   [AGENTS.md](../../AGENTS.md#windows-hosts).

A patch that no longer applies cleanly needs to be regenerated. Do not apply
it with rejected hunks. Do not run `cargo fmt --all`, which
reformats every fork. `scripts/ci/report-upstream-freshness.sh` reports
upstream releases newer than the vendored baselines.

## Downstream CI

A downstream build needs Phantom's forks to keep the patched connection
behavior. The `Downstream` job checks the dependency graph and builds two
test applications.

1. `cargo deny --locked check bans advisories licenses` checks the workspace
   graph. The `bans` check rejects the stock package names listed in
   `deny.toml`.
2. `scripts/ci/check-downstream.sh path git` builds two test applications.
   Each declares Phantom with one dependency line and no `[patch]` table: one
   as a path dependency, one as a git dependency. The git consumer points at
   a local snapshot commit of the checkout, not the GitHub remote.

For each application, the script runs `cargo generate-lockfile`,
`cargo metadata --all-features --locked`, and
`cargo check --all-features --locked`. It fails when any of these hold:

- a stock package appears in the graph.
- a `phantom-*` fork is missing, appears more than once, or resolves from a
  source other than the application's own (path or git).
- `btls-sys` resolves from anything but the reviewed fork revision.

## Next

- [HTTP/3 internals](http3.md#vendored-seams): why the `h3` and Quinn forks
  carry their patches.
- [CONTRIBUTING.md](../../CONTRIBUTING.md#run-the-checks): the gate to run
  after `check-vendor.sh`.
