---
name: vendor-refresh
description: Change, refresh, or audit a vendored fork under vendor/ (btls, h3, http2, quinn, quinn-proto, tokio-btls, tokio-tungstenite, tungstenite, wreq-proto) through its canonical patch series, then prove it with scripts/ci/check-vendor.sh.
argument-hint: "<package>"
---

# Vendored fork changes

Package: `$ARGUMENTS`. `vendor/<package>/PHANTOM.md` is the authority for
provenance, the refresh procedure, and the package's required checks. Read it
first; this skill only lists the invariants that apply to every fork.

## Invariants

- The files in `vendor/<package>/patches/series` are the canonical local
  changes, in order. Change a patch and replay the series; never leave an
  unrecorded edit in the vendored tree.
- `publish-identity.patch` stays the last entry. Regenerate it after the
  source patches. It renames the package to `phantom-<name>` and changes no
  Rust source.
- Increase the `-phantom.N` suffix whenever the fork's content changes without
  an upstream version change, and update the exact `=` pins in the root
  `Cargo.toml` and in every renamed dependent's identity patch.
- A patch that no longer applies cleanly is evidence that upstream changed.
  Regenerate it; never apply with rejected hunks or fuzz.
- Keep the `Cargo.lock` diff to the refreshed package entries and prove the
  selected source with `cargo tree -i phantom-<name> --locked`.
- Do not run `cargo fmt --all` from the workspace; it reformats every fork.
  Vendored formatting is checked per package by `check-vendor.sh`.

## Verify

Run from Git Bash at the repository root. On Windows keep CRLF conversion off
and symlinks on for the child Git processes:

```sh
GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=core.autocrlf GIT_CONFIG_VALUE_0=false \
  GIT_CONFIG_KEY_1=core.symlinks GIT_CONFIG_VALUE_1=true \
  scripts/dev/with-cargo-lock.sh scripts/ci/check-vendor.sh <package>
```

The script downloads the checksummed upstream source, replays the series,
compares the result byte-for-byte with `vendor/<package>`, and runs the
package's focused Cargo checks. Record the upstream version, checksum, and the
reason for each patch in `PHANTOM.md`, then run the workspace gate from
`AGENTS.md`. `scripts/ci/report-upstream-freshness.sh` reports upstream
releases newer than the vendored baselines.
