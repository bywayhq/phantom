# Contributing

Start with a small change, test the behavior it affects, and run the
relevant checks before opening a pull request. [AGENTS.md](AGENTS.md) is the
working agreement for humans and coding agents.

Report suspected vulnerabilities through [SECURITY.md](SECURITY.md).

## Development setup

Clone the repository and let rustup install the toolchain pinned in
`rust-toolchain.toml`:

```console
git clone https://github.com/bywayhq/phantom.git
cd phantom
cargo check -p phantom-http --all-features --locked
```

The native TLS build needs Git, CMake, Clang with `libclang`, and a C++ compiler.
Windows also needs NASM, the Visual C++ build tools, and the Windows SDK. Follow
[the build-tool setup](crates/phantom/src/docs/getting-started.md#install-the-build-tools)
if these are not installed.

For workspace tests, install the nextest version used by CI:

```console
cargo install --locked cargo-nextest@0.9.145
```

The Python tooling uses Python 3.10 and `uv`; Windows capture tests use the
interpreter pinned in `scripts/capture/windows-python-version.txt`. See
[Capture tools](scripts/capture/README.md) when recording browser evidence.

On Windows, run the shell scripts from Git Bash. Before checking a vendored
package, use the child Git settings under
[Windows hosts](AGENTS.md#windows-hosts) to preserve line endings and symlinks.

## Make a change

For a substantial change, open a
[proposal](https://github.com/bywayhq/phantom/issues/new?template=proposal.yml)
first. State the observable result, what is out of scope, and how you will check
it. Preserve unrelated work in a dirty checkout.

Follow the [engineering constraints](AGENTS.md#engineering-constraints).
Keep observable wire ordering, return recoverable errors, and verify that each
configuration option is applied. Do not add silent protocol, route, or
fingerprint fallbacks. Change a vendored fork through its `patches/series` and
follow that fork's `PHANTOM.md`.

Use [Development helpers](scripts/dev/README.md#parallel-lanes) for parallel
worktrees. Run Cargo through `scripts/dev/with-cargo-lock.sh` when several
worktrees are active. Never use `cargo fmt --all`: it formats vendored path
dependencies as well.

## Tests and evidence

Test observable behavior at the narrowest useful boundary. Keep a reduced fuzz
failure as a regression test. Wire-sensitive changes need deterministic local
proof; live services can supplement that proof.

- Put unit tests beside the code. Follow the test-size guidance in
  [AGENTS.md](AGENTS.md#code-and-documentation).
- Add integration cases to the existing
  [test binaries](scripts/dev/README.md#integration-test-binaries).
- Keep fixtures byte-exact, with capture provenance and reproduction commands
  in adjacent documentation.
- For performance claims, report a representative workload and the scope of the
  measurement.

## Run the checks

Use the focused tests for the code being changed while iterating. Before
integration, run the full gate:

```sh
scripts/dev/gate.sh
```

For a lane's focused check, use `scripts/dev/gate.sh --quick`. On Windows, add
`--linux` after changing Linux-only code so it is checked in WSL. The gate's
[usage and output](scripts/dev/README.md#integration-gate) explain the options;
[AGENTS.md](AGENTS.md#verification-and-handoff) lists the individual commands.
Read every failing or flagged step's log before reporting success.

| If the change touches | Also check |
| --- | --- |
| A vendored package | `scripts/ci/check-vendor.sh <package>` and the fork's `PHANTOM.md` |
| Shell scripts in CI, development, or release tooling | ShellCheck 0.11.0: `shellcheck scripts/ci/*.sh scripts/dev/*.sh scripts/release/*.sh` |
| `fuzz/` | `cargo fmt --manifest-path fuzz/Cargo.toml --check` and `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings` |
| Optional features | The affected combinations in [CI](.github/workflows/ci.yml), including MSRV rows |
| QUIC cryptography or TLS boundaries | The checks in [Sanitizers](.github/workflows/sanitizers.yml) |

nextest does not run doctests. The gate separately runs `cargo test --doc` to
check Rust examples, including the README and the published guides.

## Write documentation

User documentation lives beside the public crate:

- `README.md` introduces Phantom and shows one request.
- `crates/phantom/src/docs/overview.md` is the docs.rs landing page.
- The four other Markdown pages in that directory teach setup, profiles,
  requests and responses, and proxies.
- `crates/phantom/src/guide.rs` exposes those pages as rustdoc modules.
- API details belong beside their types and methods. Runnable programs belong
  in `crates/phantom/examples/`.

Write for the task the reader is trying to complete. Give a working example,
explain the choices it makes, and link to details rather than duplicating an
option catalog. Avoid claims of browser fidelity without retained evidence.
Use rustdoc links such as `[Client](crate::Client)` in crate Markdown.

Run `python scripts/docs/check_docs.py`, then compile the examples and guides:

```sh
scripts/dev/with-cargo-lock.sh cargo test -p phantom-http --doc --all-features --locked
scripts/dev/with-cargo-lock.sh cargo check -p phantom-http --examples --all-features --locked
RUSTDOCFLAGS="-D warnings" scripts/dev/with-cargo-lock.sh cargo doc -p phantom-http --all-features --no-deps --locked
```

Also check doctests without optional features when a snippet uses one. Add an
`Unreleased` entry to [CHANGELOG.md](CHANGELOG.md) for user-visible changes;
a breaking change needs a "Migrate:" note naming the old and new API.

## Continuous integration

[CI](.github/workflows/ci.yml) is authoritative for the checks and feature
matrix. The required status is `CI required`. Path classification is defined in
[`changed-paths.sh`](scripts/ci/changed-paths.sh), with cases in
[`test-changed-paths.sh`](scripts/ci/test-changed-paths.sh). Update them together.

Pull requests must pass the required checks. The repository requires signed
commits and linear history; the integrator fast-forwards approved work after
verification. Other workflows are advisory: read relevant sanitizer, fuzz, and
conformance results too. Maintainers can dispatch CI to run every job or apply
the `conformance` label to run the conformance suites.

## Commits and pull requests

Use an intent-first [Conventional Commit](https://www.conventionalcommits.org/)
subject under 72 characters, such as `fix(http2): reject conflicting settings`.
Keep commits focused. Do not add AI co-author or session trailers. Mark breaking
commits with `!`.

Fill in the [pull request template](.github/pull_request_template.md) with the
result, scope, exact verification commands and outcomes, and unresolved risks.
Do not push, merge, release, or change repository settings without the human
integrator's instruction.

## Licensing

Contributions are dual-licensed under [Apache-2.0](LICENSE-APACHE) and
[MIT](LICENSE-MIT), as described in [the README](README.md#contribution).
No CLA or DCO sign-off is required. Keep vendored license and notice files
unchanged, and record provenance for any copied code. Dependencies must fit the
allow list in `deny.toml`; CI checks it with `cargo deny check licenses`.
