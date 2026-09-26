# Agent working agreement

This file applies to the entire repository. It is for coding agents and their
human integrators, whatever the tool. Package-specific `vendor/*/PHANTOM.md`
files define how to audit and refresh vendored dependencies; they add to, but
do not replace, this agreement. [CLAUDE.md](CLAUDE.md) imports this file and
adds only Claude Code notes.

An agent that uses Phantom as a library, rather than changing it, should read
[`llms.txt`](llms.txt) instead.

## Quick reference

- Format with `cargo fmt` or `cargo fmt --check`. Never add `--all`: it also
  formats local path dependencies and rewrites the vendored forks.
- When more than one worktree is active, run each Cargo command through
  `scripts/dev/with-cargo-lock.sh` ([usage](scripts/dev/README.md#cargo-lock)).
- Check each touched vendored package with `scripts/ci/check-vendor.sh
  <package>`; on Windows use the Git settings under
  [Windows hosts](#windows-hosts).
- Documentation follows
  [Writing the documentation](docs/internals/documentation.md); check it with
  `python scripts/docs/check_docs.py`.
- The integration owner runs the full gate with `scripts/dev/gate.sh`; a
  lane may run `scripts/dev/gate.sh --quick` before handoff. See
  [Verification and handoff](#verification-and-handoff).

## Before editing

State the observable acceptance criteria, non-goals, owned files, and intended
verification. Investigate uncertain protocol behavior before implementing it.
Preserve unrelated work in a dirty checkout and avoid cleanup outside the task.

## Lanes and worktrees

The root task is the integration owner. Subagents own bounded, non-overlapping
files and do not independently merge, push, release, or change repository
settings. Shared manifests and central public APIs remain with the integration
owner unless explicitly delegated.

Use a sibling worktree only when independent work can proceed concurrently.
[Development helpers](scripts/dev/README.md#parallel-lanes) has the commands.

- A lane is `../phantom-worktrees/<lane>` on branch `lane/<lane>`, created
  from `main` by the integration owner. One agent owns each worktree and
  branch, and never edits the integration checkout or another lane.
- Serialize Cargo across worktrees with the lock helper. A lane normally stops
  after source and static checks; the integration checkout owns workspace
  compilation and the full gate. A lane may run `scripts/dev/gate.sh --quick`
  as its focused pre-handoff check; it builds in the worktree's
  `target/gate/lint` and `target/gate/test`, beside `target/debug`, so budget
  the disk for them. A focused pre-integration build, when assigned, also
  uses the worktree's own `target/`. Never share a Cargo target directory
  between divergent worktrees.
- A lane commits in logical steps and hands off; it does not rebase onto or
  merge into `main` itself.
- The integration owner rebases the lane onto `main`, reviews every commit,
  runs the full gate on the rebased branch, reads the gate output, and only
  then fast-forwards `main` with `git merge --ff-only`. Remove an integrated
  worktree and its branch promptly.

## Engineering constraints

- Implement the smallest complete vertical slice.
- Prefer concrete Rust types and functions over speculative abstractions.
- Expose configuration only when it is applied and verified.
- Keep client-family identity in profiles, never transport conditionals.
- Preserve observable ordering when it is part of the wire fingerprint.
- Never silently change protocol, route, or fingerprint as a fallback.
- Return recoverable input and network failures; runtime library code must not
  panic for them.
- Unsafe code is forbidden. The one exception is the private `backend` FFI
  module of `phantom-quic-btls`, which documents every unsafe block; see
  [Design](docs/explanation/design.md#unsafe-code). Adding unsafe code anywhere else
  requires a new documented and audited FFI boundary.
- Change a vendored crate only through its `patches/series`, as its
  `PHANTOM.md` describes; never make an unrecorded edit under `vendor/`.

## Code and documentation

- Name modules after protocol or domain concepts; do not create catch-all
  `common`, `helpers`, or `utils` modules.
- Keep private helpers with their owner. Extract a module only when it has a
  distinct responsibility, and keep the public module tree shallow.
- Move substantial tests beside the implementation in `tests.rs` or `tests/`.
  Test names describe observable behavior.
- Comments explain invariants, safety conditions, wire citations, or
  non-obvious constraints. Put history and extended rationale in documentation.
- Keep fixtures machine-focused; place capture rationale and reproduction
  commands in adjacent documentation.
- Update public documentation and compile-check examples when behavior or APIs
  change. Do not claim unimplemented or unverified support.
- Add a `CHANGELOG.md` entry under `Unreleased` for every user-visible change.
  A breaking change also needs a "Migrate:" note that names the old and new
  API. Mark a breaking commit with `!` in its subject.
- Write documentation to
  [Writing the documentation](docs/internals/documentation.md): one reader and
  one job per page, and no stock phrases or other machine-written tells.

## Commits

- Use an intent-first Conventional Commit subject in the imperative mood,
  under 72 characters, such as `fix(http2): reject conflicting settings`.
- Do not add `Co-Authored-By` trailers for AI tools, `Claude-Session`
  trailers, or agent session links to commits or pull requests, even when a
  tool suggests them. Credit human co-authors normally.
- Never push, merge, release, or change repository settings unless the human
  integrator asks for it.

## Windows hosts

- `core.autocrlf=true` is supported: `.gitattributes` keeps `fixtures/` and
  `vendor/` byte-exact. Do not rewrite line endings there.
- Run `scripts/ci/*.sh` from Git Bash with CRLF conversion off and symlinks on
  for the child Git processes:

  ```sh
  GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=core.autocrlf GIT_CONFIG_VALUE_0=false \
    GIT_CONFIG_KEY_1=core.symlinks GIT_CONFIG_VALUE_1=true \
    scripts/ci/check-vendor.sh <package>
  ```

- Windows reserves UDP ports 49841 to 50959 on the development host
  (`netsh int ipv4 show excludedportrange protocol=udp`). Bind port 0 in
  tests and captures rather than a fixed port.
- Tests bind loopback addresses only, so Windows Defender Firewall does not
  prompt for each rebuilt test binary. A test that binds `0.0.0.0` or `::`,
  directly or through a client socket aimed at a loopback peer, is a bug.
- A refused loopback TCP connect takes about two seconds on Windows instead of
  failing at once. Allow for it in timeouts and retry tests.
- A peer that goes away can surface as `ConnectionAborted`, not only
  `ConnectionReset` or `BrokenPipe`. Tests that expect a disconnect accept all
  three.

## Verification and handoff

Run the narrowest relevant checks while iterating, then the applicable gates
from [CONTRIBUTING.md](CONTRIBUTING.md). `scripts/dev/gate.sh` runs the full
integration gate with independent steps in parallel, each Cargo step through
the lock helper and in its own target directory, and prints a table of step
results. `scripts/dev/gate.sh --quick` runs formatting, Clippy, the tests of
the changed crates and their dependents, and the docs checker, for a lane.
[Development helpers](scripts/dev/README.md#integration-gate) describes both.

The script runs these commands, which remain the reference for the gate:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --all-targets --all-features --locked
cargo test --doc --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.88.0 check --workspace --all-targets --locked
uvx ruff@0.16.8 check scripts/capture scripts/conformance scripts/docs
uvx ruff@0.16.8 format --check scripts/capture scripts/conformance scripts/docs
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  --with h2==4.4.1 --with hpack==4.2.0 \
  python -m unittest discover -s scripts/capture/tests -p 'test_*.py'
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  python -m unittest discover -s scripts/conformance/tests -p 'test_*.py'
uv run --no-project --python 3.10 \
  python -m unittest discover -s scripts/docs/tests -p 'test_*.py'
uv run --no-project --python 3.10 python scripts/docs/check_docs.py
```

nextest runs each test in its own process and does not run doctests, hence
the separate `cargo test --doc`; without nextest, `cargo test --workspace
--all-targets --all-features --locked` runs the same tests. The script also
runs the fuzz crate's Clippy and tests, the optional feature rows of the CI
Features and MSRV jobs, and `scripts/ci/check-tool-pins.sh`.

Read the output of every gate command. A command list joined with `;` or
piped through `tail` or `grep` reports the status of its last command, not of
Cargo, so search the output for `error`, `FAILED`, and `warning` before
declaring success or merging. `gate.sh` searches each step's log for these
and marks a step `FLAG` when its log shows one; read the flagged log.

Run `scripts/ci/check-vendor.sh <package>` for every vendored package touched.
[CONTRIBUTING.md](CONTRIBUTING.md) lists the conditional ShellCheck, fuzz, and
feature-matrix checks. The CI workflow is authoritative when its matrix
differs from this summary: its MSRV job also checks each optional feature
combination on Rust 1.88, and its platform jobs repeat the MSRV check for
`phantom-net` and `phantom-quic-btls` on macOS and Windows.

Hand off the exact commands and results, relevant evidence, and unresolved
uncertainty. A green agent branch is not integration proof.
