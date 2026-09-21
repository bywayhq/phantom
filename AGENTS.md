# Agent working agreement

This file applies to the entire repository. It is for coding agents and their
human integrators. Package-specific `vendor/*/PHANTOM.md` files define how to
audit and refresh vendored dependencies; they add to, but do not replace, this
agreement.

## Before editing

State the observable acceptance criteria, non-goals, owned files, and intended
verification. Investigate uncertain protocol behavior before implementing it.
Preserve unrelated work in a dirty checkout and avoid cleanup outside the task.

The root task is the integration owner. Subagents own bounded, non-overlapping
files and do not independently merge, push, release, or change repository
settings. Shared manifests and central public APIs remain with the integration
owner unless explicitly delegated.

## Worktrees and builds

Use a sibling worktree under `../phantom-worktrees/` only when independent work
can proceed concurrently. One agent owns each worktree and branch. Remove an
integrated worktree promptly.

Serialize Cargo commands across agents through the integration owner. An agent
branch normally stops after source and static checks; the integration checkout
owns workspace compilation and broad gates. If a focused pre-integration build
is assigned, use that worktree's local `target/` directory. Never share a Cargo
target directory between divergent worktrees.

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
  [Design](docs/design.md#unsafe-code). Adding unsafe code anywhere else
  requires a new documented and audited FFI boundary.

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

## Verification and handoff

Run the narrowest relevant checks while iterating, then the applicable gates
from [CONTRIBUTING.md](CONTRIBUTING.md). The full integration gate is:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
uvx ruff@0.16.7 check scripts/capture scripts/conformance
uvx ruff@0.16.7 format --check scripts/capture scripts/conformance
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  --with h2==4.4.1 --with hpack==4.2.0 \
  python -m unittest discover -s scripts/capture/tests -p 'test_*.py'
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  python -m unittest discover -s scripts/conformance/tests -p 'test_*.py'
```

Run `scripts/ci/check-vendor.sh <package>` for every vendored package touched.
[CONTRIBUTING.md](CONTRIBUTING.md) lists the conditional ShellCheck, fuzz, and
feature-matrix checks. The CI workflow is authoritative when its matrix
differs from this summary: its MSRV job also checks each optional feature
combination on Rust 1.85, and its platform jobs repeat the MSRV check for
`phantom-net` and `phantom-quic-btls` on macOS and Windows.

Hand off the exact commands and results, relevant evidence, and unresolved
uncertainty. A green agent branch is not integration proof.
