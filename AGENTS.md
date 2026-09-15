# Agent working agreement

The root task is the integration owner. Subagents work on bounded changes and do not independently merge, push, release, or change repository settings.

## Before editing

Every task must state its observable acceptance criteria, non-goals, owned files, and verification commands. Investigate uncertain protocol behavior before implementing it.

## Worktrees

Use sibling worktrees under `/Users/arya/Desktop/phantom-worktrees/` only when independent implementation can run concurrently. One agent owns each worktree and branch. Do not assign overlapping files to concurrent agents.

The integration owner retains shared manifests and central public API files unless ownership is explicitly delegated. Review and test changes after integration; a green agent branch is not phase completion.

## Engineering constraints

- Implement the smallest complete vertical slice.
- Prefer concrete Rust types and functions over speculative traits or frameworks.
- Do not expose configuration that is not applied and verified.
- Keep browser identity in profiles, never in transport conditionals.
- Preserve observable ordering when it is part of the wire fingerprint.
- Do not silently fall back to a different protocol or fingerprint.
- Runtime library code must not panic for recoverable input or network failures.
- Unsafe code is forbidden unless a future FFI crate explicitly documents and audits it.

## Module organization

- Name modules after protocol or domain concepts. Do not create catch-all `common`, `helpers`, or `utils` modules.
- Keep private helpers beside the type or operation that owns them. Extract a module when it gains a distinct responsibility, not merely to shorten a file.
- Keep the public module tree shallow. Backend-specific types and translation code remain private to their backend module.
- Move substantial tests into a sibling `tests.rs` or `tests/` module once they obscure the implementation. Test names describe observable behavior.
- Before extending a large module, decide whether the new behavior belongs to an existing responsibility or deserves a clearly named sibling module. Avoid both monolithic files and one-function files.

## Local checks

Run these before handing work back to the integration owner:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
```

Record the commands actually run, relevant evidence, and unresolved uncertainty in the handoff. Do not include unrelated cleanup.
