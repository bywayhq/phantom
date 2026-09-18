# Contributing

This guide is for people proposing or implementing changes to Phantom. Before
starting, read [Design](docs/design.md) for the project invariants,
[Coverage](docs/coverage.md) for the current boundary, and
[Validation](docs/validation.md) for the evidence model.

Report suspected vulnerabilities through [the security process](SECURITY.md),
not a public issue.

## Before implementation

State four things:

1. The observable acceptance criteria.
2. What is intentionally out of scope.
3. The files or modules the change will own.
4. The commands, fixtures, or captures that will prove it works.

Investigate uncertain protocol behavior before editing. Substantial
wire-sensitive changes need retained evidence; live services may supplement
local proof but cannot be the only proof.

## Change discipline

- Implement the smallest complete vertical slice.
- Keep unrelated formatting, renames, dependency updates, and cleanup out of
  the change.
- Preserve observable ordering and fail explicitly when a requested protocol,
  route, or fingerprint cannot be honored.
- Do not expose configuration until it is applied, validated, and tested.
- Keep recoverable input and network failures panic-free.
- Update the relevant guide, coverage contract, or design boundary when public
  behavior changes.

## Tests and evidence

Tests should describe observable behavior. A wire-sensitive change normally
needs a deterministic local test or capture fixture. Minimize adversarial or
fuzz failures into ordinary regressions.

Run the primary gates from the repository root:

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
```

Changes under `scripts/capture` also run:

```console
uvx ruff@0.16.7 check scripts/capture
uvx ruff@0.16.7 format --check scripts/capture
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  python -m unittest discover -s scripts/capture/tests -p 'test_*.py'
```

Run `scripts/ci/check-vendor.sh` for every vendored package you change.

## Pull requests

Keep commits focused and use an intent-first Conventional Commit subject, such
as `fix(http2): reject conflicting settings`. In the pull request:

- explain the user- or peer-visible outcome;
- list non-goals and unresolved uncertainty;
- identify the wire evidence when applicable;
- record the exact checks run and their results; and
- call out new dependencies, patches, unsafe code, fallbacks, or security
  implications.

A passing branch is not enough when a public option is unused, a fixture masks
meaningful variance, or a failure silently changes the selected path.
