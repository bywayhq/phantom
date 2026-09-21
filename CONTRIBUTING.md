# Contributing

This guide is for people proposing or implementing changes to Phantom. Before
starting, read [Design](docs/explanation/design.md) for the project invariants,
[Coverage](docs/reference/coverage.md) for the current boundary, and
[Validation](docs/explanation/validation.md) for the evidence model.

Report suspected vulnerabilities through [the security process](SECURITY.md),
not a public issue.

## Development setup

The repository pins its development toolchain. Native TLS builds require Git,
CMake, Clang, and a C++ toolchain; Windows also requires NASM and Visual C++
build tools. Python 3.10 and `uv` are needed only for capture and conformance
tooling. See the platform jobs in [CI](.github/workflows/ci.yml) for the exact
prerequisite checks.

### Windows

Install the native prerequisites with `winget` from PowerShell:

```powershell
winget install --id Git.Git --exact
winget install --id Rustlang.Rustup --exact
winget install --id NASM.NASM --exact
winget install --id Kitware.CMake --exact
winget install --id LLVM.LLVM --exact
winget install --id astral-sh.uv --exact
winget install --id Microsoft.VisualStudio.2022.BuildTools --exact `
  --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

The Build Tools workload provides the MSVC compiler and Windows SDK. The NASM
and LLVM installers may not update `PATH`; make `nasm`, `cmake`, and `clang`
resolvable in the shell that runs Cargo (for example by adding
`C:\Program Files\NASM` and `C:\Program Files\LLVM\bin`). The native TLS build
uses LLVM's `libclang` for bindings; set `LIBCLANG_PATH` to LLVM's `bin`
directory if it is not found.

`rust-toolchain.toml` installs the pinned development toolchain on first use.
Install the minimum supported toolchain separately for the MSRV checks:

```powershell
rustup toolchain install 1.85.0 --profile minimal
```

Run `scripts/ci/*.sh` from Git Bash. Those scripts fetch upstream sources and
compare them byte-for-byte with `vendor/`, so run them with CRLF conversion
disabled and symlinks enabled for the child Git processes:

```sh
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=core.autocrlf GIT_CONFIG_VALUE_0=false
export GIT_CONFIG_KEY_1=core.symlinks GIT_CONFIG_VALUE_1=true
scripts/ci/check-vendor.sh btls
```

A checkout with `core.autocrlf=true` is otherwise supported: `.gitattributes`
keeps `vendor/` and `fixtures/` byte-exact.

### First build

Build the public crate before making a change:

```console
cargo check -p phantom-http --all-features --locked
```

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

| Change | Minimum proof |
| --- | --- |
| Public API or policy | Focused tests, rustdoc, and the relevant guide or coverage update |
| Wire-visible behavior | Retained evidence plus a deterministic differential |
| Parser or peer handling | Boundary tests and an adversarial regression |
| Dependency or vendor patch | Canonical patch replay, focused upstream tests, and provenance update |
| Hot path | Representative benchmark or profile with the claimed scope stated |

Run the primary gates from the repository root. They are the Cargo half of
the integration gate in [AGENTS.md](AGENTS.md); keep the two lists in step.

```console
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
```

`cargo test` includes doctests that compile the Rust examples in `README.md`,
`docs/getting-started.md`, `docs/guides/client.md`, `docs/sse.md`, and
`docs/guides/websocket.md`; a guide example that no longer compiles fails the gate.
The MSRV line is CI's `MSRV` job; that job also checks each optional
`phantom-http` feature combination on Rust 1.85.

Changes under `scripts/capture` or `scripts/conformance` also run the commands
below. CI installs the same test dependencies from the hash-pinned
`scripts/requirements.txt`, generated from `scripts/requirements.in` with the
command recorded in its header; keep the `--with` pins here in step with it.

```console
uvx ruff@0.16.7 check scripts/capture scripts/conformance
uvx ruff@0.16.7 format --check scripts/capture scripts/conformance
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  --with h2==4.4.1 --with hpack==4.2.0 \
  python -m unittest discover -s scripts/capture/tests -p 'test_*.py'
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  python -m unittest discover -s scripts/conformance/tests -p 'test_*.py'
```

Run `scripts/ci/check-vendor.sh` for every vendored package you change.
Shell changes under `scripts/ci` or `scripts/release` must pass ShellCheck
0.11.0 (`shellcheck scripts/ci/*.sh scripts/release/*.sh`). Changes under
`fuzz/` must pass `cargo fmt --manifest-path fuzz/Cargo.toml --check` and
`cargo clippy --manifest-path fuzz/Cargo.toml --bins --locked -- -D warnings`.
The optional-feature matrix and scheduled interoperability suites run in CI;
run the affected feature combinations locally before requesting review.

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
