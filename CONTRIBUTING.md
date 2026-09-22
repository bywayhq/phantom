# Contributing

Thank you for helping improve Phantom. This guide is for people proposing or
implementing changes. It covers setup, how to scope a change, the checks a
change must pass, and how to open a pull request.

Report suspected vulnerabilities through [the security process](SECURITY.md),
not a public issue.

## Quick start

1. Install the [prerequisites](#development-setup) for the native BoringSSL
   build.
2. Clone and build the public crate:

   ```console
   git clone https://github.com/bywayhq/phantom.git
   cd phantom
   cargo check -p phantom-http --all-features --locked
   ```

3. Read [Design](docs/explanation/design.md) for the project invariants,
   [Coverage](docs/reference/coverage.md) for the current boundary, and
   [Validation](docs/explanation/validation.md) for the evidence model.
4. For anything larger than a small fix, open a
   [proposal](https://github.com/bywayhq/phantom/issues/new?template=proposal.yml)
   first so the scope can be agreed before you write code.
5. Make the change, run the [gates](#required-checks), and open a pull request
   using the [checklist](#pull-requests).

## Development setup

The repository pins its development toolchain in `rust-toolchain.toml`, which
installs on first use. Native TLS builds require Git, CMake, Clang, and a C++
toolchain; Windows also requires NASM and Visual C++ build tools. Python 3.10
and `uv` are needed only for capture and conformance tooling. See the platform
jobs in [CI](.github/workflows/ci.yml) for the exact prerequisite checks.

Install the minimum supported toolchain separately for the MSRV checks:

```console
rustup toolchain install 1.85.0 --profile minimal
```

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

## Before implementation

State four things, in the proposal or the pull request:

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
- Do not add unsafe code outside the audited FFI module described in
  [Design](docs/explanation/design.md#unsafe-code).
- Update the relevant guide, coverage contract, or design boundary when public
  behavior changes. Do not document unimplemented or unverified support.

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

## Required checks

Run these from the repository root. They match the integration gate in
[AGENTS.md](AGENTS.md); keep the two lists in step.

```console
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
```

`cargo test` includes doctests that compile the Rust examples in `README.md`,
`docs/getting-started.md`, and the guides under `docs/guides/`; a guide example
that no longer compiles fails the gate. The hooks live in
`crates/phantom/src/lib.rs`; add one when a new guide contains Rust code. The
MSRV line is CI's `MSRV` job; that job also checks each optional
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

Conditional checks:

- Run `scripts/ci/check-vendor.sh <package>` for every vendored package you
  change; see [Vendored forks](docs/internals/vendoring.md).
- Shell changes under `scripts/ci` or `scripts/release` must pass ShellCheck
  0.11.0 (`shellcheck scripts/ci/*.sh scripts/release/*.sh`).
- Changes under `fuzz/` must pass
  `cargo fmt --manifest-path fuzz/Cargo.toml --check` and
  `cargo clippy --manifest-path fuzz/Cargo.toml --bins --locked -- -D warnings`.
- The optional-feature matrix and scheduled interoperability suites run in
  CI; run the affected feature combinations locally before requesting review.

## Continuous integration

Changes reach `main` through pull requests. The one required status check is
`CI required`, the last job in [CI](.github/workflows/ci.yml). It passes only
when the change classification below succeeded, every job that the
classification and the event call for succeeded, and every other job was
skipped. A failed, cancelled, or unclassified run never counts as passing.

| Workflow | Pull request | Push to `main` | Weekly schedule and manual dispatch |
| --- | --- | --- | --- |
| [CI](.github/workflows/ci.yml) | Linux jobs: Quality, Features, Downstream, Vendor, MSRV | Linux jobs and the macOS and Windows Platform jobs | Every job, whatever changed |
| [Parser fuzzing](.github/workflows/fuzz.yml) | 15 seconds per target when parser paths change | Same as pull requests | 300 seconds per target |
| Conformance suites | Only with the `conformance` label | When the suite's paths change | Yes, with the workflow's scheduled or chosen case set |
| [Scorecard](.github/workflows/scorecard.yml) | No | Yes | Yes |
| Benchmarks, upstream freshness | No | No | Yes |

The conformance suites are [Autobahn](.github/workflows/autobahn.yml),
[BoringSSL native](.github/workflows/boringssl-native.yml),
[QUIC interop](.github/workflows/quic-interop.yml),
[TLS-Anvil](.github/workflows/tls-anvil.yml), and
[WPT EventSource](.github/workflows/wpt-eventsource.yml).
[Release](.github/workflows/release.yml) runs only by manual dispatch.

CI skips jobs that a documentation-only change cannot affect;
[`scripts/ci/changed-paths.sh`](scripts/ci/changed-paths.sh) classifies the
changed paths against the base branch, or against the previous `main` commit
on a push:

- Documentation: Markdown outside `crates/`, `fixtures/`, `fuzz/`, and
  `vendor/`; anything under `docs/`; the license files; `.github/CODEOWNERS`;
  and `.github/ISSUE_TEMPLATE/`. A change made only of these runs only the
  classification job and `CI required`.
- Doctest sources: `README.md`, `docs/getting-started.md`, and
  `docs/guides/`, which `cargo test` compiles. A change to these, with no
  code, runs only the Quality job.
- Code: every other path, including workflows, manifests, fixtures, and
  scripts. Any code path runs every job for that event.

Every push to `main` gets its own CI run, which a later push neither cancels
nor replaces, so each pushed commit range is classified and checked. A newer
pull request run cancels the older run for the same pull request.

Change the classification together with its cases in
`scripts/ci/test-changed-paths.sh`, which the Quality job runs.

Because pull requests skip the Platform jobs, platform-specific failures
surface on `main`. Before merging a change that may behave differently on
macOS or Windows, run the platform gate locally or dispatch CI for the branch,
which runs every job:

```console
gh workflow run ci.yml --ref <branch>
```

A maintainer can run the conformance suites on a pull request by applying
the `conformance` label. The suites then run on the label event and again on
each push while the label stays, whatever paths changed, with the case set a
push to `main` uses; remove the label to stop them.

Every push to a pull request, and every label added to it, still starts a
run of each conformance workflow. Without the `conformance` label, or for an
unrelated label, that run's job is skipped and appears as a skipped check. An
unrelated label added while a labeled run is in progress does not cancel it.
To find the run that did the work, open the workflow in the Actions tab
filtered to the branch, or list its runs and pick the one whose job was not
skipped:

```console
gh run list --workflow autobahn.yml --branch <branch>
```

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) with an
intent-first subject:

```text
fix(http2): reject conflicting settings
```

- Common types are `feat`, `fix`, `docs`, `test`, `ci`, and `build`. The
  scope names the protocol or area, such as `net`, `profile`, `tls`, or
  `capture`, and may be omitted.
- Write the subject in the imperative mood, under 72 characters, without a
  trailing period.
- Wrap the body at 100 columns and explain why the change is needed.
- Keep each commit focused. Put mechanical renames, formatting, and
  dependency or lockfile updates in their own commits.

## Pull requests

Keep pull requests focused. The
[pull request template](.github/pull_request_template.md) asks for the items
below; fill in each one.

- [ ] The user- or peer-visible outcome is explained.
- [ ] Acceptance criteria and non-goals are stated.
- [ ] Wire evidence is identified when behavior is wire-sensitive.
- [ ] Tests, rustdoc, and guides are updated for public behavior changes.
- [ ] The exact checks run and their results are recorded.
- [ ] New dependencies, patches, unsafe code, fallbacks, security
      implications, and unresolved uncertainty are called out.

A passing branch is not enough when a public option is unused, a fixture masks
meaningful variance, or a failure silently changes the selected path.

## Licensing

Phantom is dual-licensed under [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT). Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in Phantom by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional
terms or conditions.

- No contributor license agreement or DCO sign-off is required.
- Source files do not carry per-file license headers; the license files at the
  repository root apply.
- Vendored packages under `vendor/` keep their upstream license and `NOTICE`
  files unchanged. Phantom's modifications are recorded as ordered patches in
  each package's `patches/series` and described in its `PHANTOM.md`.
- Do not add code copied from another project unless its license is
  compatible and its provenance is recorded.
