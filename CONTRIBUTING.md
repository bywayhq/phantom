# Contributing

Take a change from a fresh clone to a merged pull request: set up, make the
change, run the checks, and open the pull request.

> For contributors, human or coding agent. [AGENTS.md](AGENTS.md) is the
> working agreement; this page condenses it and adds setup and CI detail.

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

3. For anything larger than a small fix, open a
   [proposal](https://github.com/bywayhq/phantom/issues/new?template=proposal.yml)
   first, so the scope is agreed before you write code.
4. [Make the change](#make-a-change), [run the checks](#run-the-checks), and
   open a [pull request](#commits-and-pull-requests).

## Development setup

`rust-toolchain.toml` pins the development toolchain, and `rustup` installs it
on first use. Native TLS builds need Git, CMake, Clang, and a C++ toolchain;
Windows also needs NASM and the Visual C++ build tools. Python 3.10 and `uv`
are needed only for the capture and conformance tooling. The platform jobs in
[CI](.github/workflows/ci.yml) show the exact prerequisite checks.

Install the minimum supported Rust version (MSRV) for the MSRV check, and Rust
1.85 for `scripts/ci/check-vendor.sh btls`, which also checks the vendored
`btls` crate on its upstream MSRV:

```console
rustup toolchain install 1.88.0 --profile minimal
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

The Build Tools workload provides the MSVC compiler and the Windows SDK. The
NASM and LLVM installers may not update `PATH`: add `C:\Program Files\NASM`
and `C:\Program Files\LLVM\bin` so that `nasm`, `cmake`, and `clang` resolve
in the shell that runs Cargo. If the build cannot find `libclang`, set
`LIBCLANG_PATH` to LLVM's `bin` directory. A checkout with
`core.autocrlf=true` is supported: `.gitattributes` keeps `vendor/` and
`fixtures/` byte-exact.

Run `scripts/ci/*.sh` from Git Bash. These scripts fetch upstream sources and
compare them byte for byte with `vendor/`, so turn off CRLF conversion and
turn on symlinks for their child Git processes:

```sh
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=core.autocrlf GIT_CONFIG_VALUE_0=false
export GIT_CONFIG_KEY_1=core.symlinks GIT_CONFIG_VALUE_1=true
scripts/ci/check-vendor.sh btls
```

[AGENTS.md](AGENTS.md#windows-hosts) lists the other Windows host constraints
that tests must allow for: reserved UDP ports, slow refused connects, and
`ConnectionAborted` on disconnect.

## Make a change

Before you edit, state in the proposal or pull request the observable
acceptance criteria, what is out of scope, the files the change owns, and the
commands, fixtures, or captures that will prove it. Investigate uncertain
protocol behavior first. Tests against live services may add to local proof
but are never the only proof.

While you edit, keep the
[engineering constraints](AGENTS.md#engineering-constraints). In short:
implement the smallest complete vertical slice, and keep unrelated formatting,
renames, dependency updates, and cleanup out of it. Preserve observable
ordering, and return an error when a requested protocol, route, or
fingerprint cannot be honored; never fall back. Expose configuration only
once it is applied, validated, and tested. Keep recoverable failures panic-free, and add
no unsafe code outside the audited FFI module in
[Design](docs/explanation/design.md#unsafe-code). When public behavior
changes, update the guide, coverage contract, or design boundary, and never
document unverified support.

To run changes in parallel worktrees, see
[Lanes and worktrees](AGENTS.md#lanes-and-worktrees) and
[Development helpers](scripts/dev/README.md#parallel-lanes). Three common
changes have their own walkthroughs:

| Task | Walkthrough |
| --- | --- |
| Add or update a browser recipe | [Add a browser recipe](docs/internals/browser-recipes.md) |
| Record browser evidence | [Capture tools](scripts/capture/README.md) |
| Change or refresh a vendored fork | [Vendored forks](docs/internals/vendoring.md) and the fork's `vendor/*/PHANTOM.md` |

### Tests and evidence

Name tests after the observable behavior they check. A wire-sensitive change
normally needs a deterministic local test or capture fixture. Reduce an
adversarial or fuzz failure to a minimal input and keep it as an ordinary
regression test.

| Change | Minimum proof |
| --- | --- |
| Public API or policy | Focused tests, rustdoc, and the relevant guide or coverage update |
| Wire-visible behavior | Retained evidence plus a deterministic differential |
| Parser or peer handling | Boundary tests and an adversarial regression |
| Dependency or vendor patch | Canonical patch replay, focused upstream tests, and provenance update |
| Hot path | Representative benchmark or profile with the claimed scope stated |

## Run the checks

The integration gate is defined in
[AGENTS.md](AGENTS.md#verification-and-handoff), which is authoritative. It is
copied here so this page is complete; change both lists together. Run it from
the repository root:

```console
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.88.0 check --workspace --all-targets --locked
uvx ruff@0.16.7 check scripts/capture scripts/conformance scripts/docs
uvx ruff@0.16.7 format --check scripts/capture scripts/conformance scripts/docs
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  --with h2==4.4.1 --with hpack==4.2.0 \
  python -m unittest discover -s scripts/capture/tests -p 'test_*.py'
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  python -m unittest discover -s scripts/conformance/tests -p 'test_*.py'
uv run --no-project --python 3.10 \
  python -m unittest discover -s scripts/docs/tests -p 'test_*.py'
uv run --no-project --python 3.10 python scripts/docs/check_docs.py
```

- Never run `cargo fmt --all`: it also formats path dependencies and rewrites
  the vendored forks.
- Read the output of every command. A list joined with `;` or piped through
  `tail` reports the status of its last command only, so search the output for
  `error`, `FAILED`, and `warning`.
- `cargo test` compiles the Rust examples in `README.md`,
  `docs/getting-started.md`, and the guides that `crates/phantom/src/lib.rs`
  includes. A new guide with Rust code needs an include there.
- CI installs the Python test dependencies from the hash-pinned
  `scripts/requirements.txt`, generated from `scripts/requirements.in` by the
  command in its header. Keep the `--with` pins above in step with it.

Run these too when the change touches their area:

| Change touches | Check |
| --- | --- |
| A vendored package | `scripts/ci/check-vendor.sh <package>`; see [Vendored forks](docs/internals/vendoring.md) |
| `scripts/ci` or `scripts/release` shell | ShellCheck 0.11.0: `shellcheck scripts/ci/*.sh scripts/release/*.sh` |
| `fuzz/` | `cargo fmt --manifest-path fuzz/Cargo.toml --check` and `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings` |
| Optional features | The affected combinations from the Features and MSRV jobs in [CI](.github/workflows/ci.yml) |
| The QUIC cryptography backend | AddressSanitizer, as [below](#reproduce-a-sanitizer-report) |

### Reproduce a sanitizer report

[Sanitizers](.github/workflows/sanitizers.yml) runs `phantom-quic-btls` and
the HTTP/3 loopback tests under AddressSanitizer. To reproduce a report as CI
produces it, use Linux x86_64, natively or under WSL. The explicit target is
what keeps host build scripts and proc macros uninstrumented:

```console
rustup toolchain install nightly-2026-09-01 --profile minimal
rustup target add x86_64-unknown-linux-gnu --toolchain nightly-2026-09-01
export RUSTFLAGS=-Zsanitizer=address
export ASAN_OPTIONS=detect_leaks=1
cargo +nightly-2026-09-01 test -p phantom-quic-btls --lib --all-features \
  --locked --target x86_64-unknown-linux-gnu
cargo +nightly-2026-09-01 test -p phantom-net --lib --all-features \
  --locked --target x86_64-unknown-linux-gnu -- 'http3::'
```

For a first pass on Windows, run the same two test commands against
`x86_64-pc-windows-msvc`. Put `clang_rt.asan_dynamic-x86_64.dll` from
`VC\Tools\MSVC\<version>\bin\Hostx64\x64` on `PATH`, or the test binary exits
with `STATUS_DLL_NOT_FOUND`. Run `unset ASAN_OPTIONS`: Windows has no
LeakSanitizer, and asking for it aborts with `detect_leaks is not supported on
this platform`. A Windows run therefore cannot report a leaked ex-data owner
and never exercises `prefix-symbols`, the Linux-only `nm`/`objcopy` archive
rewrite in `btls`. A clean Windows run shows that the instrumentation works,
not that the CI job passes.

## Continuous integration

Changes reach `main` through pull requests. The `main` ruleset requires signed
commits, a linear history, and one status check, `CI required`. GitHub cannot
sign a rebase merge, and a squash merge would flatten a lane's logical
commits, so the integrator fast-forwards `main` locally once the pull request
is green.

`CI required` is the last job in [CI](.github/workflows/ci.yml). It passes
only when change classification succeeded, every job the classification and
event call for succeeded, and every other job was skipped. A failed,
cancelled, or unclassified run never passes. It covers CI's jobs alone, so
every other workflow is advisory. Read the Sanitizers and Parser fuzzing runs
before merging a change to the QUIC or TLS paths.

| Workflow | Pull request | Push to `main` | Weekly schedule and manual dispatch |
| --- | --- | --- | --- |
| [CI](.github/workflows/ci.yml) | Linux jobs: Quality, Documentation, Features, Downstream, Vendor, MSRV, and the Windows Platform job | Same, plus the macOS Platform job | Every job, whatever changed |
| [Parser fuzzing](.github/workflows/fuzz.yml) | 15 seconds per target when parser paths change | Same as pull requests | 300 seconds per target |
| [Sanitizers](.github/workflows/sanitizers.yml) | `phantom-quic-btls` and the HTTP/3 loopback tests under ASan when QUIC, TLS, testkit, or vendored paths change; each job times out at 60 minutes | Same as pull requests | Both jobs, whatever changed |
| Conformance suites | Only with the `conformance` label | When the suite's paths change | Yes, with the workflow's scheduled or chosen case set |
| [Scorecard](.github/workflows/scorecard.yml) | No | Yes | Yes |
| [Benchmarks](.github/workflows/benchmarks.yml), [upstream freshness](.github/workflows/upstream-freshness.yml) | No | No | Yes |

The conformance suites are [Autobahn](.github/workflows/autobahn.yml),
[BoringSSL native](.github/workflows/boringssl-native.yml),
[QUIC interop](.github/workflows/quic-interop.yml),
[TLS-Anvil](.github/workflows/tls-anvil.yml), and
[WPT EventSource](.github/workflows/wpt-eventsource.yml).
[Release](.github/workflows/release.yml) runs only by manual dispatch.

### Which jobs a change runs

[`scripts/ci/changed-paths.sh`](scripts/ci/changed-paths.sh) classifies the
changed paths against the base branch, or on a push against the previous
`main` commit. Each push to `main` gets its own run that no later push cancels,
so every pushed range is checked; a newer pull request run cancels the older
one.

| Class | Paths | Jobs that run |
| --- | --- | --- |
| Documentation | Markdown outside `crates/`, `fixtures/`, `fuzz/`, and `vendor/`; anything under `docs/`; the license files; `.github/CODEOWNERS`; `.github/ISSUE_TEMPLATE/` | Classification, Documentation, and `CI required` |
| Doctest sources | `README.md`, `docs/getting-started.md`, `docs/guides/` | Quality only, when no code changed |
| Code | Every other path, including workflows, manifests, fixtures, and scripts | Every job for the event |

Change the classification together with its cases in
`scripts/ci/test-changed-paths.sh`, which the Quality job runs.

### Run the jobs a pull request skips

Pull requests run the Windows Platform job, because Windows is the development
host. macOS runs only on the push to `main`, so a macOS-specific failure can
still land. Before merging a change that may behave differently there,
dispatch CI for the branch, which runs every job:

```console
gh workflow run ci.yml --ref <branch>
```

A maintainer runs the conformance suites on a pull request by applying the
`conformance` label. They run on the label event and on each later push until
the label is removed, whatever paths changed, with the case set a push to
`main` uses. Every push and label still starts each conformance workflow; a
run without the label, or for another label, shows as skipped and does not
cancel a labeled run. To find the run that did the work, pick the one whose
conclusion is not `skipped`:

```console
gh run list --workflow autobahn.yml --branch <branch>
```

## Write documentation

Follow [Writing the documentation](docs/internals/documentation.md) for
readers, page types, page shape, and prose rules, and run
`python scripts/docs/check_docs.py` before you commit. Add an entry under
`Unreleased` in [CHANGELOG.md](CHANGELOG.md) for every user-visible change; a
breaking change also needs a "Migrate:" note.

## Commits and pull requests

Use [Conventional Commits](https://www.conventionalcommits.org/) with an
intent-first subject, such as `fix(http2): reject conflicting settings`.

- Common types are `feat`, `fix`, `docs`, `test`, `ci`, and `build`. The scope
  names the protocol or area, such as `net`, `profile`, `tls`, or `capture`,
  and may be omitted.
- Write the subject in the imperative mood, under 72 characters, without a
  trailing period. Wrap the body at 100 columns and explain why.
- Keep each commit focused. Put mechanical renames, formatting, and
  dependency or lockfile updates in their own commits.
- Add no `Co-Authored-By` trailers for AI tools, no `Claude-Session`
  trailers, and no agent session links. Credit human co-authors normally.

Keep pull requests focused, and fill in every section of the
[pull request template](.github/pull_request_template.md): the observable
outcome, acceptance criteria, non-goals, evidence with the exact commands run
and their results, and risk (new dependencies, patches, unsafe code,
fallbacks, security implications, and unresolved uncertainty). Passing checks are not enough if a public option is never applied, a fixture
hides meaningful variance, or a failure silently changes the selected path.

## Licensing

Phantom is dual-licensed under [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT). Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in Phantom by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional
terms or conditions.

- No contributor license agreement or DCO sign-off is required.
- Source files carry no per-file license headers; the license files at the
  repository root apply.
- Vendored packages under `vendor/` keep their upstream license and `NOTICE`
  files unchanged. Phantom's modifications are ordered patches in each
  package's `patches/series`, described in its `PHANTOM.md`.
- Do not add code copied from another project unless its license is
  compatible and its provenance is recorded.

## Next

- [Design](docs/explanation/design.md): the invariants a change must keep;
  [Coverage](docs/reference/coverage.md) and
  [Validation](docs/explanation/validation.md) hold the boundary and evidence.
- [Add a browser recipe](docs/internals/browser-recipes.md): the most common
  wire-sensitive change, step by step.
- [Writing the documentation](docs/internals/documentation.md): rules for any
  page the change touches.
