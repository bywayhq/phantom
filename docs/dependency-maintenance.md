# Dependency and platform maintenance

Phantom reuses mature protocol engines and carries a patch only when retained
wire evidence proves that an upstream seam is insufficient. A fork is a small,
reviewable compatibility delta, not a second upstream project.

## Patch contract

Every patched dependency has one source of truth for each of these items:

1. Exact upstream repository and commit or registry version and checksum.
2. The reason the stock behavior cannot satisfy a retained differential.
3. A canonical machine-applicable patch, kept separate from packaging changes.
4. Focused tests for the changed behavior and proof that stock defaults remain
   unchanged when Phantom's option is not selected.
5. A `PHANTOM.md` provenance and refresh procedure beside a vendored source, or
   equivalent provenance in the dependency fork.
6. A scheduled freshness report and a disposable candidate probe which fails
   closed when the patch no longer applies cleanly.

Patches are never applied with fuzzy or rejected hunks. Updating a pin means
staging pristine upstream source, checking and applying the canonical patch,
running its focused tests, then running the workspace gates. The reviewed pin
changes only after that evidence is available. Automated dependency updates may
open review work; they do not silently rewrite a wire profile or vendor tree.

The current `wreq-proto`, `btls`, `http2`, H3, and `tungstenite` copies follow
this contract.
The `wreq-proto` patch adds Phantom's opt-in HTTP/1 chunk-size-line bound while
preserving the stock default; its disposable probe checksum-binds the crates.io
archive, reapplies the canonical patch, and runs the vendored crate plus
workspace gates. The HTTP/2 and H3 patches also retain decoded ordinary
response fields before `HeaderMap` normalization loses their global order. The
H3 source is selected by the root workspace for the direct request path. Its
disposable probe checksum-binds an exact Hyperium revision, reapplies the
ordered-SETTINGS, QPACK-runtime, ordered-response, and cancel-safe receive
patches, and runs the focused H3 and `h3-quinn` gates. Chrome's nonzero inbound
QPACK settings are enabled with bounded decode and feedback state. Outbound
dynamic QPACK, WebTransport, and extension-specific datagram APIs remain
separate capabilities.

The `tungstenite` series preserves stock defaults while exposing the narrow
frame-engine controls Phantom needs. Its fragment-count patch remains disabled
in the engine by default; Phantom selects a bounded public default. The
checksum-bound replay gate applies the ordered series to the crates.io archive,
compares the full vendored tree, and runs no-default, deflate, and all-feature
tests.

A dependency patch may also be justified by a concrete provider-contract
failure even when it does not alter the intended wire image. Quinn 0.11.18's
Initial-key interface cannot represent derivation failure, while its key-update
interface represents absence but not failure and production call sites unwrap
that absence. Phantom therefore carries two narrow error-propagation patches:
stock providers retain their behavior, while a custom provider can reject
construction or close with `INTERNAL_ERROR` before committing Retry or key
phase state. Observable transport changes still require retained packet
evidence; this safety exception is not permission for speculative tuning.

## Cross-platform gate

Every pull request and `main` push run:

| Runner | Gate |
| --- | --- |
| Linux | formatting, Clippy with warnings denied, capture-tool checks, vendored patch gates, all workspace tests, rustdoc warnings denied, patch-tooling regressions, and the declared MSRV |
| macOS | all workspace targets, features, and tests with the locked dependency graph |
| Windows | all workspace targets, features, and tests with the locked dependency graph |

The BoringSSL symbol-prefix feature is selected only on non-Apple, non-Windows
targets. The pinned `btls` revision cannot rewrite its archive consistently on
Apple and Windows, so those targets intentionally use the unprefixed build.
This platform choice is declared in each direct BoringSSL consumer and exercised
by the matrix; it is not selected at runtime.

Native builds require CMake 3.22 or newer and a C/C++ toolchain. Windows also
requires Visual Studio 2022 with the C++ tools and NASM; macOS uses the Xcode
command-line tools. CI checks these prerequisites before compiling so a runner
image change fails with a direct diagnostic instead of an opaque native-build
error. The actual debug and release builds remain the authoritative proof that
the tools, headers, generated bindings, archives, and Rust linker agree.

Until the native build can prefix Mach-O and COFF symbols, Apple and Windows
builds require one OpenSSL/BoringSSL lineage in the final process. Publishing
bindings or embedding Phantom beside a second provider is blocked on a native
prefix implementation plus a link test containing both providers. The platform
matrix checks native prerequisites, debug workspace tests, a release-mode QUIC
crypto link, and focused MSRV compilation; a configured workflow is not treated
as a successful platform run until its remote job is green.

GitHub Actions are pinned by commit, jobs have finite timeouts and read-only
repository permissions, and cross-platform jobs do not repeat Linux-only lint
or documentation work. Additional Rust targets remain best-effort until a CI
runner and a focused platform test justify adding them to the maintained
matrix.

## Release check

Before a release or a patched-dependency refresh:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
scripts/ci/test-upstream-freshness.sh
for package in wreq-proto btls http2 quinn-proto h3 tungstenite; do
  scripts/ci/check-vendor.sh "$package"
done
```

The scheduled upstream-freshness workflow supplements this gate by testing
candidate revisions in a disposable checkout. It reports drift for human
review; it never mutates the source checkout or publishes a replacement pin.
