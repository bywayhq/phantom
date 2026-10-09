# Bounded development, docs and conformance source pass

Revision: `2cb59371ee00b4ae6369dfff06683d090e5762f5`. Root checkout remains at the original baseline, so every fresh committed read used Git snapshot bytes. No Cargo, runtime test, subprocess fixture, Docker build or integration operation was executed. Raw OID, SHA-256, physical line count, full/partial range, contract and limitation are recorded per file in the companion JSON.

## Supported source candidates

`crates/phantom-net/examples/quic_version_interop.rs:26: minor`: Explicit zero requests returns success after zero handshakes/responses. Parse a nonzero request count before root/connector/network work; reject zero with pure parser control; retain default three only when absent.

Evidence limit: Static loop/control flow only, not reproduced. Manual example not selected by current gate.

`scripts/conformance/quic_interop.py:95: major`: Image arguments only reject whitespace, but pinned upstream runner interpolates them into shell=True command strings. Metacharacters and ${IFS} are accepted and acquire shell syntax. Validate a constrained Docker image/reference grammar rejecting all shell syntax before registry/file writes, with atomic invalid-input controls and a harmless controlled upstream-shell reproduction.

Evidence limit: Pinned interop.py lines123-140,154-170,392-427 source inspected; no reproduction run, no claim of attacker-controlled CI values.

`scripts/conformance/quic_interop.py:291: major`: The outer runner timeout owns only run.py, while that process launches shell/docker compose descendants and its normal per-test timeout cleanup. Killing run.py can bypass that cleanup; finally restores files without stopping its descendants or containers. Use an owned subprocess group plus attempt-specific Docker project cleanup on timeout/interruption, drain/join before restoration and failed summary publication, and test controlled descendants plus cleanup faults.

Evidence limit: Local subprocess.run timeout and final restoration; pinned upstream interop.py lines421-443 stop containers only on its own TimeoutExpired. Source-supported ownership gap, no live leak reproduction. Normal success/failure path is not claimed to leak.

## Boundary traces

The new dev regression chain reaches the actual lock/search/freshness helpers. Marker barriers forbid premature commands, injected search statuses distinguish absence from infrastructure failure, and the offline report test checks exact independent capture metadata and workflow fields. Their source controls have not been executed by this reviewer. The lock tests cover a signal after successful acquisition, not every startup-window or repeated-interrupt interleaving.

The docs chain reaches parser, checker, CLI and independently constructed pages. Paths are case checked and normalized repository escapes fail. Masking, explicit allow directives, error versus warning status and test assertions match the supported subset. This does not claim a complete Markdown parser or browser anchor implementation. The current CI docs job discovers those tests and runs the checker; gate.sh does likewise.

The aioquic chain is a manual observer, not a default CI interop job. Actual event state supplies reported numbers; server header events count toward the threshold without unique-stream filtering. Normal Rust requests are bodyless GETs and default to three. Reports do not automatically assert the expected negotiated version/resumption pattern. Historical three-request captured observation remains distinct from present source inspection.

The QUIC runner chain checks exact clean revision, guarded registry/compose/testcase rewrites, one matching HTTP3 successful cell and zero child exit. The real endpoint requires nonempty targets, pinned runner hosts, same origin, safe output names, bounded downloads and actual HTTP3 metadata. The pinned upstream HTTP3 case selects three independent files and checks handshake count plus its version/files helper; that helper body remains a gap. PR/main workflow runs the image/unsupported control only; schedule/manual selects the full interop invocation.

The report caps retained runner text after subprocess capture. This is a retained-artifact bound, not a bound on memory consumed while collecting stdout/stderr. JSON report size and OpenSSL startup time are not internally bounded. Those limitations are recorded without inventing a universal secrecy or input-memory guarantee.

## Maintenance patch disposition

No finding in the five source/prose maintenance files: exact package selectors match current manifests, local wrapper/adapter versus Git sys provenance is accurate, and renamed Quinn identity/lock references match actual selected declarations. The original script complete read retains its original snapshot; the working patch uses separate hashes and partial ranges. No backend payload source or canonical patch changed in these reviewed hunks. Root CHANGELOG/ledger maintenance is outside this patch disposition.

## Remaining paths and verification

Capture75 remain assigned to the capture owner, including old complete files whose current source changed and partial caller records. Conformance runners Autobahn, TLS-Anvil and WPT-EventSource plus their configs/tests remain unread here. QUIC requirements are partial; upstream version/file-check helper and dependency container scripts remain explicit gaps. Prior development README and root lock/requirements partial coverage is not promoted. No entire tooling completion claim is made.

The integration owner still needs controlled baseline reproductions for supported candidates, final relevant Python discovery, Ruff and ShellCheck, the final full gate, and applicable canonical vendor checks. The disposition index is additive; no prior source or runtime evidence is replaced.

## Exact fresh read roster

| File | Read | Lines |
| --- | --- | --- |
| `scripts/dev/tests/test_cargo_lock.py` | full_source | 227 |
| `scripts/dev/tests/test_ci_checks.py` | full_source | 114 |
| `scripts/dev/tests/test_upstream_report.py` | full_source | 128 |
| `scripts/dev/with-cargo-lock.sh` | full_source | 86 |
| `scripts/ci/check-unsafe-boundaries.sh` | full_source | 74 |
| `scripts/ci/check-tool-pins.sh` | full_source | 145 |
| `scripts/ci/report-upstream-freshness.sh` | full_source | 462 |
| `scripts/dev/gate.sh` | full_source | 495 |
| `scripts/ci/check-vendor.sh` | full_source | 427 |
| `scripts/docs/check_docs.py` | full_source | 622 |
| `scripts/docs/tests/test_check_docs.py` | full_source | 327 |
| `scripts/docs/README.md` | full_source | 51 |
| `scripts/docs/__init__.py` | full_source | 1 |
| `scripts/docs/tests/__init__.py` | full_source | 1 |
| `scripts/conformance/__init__.py` | full_source | 1 |
| `scripts/conformance/tests/__init__.py` | full_source | 1 |
| `scripts/conformance/aioquic_versions.py` | full_source | 182 |
| `scripts/conformance/tests/test_aioquic_versions.py` | full_source | 62 |
| `scripts/conformance/loopback_tls.py` | full_source | 132 |
| `crates/phantom-net/examples/quic_version_interop.rs` | full_source | 78 |
| `scripts/conformance/quic_interop.py` | full_source | 418 |
| `scripts/conformance/tests/test_quic_interop.py` | full_source | 126 |
| `scripts/conformance/quic-interop/run_endpoint.sh` | full_source | 11 |
| `scripts/conformance/quic-interop/Dockerfile` | full_source | 20 |
| `crates/phantom/examples/quic_interop/main.rs` | full_source | 368 |
| `crates/phantom/examples/quic_interop/target.rs` | full_source | 128 |
| `.github/workflows/quic-interop.yml` | full_source | 141 |
| `.github/workflows/upstream-freshness.yml` | full_source | 138 |
| `Cargo.toml` | full_source | 80 |
| `vendor/btls/Cargo.toml` | full_source | 85 |
| `vendor/http2/Cargo.toml` | full_source | 187 |
| `vendor/wreq-proto/Cargo.toml` | full_source | 178 |
| `vendor/quinn-proto/Cargo.toml` | full_source | 205 |
| `vendor/tokio-btls/Cargo.toml` | full_source | 48 |
| `.github/workflows/ci.yml` | partial_source | 520 |
| `docs/explanation/validation.md` | partial_source | 6910 |
| `Cargo.lock` | partial_source | 2772 |
| `scripts/conformance/quic-interop/requirements.txt` | partial_source | 259 |

## Next

- [Findings](findings.md): verification and integration state.
