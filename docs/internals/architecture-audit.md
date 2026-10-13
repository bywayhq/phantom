# Architecture audit

Use this record to find the completed reviews and their delivered changes.
The audit finished on 2026-10-13 at `f0148f11`, before release preparation.

## Scope and result

The review started at `df2ae9b7` on 2026-10-09. It covered all five crates,
first-party tests, examples, fuzz targets, scripts, workflows, configuration
and documentation. Maintained vendor patches and relevant upstream boundaries
have separate whole or partial reviews.

Independent review traced request preparation, routing, admission, transport,
streaming, retries, cookies, SSE, WebSockets, cancellation and shutdown.
Confirmed fixes address deadlines, input limits, task and socket ownership,
retained error causes and credential-safe diagnostics. Public API cleanup
updates callers and migration notes. The reviewed responsibilities support
keeping the five crates.

Untouched upstream source was not exhaustively audited. Structured capture
review does not mean every payload was read. The audit makes no fresh browser
parity, live server acceptance or defect-free claim. Earlier HTTP/3 draining
and TLS capture timer failures retain their unresolved original causes.

## Deliveries

Each delivery retains its own source review, exact gate and applicable CI.

| Delivery | Revision | PR |
| --- | --- | --- |
| Runtime and public APIs | `32a3071f` | 198 |
| Testkit and fixtures | `90b9b7ea` | 199 |
| Capture and conformance tools | `20fa0d5b` | 200 |
| Architecture and documentation | `d1d353e8` | 204 |
| Fixture ownership and parsing | `7e153e1a` | 205 |
| HTTP/3 WebSocket and MASQUE fixtures | `1806cb77` | 206 |
| Capture workers, input and QPACK | `b6942293` | 207 |
| Firefox and HTTP/2 preface captures | `b8ab9851` | 208 |
| Capture validation and peer collection | `f146e52c` | 209 |
| Alt-Svc setup ownership and final audit records | `f0148f11` | 210 |

All ten PRs merged. The final revision passed all 24 local gate steps,
including 4,575 native tests and 143 doctests. All 29 PR checks passed,
including Windows and macOS. Its three applicable main workflows passed:
CI, Scorecard and code analysis, with all 23 jobs successful.

The local gate's Linux checks compile and lint through WSL. Focused Linux
runtime controls and hosted platform checks retain their separate scope.
Cached native builds, ignored examples and skipped Python tests remain
identified in the retained logs. Later green runs do not diagnose earlier
failures.

## Cleanup

Delivered lane branches and worktrees were removed after preserving their
histories and verification evidence. Independent verification checked the
final history bundle and all 138 archived evidence files. Superseded draft
PR 197 is closed and its remote branch is removed.

The original dirty audit worktree, its recovery branch and the two pre-audit
worktrees remain intact. The earlier plan and detailed per-pass records
remain retrievable through Git history and the evidence index.

## Downstream

Playground's migration is ready on `lane/phantom-migration` at `399af77e`.
Its quick gate and 773 selected tests passed locally, with 340 tests outside
that selection. The preserved Solve source snapshot passed 35 consumer tests.
These are local checks without fresh browser or live server acceptance.

The user chose to leave the migration unlanded and keep Foundry active.
Downstream integration remains separate from the completed audit.

## Evidence records

- [Coverage](architecture-audit/coverage.md): actual review scope and limits.
- [Findings](architecture-audit/findings.md): causes, remedies and verification.
- [Inventory](architecture-audit/inventory.tsv): per-path review dispositions.
- [Retained evidence](architecture-audit/evidence.md): original reviews and logs.

Historical records keep their original revision and scope. The completion
receipt, final main checks and archive verification remain under
`C:/code/phantom/target/architecture-audit` as
`final-goal-closure-f0148f11.json`,
`final-delivery-f0148f11-independent-verification.json` and
`final-delivered-lanes-cleanup-independent-verification-f0148f11.json`.

## Next

- [Design](../explanation/design.md): ownership and wire invariants.
- [Roadmap](../roadmap.md): release, hardening and profiling work.
