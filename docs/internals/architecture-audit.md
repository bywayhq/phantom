# Architecture audit

Use this record to follow the review of the current code, its findings, and
the changes that resolve them. The review starts before release preparation.

## Starting point

- Revision: `df2ae9b7d87567907a2f273068220349dcd4750b`.
- Date: 2026-10-09.
- Integration checkout: clean on `main`, matching `origin/main`.
- Main checks: CI, parser fuzzing, QUIC interoperability, Autobahn, WPT
  EventSource, Scorecard, and code analysis passed on this revision.
- Two unrelated worktrees remain outside this audit.

## Acceptance criteria

Review the first-party code, tests, examples, fuzz targets, manifests,
scripts, workflows, documentation, and configuration. Review vendored
patches and the upstream code that governs their integration. Record each
area's actual review coverage, including platform and feature conditions.

Resolve confirmed correctness, ownership, lifecycle, API, documentation,
and maintainability findings. Preserve wire ordering, route and protocol
choices, bounded resources, credential protection, and cancellation.
Breaking API cleanup is allowed when callers and migration notes move with
it. No publication, runtime replacement, browser refresh, or unrelated
feature work belongs here.

## Delivery priority

Ship the reviewed production changes needed by Playground before completing
the remaining audit. Playground integration comes next, followed by the
Solve consumer. The full audit remains open across these deliveries.

| Order | PR scope | Acceptance |
| --- | --- | --- |
| 1 | Runtime, public APIs and required vendor repairs | Required regression tests, migration notes, independent review, full gate and platform CI |
| 2 | Remaining testkit and integration fixture repairs | Original behavioral assertions, observed worker failures and bounded cleanup |
| 3 | Capture, conformance and development tools | Tool-specific controls, retained failures and platform checks |
| 4 | Remaining architecture and documentation audit | Complete review dispositions, combined standards review and accurate roadmap |

Keep a production change with the regression tests and dependency updates
needed to verify it. Move additional fixture cleanup and capture work into
later PRs. A confirmed production defect on the downstream path still blocks
its shipping candidate. An unfinished test-only audit does not automatically
block an independently verified production slice.

Pin Playground to the exact merged revision and check its actual transport
features and workflows. Check the Solve consumer after that migration.
Existing downstream changes and the original audit branches remain intact.

## Current deliveries

This is the delivery snapshot from 2026-10-13. The full audit remains open.

| Delivery | Revision | State |
| --- | --- | --- |
| Runtime and public APIs, PR 198 | `32a3071f` | Merged; all 43 PR checks passed |
| Testkit and fixtures, PR 199 | `90b9b7ea` | Merged; applicable PR checks passed, including both platforms |
| Capture and conformance tools, PR 200 | `20fa0d5b` | Merged; all 24 local gate steps and applicable PR checks passed |
| Architecture and documentation, PR 204 | `d1d353e8` | Merged; all 22 local gate steps, applicable PR checks and six main workflows passed |
| Fixture ownership and parsing, PR 205 | `7e153e1a` | Merged; all 24 local gate steps, 41 PR checks and four applicable main workflows passed |
| HTTP/3 WebSocket and MASQUE fixtures, PR 206 | `1806cb77` | Merged; all 24 local gate steps, 41 PR checks and four applicable main workflows passed |
| Capture workers, input and QPACK repairs, PR 207 | `b6942293` | Merged; all 24 local gate steps, 29 PR checks and applicable main workflows passed |
| Firefox and HTTP/2 preface captures, PR 208 | `b8ab9851` | Merged; all 24 local gate steps, 29 PR checks and three applicable main workflows passed |

The tooling gate includes Linux Clippy and MSRV checks through WSL. Its
source and complete logs have independent review. The 42 PR checks completed
successfully or were skipped by applicability, including successful macOS and
Windows checks. All eight applicable main push workflows passed at
`20fa0d5b`. Their exact-revision receipt is retained with the delivery evidence.

The records delivery passed all 37 applicable PR checks, including macOS and
Windows. All six applicable main push workflows passed at `d1d353e8`.
Its source, gate logs and independent reviews remain with the delivery evidence.

Current coverage reconciliation distinguishes historical complete reads,
later reviewed changes and actual gaps. Fresh reads found detached test peers
and a malformed capture parser panic. Their reviewed repairs are in PR 205.
Thirty-seven source-review paths now have reconciled receipt pointers.
Remaining capture remedies, coverage dispositions and the final combined
review stay open. The records delivery does not close the full audit.

PR 205 covers malformed capture input, redirects, WebSockets, EventSource
reconnects and HTTP/2 and HTTP/3 connection counts. The first full gate found
three fixture cancellation regressions and lint failures. Their reviewed
corrections pass the replacement gate, including 4,507 native tests and
143 doctests. All 41 PR checks pass, including both platforms and the
conformance suites. All four applicable main push workflows passed.

PR 206 collects HTTP/3 WebSocket and MASQUE workers and their original
outcomes. It bounds frames, capsules and rejection drains, rejects non-loopback
targets, and preserves caller deadline causes. Independent review accepts
the source and complete gate logs. Its 24 gate steps include 4,574 native
tests and 143 doctests. All 41 PR checks and four main push workflows pass.

Playground's migration branch is ready at `399af77e`. Its quick gate and
773 selected tests passed locally. The API selection skips 340 other tests.
The preserved Byway source snapshot passes 35 Solve and worker tests against
that Playground revision. These are local consumer checks, without a fresh
browser capture or live server acceptance.

The user chose to leave the migration branch ready and keep Foundry active.
The primary downstream working trees remain intact. The
[delivery evidence](architecture-audit/evidence.md#delivery-reconciliation)
records source preservation, retained logs and verification limits.

## Review plan

1. Inventory tracked files and assign bounded source reviews.
2. Trace requests through configuration, routing, admission, transport,
   response consumption, cancellation, and shutdown. Review independent
   tests beside the code, including platform and optional feature paths.
3. Examine trust boundaries, diagnostics, resource bounds, FFI contracts,
   ownership, error propagation, and manually assessed readability.
4. Validate findings against callers and resolved dependency source.
   Prioritize observable defects before structural cleanup.
5. Fix findings in coherent lanes, with regression tests where behavior
   changes. Review each substantial change independently.
6. Reconcile guides, references, API inventories, tooling, and roadmap.
7. Review the combined architecture. Run required gates on the exact
   rebased revision, require PR checks, and verify main after integration.

The integration owner owns this record, shared manifests, and central API
changes. Source auditors begin read-only. Implementation assignments name
their files and required checks separately.

## Review standard

The supplied Engineering standards guide review. Repository commands,
package naming, vendor patch discipline, Cargo locking, and formatting
restrictions remain authoritative. Each finding needs an affected
contract, source evidence, a cause, a remedy, and a verification method.

Search matches, file sizes, lint counts, and passing tests identify useful
questions. They do not prove that a file or lifecycle has been reviewed.
Abstractions need current compatible responsibilities. Manual review checks
names, operation grouping, invariants, and test usefulness.

## Evidence records

- [Coverage](architecture-audit/coverage.md): reviewed paths and gaps.
- [Findings](architecture-audit/findings.md): confirmed and rejected issues.
- [Inventory](architecture-audit/inventory.tsv): tracked review surfaces.
- [Retained evidence](architecture-audit/evidence.md): original reviews and logs.

The inventory records discovery, not review. Untouched upstream sources and
capture payloads have separate evidence requirements from first-party
source. Inspection, regression tests, gates, and live CI are recorded as
different kinds of evidence.

## Next

- [Design](../explanation/design.md): current ownership and wire invariants.
- [Roadmap](../roadmap.md): release, hardening, and profiling work.
