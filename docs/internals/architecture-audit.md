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

The inventory records discovery, not review. Untouched upstream sources and
capture payloads have separate evidence requirements from first-party
source. Inspection, regression tests, gates, and live CI are recorded as
different kinds of evidence.

## Next

- [Design](../explanation/design.md): current ownership and wire invariants.
- [Roadmap](../roadmap.md): release, hardening, and profiling work.
