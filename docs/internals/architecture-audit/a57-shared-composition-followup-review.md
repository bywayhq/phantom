# A57 shared composition follow-up

Source approved at exact signed `54ebd4686d97e92c39cace0371b223754b8b5adf`,
following regression checkpoint `9b7789078c976a00e4dd422097de7fcb504f666f`.
The prior request-changes report at efb5c691 is preserved. Paired JSON records
eight full source files, two bounded documentation ranges, exact canonical
blobs and working hashes, three full execution logs and an independent
actual-main fixture. Unrelated audit-document imports were preserved.

Both existing retention handlers now include KeyboardInterrupt alongside
OSError. A failed Docker log command retains its original status and
diagnostic when log writing is interrupted. Interrupted summary writing
preserves collected suite and removal causes. The original primary failure
remains the explicit cause of the combined exception. A lone interrupt is
re-raised unchanged. No retry, new configuration or generic exception
suppression was added. Shared identity verification, immutable-ID removal,
caller deadlines, direct/package imports and workflow triggers are unchanged
from the approved portions of the earlier composition review.

The four new tests exercise real runner flow. They check mixed causes,
primary cause chains, one scoped removal, original lone interrupt identity
and no promised summary file after an interrupted write. Their paragraphs
separate setup, injected retention boundary, operation and assertions.
The exact test-only baseline has 22 passing controls and two intended
failures. The corrected full Windows conformance log has 88 passing methods.
Both logs were fully read.

A fresh independent fixture calls actual main for both mixed retention
paths. It verifies CLI status 2 and all existing suite/log/removal/interruption
diagnostics. It also checks that the failed summary write leaves no promised
artifact, while the log failure retains a summary containing that cause.
Its run passes 21 methods: nineteen existing runner methods and two new
independent CLI controls. The full output was read. Independent Ruff 0.16.9
lint and format checks on the changed source/tests pass; committed diff
check passes. These checks supplement the manual responsibility and grouping
review.

CONTRIBUTING now says failures remain in the report or diagnostics when the
report cannot be written. Its late daemon creation qualification remains
accurate. CHANGELOG includes report-writing failures without promising
successful report retention. No further source or documentation blocker was
found in this follow-up.

Root's exact corrected Linux run was still in progress when this review was
published; no new Linux result is claimed. Full gates and actual conformance
CI remain required. No Docker daemon, native suite, OS signal, Cargo or
process-tree cancellation ran here. Initial whole-log reads/captured output
remain outside retained-size bounds, and metadata does not cancel possible
late daemon creation. This approval covers the repaired composition, not
the whole architecture audit.

## Next

- [Findings](findings.md): verification and integration state.
