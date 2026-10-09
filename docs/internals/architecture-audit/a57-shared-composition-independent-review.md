# A57 shared cleanup composition review

Request changes at exact signed `efb5c691037dc9dc88f60413ad26c148ea02ebe8`.
Paired JSON records eight full source files, two bounded changed-document
ranges, exact canonical blobs and working-byte hashes, nine full logs and
an independent harmless reproduction. No tracked source edits were made.

The shared owner migration itself is coherent. Both direct-script and package
imports use the same identity verification and removal functions. The private
Autobahn duplicate is removed. Autobahn keeps readiness, log collection,
case validation and launch policy. Its caller-specific label is passed
explicitly, and both shared cleanup calls use the applied 30-second deadline.
The root's added paragraphs separate inspection, absence, logging and removal
without splitting related assertions or introducing a generic runner layer.

TLS-Anvil's push filter now includes the shared source and tests. Autobahn's
existing wildcard covers both. The root's full composed Windows and Linux
logs each report 84 passing methods. The Linux Ruff lint/format log and all
four direct/package help outputs were fully read. These checks validate
composition and import paths but omit the two failure cases below.

## Required repairs

1. Autobahn summary retention catches only OSError. Injecting KeyboardInterrupt
   into the real summary write after an independently failed case plus removal
   status 9 raises only the interruption message. Existing suite and cleanup
   causes are lost from the diagnostic. Add interruption to the existing
   retention aggregation, as the TLS consumer already does.
2. Autobahn log retention also catches only OSError. If Docker logs returns
   status 7 with its diagnostic and writing container.log is interrupted,
   cleanup records only the interruption and loses the prior log-command
   status and diagnostic. Suite and removal causes remain visible. Aggregate
   the interrupted write with the failed log command; preserve an original
   lone interrupt when there was no earlier command failure.
3. CONTRIBUTING says cleanup failures remain in the report without qualifying
   report-write failures. Say report or diagnostics. Keep the existing precise
   warning that an absent inspection does not cancel a late daemon launch.

The original controlled reproduction has sixteen passing controls and one
intended summary failure. The expanded reproduction has sixteen passing
controls and two intended failures. It calls the real Autobahn runner,
writes independent eight-case reports, sets independent process statuses and
injects interruption only at the filesystem retention boundary. Both failing
cases verify that immutable-ID removal was still attempted exactly once.
Neither reproduction executes Docker, Cargo, a real socket or an OS signal.
Root retained script and both logs are listed with hashes in the paired JSON.

## Remaining evidence boundaries

A shared helper does not prove actual Docker teardown. Metadata identifies
an uncertain owner but does not cancel asynchronous daemon creation after a
CLI timeout. Initial whole-log reads and captured output remain unbounded
by retained-size limits. No whole-codebase audit completion is implied.
The repaired composition needs exact-source follow-up and focused Windows
and Linux verification before approval.

## Next

- [Findings](findings.md): verification and integration state.
