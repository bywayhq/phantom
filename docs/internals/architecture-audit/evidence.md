# Retained audit evidence

Use this index to retrieve original source reviews and local check results.
Keep each result's revision, scope, failures and limitations when reading it.

## Historical source records

The per-pass records remain in the
[audit checkpoint at `1da2ba31`](https://github.com/bywayhq/phantom/tree/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit).
Record names in the inventory's evidence column refer to files there.
Their fragments and source ranges retain their original meaning.

The working tree keeps the plan, coverage, findings and source inventory.
Generated audit records are excluded from the source-review inventory.
Their removal does not change any remaining file's review disposition.
Earlier reports remain historical evidence, including corrections and failed
baselines. They do not establish completion on a later revision.

## Delivery reconciliation

This snapshot is dated 2026-10-13. Runtime PR 198 merged at `32a3071f`,
fixture PR 199 at `90b9b7ea`, tooling PR 200 at `20fa0d5b`, and architecture
records PR 204 at `d1d353e8`. The following receipts remain under `C:/code/phantom/target/architecture-audit`:

| Receipt | Revision and result |
| --- | --- |
| `foundation-32a-final-pr-checks.json` | `32a3071f`: all 43 PR checks succeed |
| `fixtures-90b9-final-pr-checks.json` | `90b9b7ea`: applicable PR checks succeed, including both platforms |
| `tooling-20fa-final-pr-checks.json` | `20fa0d5b`: 42 successful or applicability-skipped PR checks, including both platforms |
| `tooling-20fa0d5b-windows.gate.log` and `.gate.exit` | `20fa0d5b`: all 24 gate steps pass; exit zero |
| `main-20fa-final-push-checks.json` | `20fa0d5b`: all eight applicable push workflows succeed |
| `audit-records-d1d353e8-windows.gate.log` and `.gate.exit` | `d1d353e8`: all 22 local gate steps pass; exit zero |
| `audit-records-d1d353e8-final-pr-checks.json` | `d1d353e8`: all 37 applicable PR checks succeed, including both platforms |
| `main-d1d353e8-push-checks.json` | `d1d353e8`: all six applicable push workflows succeed |
| `fixture-7e153e1a-final-pr-checks.json` | `7e153e1a`: 41 successful PR checks, including both platforms |
| `main-7e153e1a-push-checks.json` | `7e153e1a`: all four applicable main push workflows succeed |
| `h3-masque-gate-1806cb77-independent-log-review.json` | `1806cb77`: independent acceptance of all 24 gate steps and archived raw logs |
| `h3-masque-1806cb77-independent-composition-review.json` | `1806cb77`: independent source acceptance and 117 focused controls |
| `h3-masque-1806cb77-final-pr-checks.json` | `1806cb77`: 41 successful PR checks, including both platforms |
| `main-1806cb77-push-checks.json` | `1806cb77`: all four applicable main push workflows succeed |

The tooling packet includes `source-before.log`, `source-after.log`,
`clean-before.log` and `clean-after.log` with the same
`tooling-20fa0d5b-windows` prefix. The integration owner retains
SHA-256-verified copies of the final raw logs in `foundation-32a3071f-step-logs`,
`fixtures-90b9b7ea-step-logs` and `tooling-20fa0d5b-step-logs` under the evidence
root above. These copies remain independent of temporary worktrees.
Independent review accepts the source binding and complete gate logs.
The failed earlier run remains in `tooling-877c780f-step-logs`; its failures
are not replaced by the later successful result.

The tooling gate includes Linux Clippy and MSRV through WSL. All eight
applicable main push workflows passed at exact revision `20fa0d5b`.

The records candidate's original `e74a3e92` gate remains retained under
`audit-records-e74a3e92-windows` and `audit-records-e74a3e92-failed-step-logs`.
Its native tests and Python suites pass. Its MSRV feature step fails because
the local Rust 1.88 installation lacks its standard library and manifest.
The toolchain was reinstalled before the replacement gate below.
All 37 PR checks passed at that revision, including both platforms.

The replacement records gate at `d1d353e8` passes all 22 native steps.
Its logs and zero exit use the `audit-records-d1d353e8-windows` prefix.
Raw per-step logs remain in `audit-records-d1d353e8-step-logs`, with their
SHA-256 manifest. Source and clean-state records bind the exact revision
before and after the gate. Independent source and log reviews accept it.
No Linux-only implementation changed in that delivery.

PR 204 merged that revision after all 37 applicable PR checks passed,
including macOS and Windows. `main-d1d353e8-push-checks.json` records all six
applicable main push workflows succeeding. The integrated worktree has been
removed after preserving its logs. The earlier failed gate remains retained.

The earlier coverage checkpoint is retained in
`final-coverage-reconciliation-20fa.json` and
`coverage-reconciliation-source-index.json`. The fresh source read in
`final-coverage-fresh-source-read-20fa.json` identifies remaining fixture
ownership and parser findings. Source-byte indexing alone is not semantic
approval. The parser's baseline and remedy controls remain in
`fixture-input-validation`. At `7e153e1a`, independent source and full gate-log
reviews are approved. All 24 gate steps pass, with 4,507 native tests and
143 doctests passing. The `fixture-gate-7e153e1a-windows` receipts bind equal
clean source revisions. All 74 raw step files have SHA-256-verified copies
in `fixture-gate-7e153e1a-step-logs`. The failed `5d51de09` gate is retained
in its separate failed-step archive. All 41 PR checks passed, including
both platforms and conformance suites, before fast-forwarding main.
`fixture-7e153e1a-final-pr-checks.json` retains the exact PR checks.
All four applicable main push workflows passed at `7e153e1a`.

`websocket-h3-profile-masque-whole-source-review-d1d353e8.json` binds complete
reads of the assigned WebSocket HTTP/3, profile and MASQUE fixtures at that
historical checkpoint.
It records A305–A311 and the profile and QUIC MASQUE no-change dispositions.
These are fixture source findings, without a production-client defect claim.
Their controls and repairs later merged in PR 206 at `1806cb77`. Independent
source and complete gate-log reviews accept that candidate. All 24 local
gate steps, 41 PR checks and four applicable main push workflows passed.

The composed fixture selection passes all 177 tests at clean `4111f7bf`,
with 1,179 other tests skipped. Its complete log, zero exit and equal
before/after source bindings use `fixture-composed-remedy-4111f7bf`.
Independent source reviews cover the composed ownership and parser changes.
Initial compile failures and failing controls remain in their earlier logs.
That checkpoint still required the full gate and integration checks.
The later replacement and PR results above supersede its pending state.

The full Windows and Linux gate at clean `5d51de09` fails four of its 24
steps: native and Linux Clippy, feature-row Clippy, and nextest. The other
twenty steps pass. Nextest passes 4,502 of 4,505 tests; two H2 fixture
controls and one DNS fixture control report unexpected cancellation.
The original gate log and exit use `fixture-gate-5d51de09-windows`.
All 74 raw step files are preserved in
`fixture-gate-5d51de09-failed-step-logs`, with a SHA-256 manifest.

The reviewed corrections preserve explicit coordinator stop intent,
collect H2 drivers before backup cancellation, and deliver observed read
bytes before injecting a later error. Unexpected external cancellation
still returns its original join error. Parser assertions and typed causes
remain intact through the lint corrections.

At clean `ccf8c088`, native strict workspace Clippy passes with all targets
and features. The expanded fixture selection passes all 239 tests across
four binaries, with 1,522 other tests skipped. The three earlier failing
controls and the new read and external-cancellation controls pass.
Complete logs, zero exits and equal source bindings use
`fixture-remedies-ccf8c088`. These are focused results. The replacement
full gate and PR results at `7e153e1a` above establish later integration.

### Source preservation

Read-only Git comparison uses original audit revision
`9e500991ec4cf56302177313b79fa06a5d5ffa8c`, merged fixture revision
`90b9b7ea76535530e10a33aa6502bf73b32edd45`, and tooling revision
`20fa0d5bd392487d90c612280335d2ed7677723d`. The tooling revision contains the
merged runtime and fixture history.

- Of the tooling delivery's 156 changed paths, 146 match the original audit
  exactly. The ten others are the consolidated changelog and nine capture
  files with later reviewed process/profile and callback-control repairs.
- Outside tooling, 37 paths differ between the original audit and fixture
  main. Seventeen preserve later changes: two body dependency requirements,
  fourteen fixture files and the session peer-completion consolidation roster.
  Their current versions retain the later repairs.
- The twenty remaining paths are seventeen docs/config files and three
  testkit import/module-layout files. PR 204 integrates them at `d1d353e8`,
  including the delivery-priority plan. Their earlier `074c8882` and
  `1215ca20` candidate commits remain historical evidence.
- Actual differences under first-party `src`, vendor and fuzz between the
  original audit and tooling revision consist only of those three testkit
  layout files. No production operation body, vendor patch or fuzz
  implementation is omitted.

This comparison establishes source preservation, not a new complete source
review. Current dispositions still require their original review receipts,
revision bindings and any correction or later independent review.

The inventory retains 2,432 historical rows and their original evidence
pointers, plus 33 newer paths. Presence at `d1d353e8` establishes 2,460 merged
paths and five historical-only paths. Receipt reconciliation updates source
coverage for 37 paths without erasing their earlier records. Other review
statuses retain their actual scope.

### Current source receipt reconciliation

These records remain under the evidence root above:

| Receipt | Scope |
| --- | --- |
| `final-24-receipt-dispositions-4111f7bf.json` | Original methods and contracts for 24 exact-current complete source reviews |
| `final-13-historical-chain-dispositions-7e153e1a.json` | Complete baselines and every surviving later difference for 13 paths |
| `coverage-37-root-source-bindings-d1-7e.json` | Independent Git blob, hash and line-count checks at `d1d353e8` and `7e153e1a` |
| `coverage-37-root-original-receipt-bindings.json` | All 56 selected original receipt objects retain their recorded bytes |
| `merged-fixture-13-current-source-dispositions-1806cb77.json` | Exact-current reviews and baseline-plus-difference chains for the thirteen added fixture paths, with nine new independent current-source reads |
| `merged-fixture-13-root-bindings-1806-b694.json` | Root verifies all thirteen source blobs and original receipt hashes; candidate Rust bodies remain unchanged |
| `merged-shipping-23-current-source-dispositions-b6942293.json` | Seven original whole reviews, five complete baselines with reviewed formatting differences, and eleven fresh independent whole reads of Rust children |
| `merged-shipping-23-root-bindings-1806-b694.json` | Root checks all twenty-three source bodies and fifteen original receipt hashes; scope and runtime qualifications remain |
| `remaining-fixture-17-current-source-dispositions-b6942293.json` | Individual parent assessments, exact original receipts, complete reviewed differences and three fresh independent reads |
| `websocket-four-current-source-review-b6942293.json` | Four fresh independent whole-parent reads close repair provenance gaps and identify A343 |
| `remaining-fixture-17-root-bindings-1806-b694.json` | Root checks seventeen source bodies, thirteen original receipt hashes and the four fresh parent scope bindings |
| `vendor-boundary-current-source-dispositions-b6942293.json` | Ten whole selected-file reads, one complete baseline with its reviewed difference, eleven partial upstream owners and nine selected lock graphs |
| `vendor-boundary-31-root-bindings-1806-b694.json` | Root checks all thirty-one source bodies and fifteen original receipt hashes; upstream and advisory limits remain explicit |
| `capture-completion-b6942293-independent-composition-review.json` | Exact composed capture source and documentation approval |
| `capture-completion-gate-b6942293-independent-log-review.json` | All 24 full-gate steps and retained raw logs reviewed at the clean candidate |
| `capture-completion-b6942293-final-pr-checks.json` | All 29 PR checks succeed, including macOS and Windows |
| `main-b6942293-final-workflows.json` | Both applicable push workflows and the separate main code-analysis run succeed |

The integration owner reads the original review methods, contract assessments
and limits alongside these records. All 37 source blobs match both revisions.
Hash checks establish identity only. The 24-path group includes 21 explicit
independent complete reviews, two complete manual reads without explicit
independence, and one author-only complete read. The Alt-Svc race baseline
in the 13-path group also lacks an explicit independence statement.

The thirteen-path record combines whole baselines with later semantic
reviews; it is not a fresh complete reread of every current file. Two paths
also have previously missed complete exact-current reviews. Child tests,
manifests and patches credit their own responsibility, without promoting
parent, whole-crate, runtime, browser or server coverage. Original findings
and historical verification limits remain in their receipts.

### Downstream checks

The `playground-composed-migration-399af77e` packet retains its quick-gate,
`pg-types`, `pg-egress` and `pg-api` logs and exits, plus source and clean-state
bindings before and after checks. The exact source revision is
`399af77e999a5f4f6bb094dda3cc9823cbb21359`. Its Windows quick gate passes,
along with 616 types tests, 154 egress tests and three selected API tests.
The API selection skips 340 other tests. Every command exits zero.

The `byway-phantom-migration-399af77e` packet retains `solve.log`,
`worker.log` and their zero exit records. The preserved source snapshot
passes 35 Windows tests against that Playground revision: 21 Solve and
fourteen worker tests. `byway-migration-source-hashes.json` records the
captured source bytes. The run uses the existing native V8 fork archive;
build diagnostics remain in the logs. This is not a fresh native rebuild.

The user chose to leave the Playground migration branch ready and keep
Foundry active. Primary downstream source trees remain intact. These local
consumer results do not establish fresh browser captures, deployed Solve
behavior or live server acceptance.

## Original local checks

The archive directory is
`C:/code/phantom-audit-evidence/2026-10-12-1da2ba31`.
It contains these byte-verified archives and per-entry SHA-256 manifests:

| Archive | Contents | Entries |
| --- | --- | --- |
| `tracked-records.zip` | Original audit records, including the canonical documents at the checkpoint | 2,196 |
| `original-local-evidence.zip` | Original logs, exits, runners, native probes and retained source snapshots | 14,877 |

Each manifest records the original root and relative paths. The archive
verification compares every retained entry with its original bytes. Failed
checks and their diagnostic probes remain beside passing repairs.

These local checks cover their stated hosts and revisions. They do not
replace final workspace, vendor, platform, PR or main checks. Source reviews
also retain their limits on untouched upstream code and browser acceptance.

The later `fafa0a4e` capture checks remain in
`C:/code/phantom/target/architecture-audit`, outside the checkpoint archive.
Their runner is `run-capture-input-peers.sh`. Original logs and exits use
`capture-input-peers-fafa0a4e2dbe4a4448b75fd0d5b17f3500b90210-<host>.<step>`.
Hosts are `windows` and `linux`; steps are `lifecycle`, `cookie`, `quic`,
`ruff`, `format` and `docs`. Both original handles finish with exit zero.
Each host passes 26, 21 and 12 methods respectively, with no skips.

The session/configuration packet uses `run-config-session-remedy.sh` and
`config-session-remedy-d9e6b6e7dacff2366a5846154835c8d0db81404c-<host>.<step>`.
Steps are `dns`, `quic`, `client`, `sessions`, `peers`, `fmt`, `clippy`,
`msrv`, `rustdoc` and `docs`. Both original handles exit one: eight DNS
test assertions fail strict Clippy. Every other step exits zero.

The corrected DNS/Close packet uses `run-dns-drain-remedy.sh` and
`dns-drain-remedy-12422fcc03515b73644d6728f828418a47526e08-<host>.<step>`.
Steps are `dns`, `origins`, `proxy`, `certs`, `fmt`, `clippy`, `msrv` and
`docs`. Both original handles and all sixteen steps exit zero. Each host
passes 103 tests with no skips. Root and independent reviewers read complete
logs and exits, then separately verify both clean exact revisions.

### Current source and failure records

The following records remain under the local evidence root. Each states its
actual read scope, original source bindings and verification limits.

| Receipt | Scope and result |
| --- | --- |
| `tooling-ten-and-trust-root-bindings-b6942293.json` | Thirteen source dispositions, original-object hashes and qualified supporting reads |
| `documentation-config-current-source-dispositions-b6942293.json` | Six complete document reads and structured inventory validation; six identified factual corrections applied at `a365837d` |
| `final-architecture-current-independent-review-b8ab9851.json` | Twelve cross-crate boundaries; 24 whole files and 35 partial files; no new supported source blocker |
| `capture-validation-completion-89524379-independent-composition-review.json` | Exact six-file source composition approved |
| `capture-validation-completion-gate-89524379-step-logs-manifest.json` | All 74 raw gate files retained; nextest fails two draining tests, while 23 other steps pass |
| `h3-drain-89524379-focused-v2.log` | Both draining tests pass in isolation; the earlier full failure remains unresolved |
| `h2-websocket-peer-completion-6ec7e1f5-independent-source-review.json` | Whole helper and controls approved; 41 retained native passes; integration required |
| `browser-launch-peer-completion-662aa729-independent-source-review.json` | Whole helper and controls reviewed; attached teardown error is still discarded, so changes are required |
| `browser-launch-peer-completion-fb6adf73-independent-source-addendum.json` | Complete reviewed baseline plus complete follow-up; independent error cause retained; 37 native controls pass |
| `capture-validation-completion-39488c23-independent-composition-review.json` | Exact twelve-file composition approved; no runtime or vendor change |
| `capture-validation-completion-gate-39488c23-step-logs-manifest.json` | All 74 raw files retained; 4,575 native tests pass; one TLS capture `/done` read times out, blocking integration |
| `fixture-artifact-dispositions-b8ab9851.json` | Twelve retained capture groups; provenance and data contracts, with no individual full-payload or fresh-capture claim |
| `fixture-artifact-dispositions-b8ab9851-root-bindings.json` | All 480 identities, eight mirrors and three original receipt hashes checked; zero findings closed |
| `remaining-twelve-tool-source-dispositions-b8ab9851.json` | Twelve qualified whole-current tool reviews; original methods, contracts, authorship and limits retained |
| `remaining-twelve-tool-source-dispositions-b8ab9851-root-bindings.json` | Twelve current bodies, twenty historical source bindings and fifteen original receipt hashes checked |
| `capture-validation-completion-gate-39488c23-independent-log-review.json` | All 25 raw logs read and 74 hashes verified; TLS capture failure blocks integration |
| `tls-done-39488c23-independent-diagnosis.json` | Actual native read timeout; unchanged TLS source; long generic callback does not identify the failing timer or cause |
| `tls-39488c23-focused.log` | Three unchanged OpenSSL server controls pass in isolation; no cause or full-gate closure follows |
| `eleven-tool-controls-current-source-reconciliation-39488c23.json` | Eleven new control files retain independent whole/delta reads and individual contracts and limits |
| `eleven-tool-controls-current-source-reconciliation-f146e52c-root-bindings.json` | Current and reviewed bodies and original receipts checked; eleven inventory rows added without closing findings |
| `downstream-wire-peer-completion-handoff-42a24a66-v2.json` | Qualified extracted task baseline fails three controls; remedy passes 11 default and 13 all-feature tests, Clippy and Rust 1.88 |
| `downstream-wire-peer-42a24a66-independent-source-review.json` | Whole original and repaired wire source, actual ownership controls and complete retained checks independently approved |

The first draining diagnostic had two writers sharing one log. Its overwritten
prefix and NUL gap make it unsuitable as a complete verification receipt.
The separate v2 log is complete. The failed full gate archive is unchanged.

## Next

- [Coverage](coverage.md): reviewed paths and remaining gaps.
- [Findings](findings.md): causes, remedies and verification.
