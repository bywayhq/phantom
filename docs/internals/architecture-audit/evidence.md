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
fixture PR 199 at `90b9b7ea`, and tooling PR 200 at `20fa0d5b`. The following
receipts remain under `C:/code/phantom/target/architecture-audit`:

| Receipt | Revision and result |
| --- | --- |
| `foundation-32a-final-pr-checks.json` | `32a3071f`: all 43 PR checks succeed |
| `fixtures-90b9-final-pr-checks.json` | `90b9b7ea`: applicable PR checks succeed, including both platforms |
| `tooling-20fa-final-pr-checks.json` | `20fa0d5b`: 42 successful or applicability-skipped PR checks, including both platforms |
| `tooling-20fa0d5b-windows.gate.log` and `.gate.exit` | `20fa0d5b`: all 24 gate steps pass; exit zero |
| `main-20fa-final-push-checks.json` | `20fa0d5b`: all eight applicable push workflows succeed |

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

The current coverage reconciliation is retained in
`final-coverage-reconciliation-20fa.json` and
`coverage-reconciliation-source-index.json`. The fresh source read in
`final-coverage-fresh-source-read-20fa.json` identifies remaining fixture
ownership and parser findings. Source-byte indexing alone is not semantic
approval. The parser's baseline and remedy controls remain in
`fixture-input-validation`; final independent review and integration are open.

`websocket-h3-profile-masque-whole-source-review-d1d353e8.json` binds complete
current reads of the assigned WebSocket HTTP/3, profile and MASQUE fixtures.
It records A305–A311 and the profile and QUIC MASQUE no-change dispositions.
These are fixture source findings, without a production-client defect claim.
Their new controls, source repairs and integration verification remain open.

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
  testkit import/module-layout files. They are retained in the architecture/docs
  branch at `074c8882` and `1215ca20`, including the delivery-priority plan.
- Actual differences under first-party `src`, vendor and fuzz between the
  original audit and tooling revision consist only of those three testkit
  layout files. No production operation body, vendor patch or fuzz
  implementation is omitted.

This comparison establishes source preservation, not a new complete source
review. Current dispositions still require their original review receipts,
revision bindings and any correction or later independent review.

The inventory retains 2,432 historical rows and their original evidence
pointers. Its `delivery` column distinguishes `merged` paths at exact revision
`20fa0d5b`, `candidate` paths added only by the retained architecture/docs
branch, and `historical` paths absent from both. There are 2,455 merged paths,
five candidate-only audit records and five historical-only paths.
Thirty-three newer paths are added with `receipt-pending` review status.
That status requires indexing their actual review records; it does not
establish an implementation defect or erase existing verification. Presence
and these counts do not establish reviewed current bytes.

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

## Next

- [Coverage](coverage.md): reviewed paths and remaining gaps.
- [Findings](findings.md): causes, remedies and verification.
