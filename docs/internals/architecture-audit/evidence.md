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

## Next

- [Coverage](coverage.md): reviewed paths and remaining gaps.
- [Findings](findings.md): causes, remedies and verification.
