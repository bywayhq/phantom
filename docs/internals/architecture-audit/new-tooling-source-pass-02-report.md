# Autobahn source continuation

Snapshot: `2cb59371ee00b4ae6369dfff06683d090e5762f5`. Seven files were read completely from exact Git blobs, with raw SHA-256/OID, ranges and contracts in the companion JSON. No test, subprocess fixture, Cargo command, Docker image or integration operation was executed.

`scripts/conformance/autobahn.py:391: major`: Finally ignores docker rm --force exit status, so successful protocol results can be returned with a still-running container after removal failure. Log collection/removal have no deadline and can also defeat the suite deadline. Always attempt named-owner removal with finite deadlines, check its outcome and retain cleanup failure without replacing an earlier suite cause; add controlled failure and combined-failure tests. Account explicitly for uncertain detached-launch completion.

This is source-supported, without a runtime failure reproduction. The normal report path rejects an empty report, wrong agent, missing case and cardinality mismatch. Smoke additionally checks the exact eight case identifiers. Wildcard compression/full modes enforce configured counts; their exact expanded ID inventories remain a limit. Non-strict and selected close behaviors intentionally become warnings rather than failures.

The actual Rust adapter discovers a count, opens each case and echoes text/binary messages. Receive errors end a case because malformed-protocol cases require the independent Autobahn peer classification; they do not by themselves count as passing suite evidence. Timed-out cases are retained, report-update is attempted and the adapter exits failure. The outer script also checks adapter exit status and peer report classes. The isolated report tests check exact warning/failure lists rather than generating expected outcomes from client code.

Caller boundaries include OpenSSL argv/certificate creation from the first pass, the current pinned image, unique named container, loopback port mapping, finite adapter and copied-report deadlines, and the actual CI mode selector. SIGKILL and uncertain detached-launch completion are not covered by an owned-process control. Unbounded docker log collection is a retained-artifact limitation; no universal secrecy claim is made.

The first pass and old evidence remain unchanged. TLS-Anvil and WPT-EventSource runners/configs/tests remain genuinely unread in this continuation, and QUIC requirements remain partial. Capture75 stay with the capture owner. Root still owns reproductions, fixes, final Python/Ruff/ShellCheck checks and integration gates.

| File | Read lines |
| --- | --- |
| `scripts/conformance/autobahn.py` | 1–418 |
| `scripts/conformance/tests/test_autobahn.py` | 1–69 |
| `scripts/conformance/autobahn/compression.json` | 1–9 |
| `scripts/conformance/autobahn/full.json` | 1–9 |
| `scripts/conformance/autobahn/smoke.json` | 1–18 |
| `crates/phantom/examples/autobahn_client.rs` | 1–282 |
| `.github/workflows/autobahn.yml` | 1–97 |

## Next

- [Findings](findings.md): verification and integration state.
