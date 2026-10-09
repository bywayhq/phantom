# HTTP/3 early-stream and ECH continuation

Read-only baseline df2ae9b7d87567907a2f273068220349dcd4750b. Completed early_streams.rs by reading remaining lines 431–1089, and read all 498 ECH test lines: 1,157 newly read lines. Completed files total 1,587 lines, with prior early_streams.rs lines 1–430 counted only once. The remaining inventory has 19 paths. Exact Git blob and working bytes are separate in JSON. No builds/tests were executed.

## Early session ownership and gates

`http3/tests/early_streams.rs` new lines 431–1089: a one-stream peer and delayed relay put two concurrent requests behind early-session admission. Both must receive the exact EarlyDataRejected unprocessed marker without holding the send lock against restart; one later path is served exactly once on the replacement session. A semaphore holds rejection publication after Quinn handshake metadata appears. A request in that window remains pending, reaches no server path before release and is served once after release. Another control accepts transport early data while invalid application metadata is held: only the already opened first request is observed, the parked second never opens, and both fail when invalid ALPS is published.

Explicit hooks force session start/open/answer ordering that ordinary scheduler delays cannot guarantee. Peer-recorded critical stream IDs/types must be exactly 2/control, 6/QPACK decoder and 10/QPACK encoder, with next uni-stream 14. Both accepted and rejected startup windows preserve a usable connection. Hooks confirm a late-opened stream is handed to the new session and a discarded early session's attempted close is suppressed. A rejected gate cannot consume the peer server stream; an accepted gate can. A controlled answer wakes a pending accept and produces exact server stream ID 3.

Principal connect/ticket/request and critical-stream waits are bounded, but several Quinn open/connect/send calls and answer awaits have no direct phase deadline. Server/relay tasks are aborted on successful paths without universal abort guards on earlier errors. Timing-based pending checks prove a finite observed wait and the served-path barriers add independent evidence; seeded delay stress does not reproduce the runtime/network schedule.

### Supported test configuration gap

At lines 714–719, PHANTOM_H3_STRESS_ITERATIONS parses any usize, including zero. The multi-threaded stress test reads that value at line 735, loops at line 751 and returns success at line 773. With zero, neither credit-wait nor handshake-window scenario runs and both counters remain zero. This is a concrete zero-observation pass condition in a test configuration, not a production transport bug. Suggested remedy: require a positive iteration count, report invalid/zero values clearly, and add focused parser controls for absent/default, positive, zero and malformed input. The parent must decide and execute an actual baseline/fix; this source read does not claim runtime reproduction. Default ten iterations remains nonzero.

## Real ECH acceptance and rejection

`http3/tests/ech.rs` lines 1–498: controlled private fixture keys configure a real BTLS QUIC server. Accepted ECH exposes the public name in outer ClientHello while the server reports accepted=true and the protected origin name. Rejection preserves Handshake and EchFailure::Rejected, and the peer observes exact TLS ech_required QUIC close code 0x179. A malformed configuration yields InvalidConfigList before any accepted peer connection during a 300 ms quiet window. The production preflight path, read earlier, supports the no-packet behavior; quiet accept alone is a finite endpoint observation rather than packet capture.

Slow address resolution and delayed record futures test the bounded ECH wait relative to a resolver notification, separating the short available-record case from a too-late GREASE case. Those use a blocking resolver sleep on its lookup thread and scheduled record task; this is controlled testing of timing, not proof of a general resolver work bound. The task may outlive the timed record wait briefly and finishes on its own; it is not cancelled through an explicit owner handle.

Frozen Chrome/Edge/Brave/Opera acceptance captures compare outer SNI, exact ECH outer fields, fixed inner name and normalized permuted extension membership. Reject captures check every recorded QUIC offer and the local replay's exact close/failure without another accepted connection during the quiet period. The test inspects concrete first-capture fields so an empty count cannot make the whole replay succeed. Results are local controlled-key contracts and fixed build capture comparisons, not fresh browser acceptance or all-configuration crypto support. Fixture-only keys and ClientHello diagnostic bytes are test material; no production secret exposure finding follows from their test Debug implementations.

## Scope retained

Prior production early-stream/gate ownership reads are not newly counted. Remaining 19 paths are explicitly listed in the JSON; the entire transport test suite is not declared audited. Earlier supported defects and platform deferrals retain their independent status.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
