# TLS session and tracing test continuation

Read-only baseline df2ae9b7d87567907a2f273068220349dcd4750b. Three complete files, 1,728 lines, leave 16 paths not completed in this agent's additive inventory. Exact Git blob and working-file hashes are separate. No builds or tests were run; no new supported production defect was found.

## Independent ticket identity and authentication

`tls/tests/session_cache.rs` lines 1–641: independent servers use separate ticket keys, so an actual resumed handshake proves which saved ticket was selected. NewestFirst eviction/take, earliest-connection grouping under interleaved capture, Android strict oldest order and both front-eviction policies are checked against exact issuer order and peer resumption vectors. Ten Firefox connections establish nine resumed handshakes and the ten-ticket bound. These are controlled cache policy assertions, not evidence that Android ticket order was freshly captured.

An untrusted TLS 1.2 attempt consumes attempted sessions, publishes no pending session and leaves the cache empty; a later trusted connection is fresh on both ends. Capturing a session remains invisible until authenticated commit, dropping an uncommitted capture loses it, and post-commit captures become visible. Alternating hostnames retain independent tickets. Adding a client certificate starts a separate cache without consuming the anonymous connector's retained session, which still resumes. The server does not demand a certificate in that last test, so this proves cache identity isolation rather than mutual TLS authentication. Stream reads process issued tickets before observations; server/client typed errors and resumption are independently asserted.

Connection/read and final server joins are timed through known helpers, but the peer's accept/handshake/read-to-close and early-error abort/join are not uniformly guarded inside this file. Ticket policy unit seams are deliberately used to interleave capture groups while actual issuers verify identity.

## TCP resumed ClientHello comparisons

`tls/tests/resumption.rs` lines 1–742: actual ticket-learning connections precede a separately bounded ClientHello capture. Chromium-family resumed handshakes match selected stable vectors and extension sets with PSK last; early-data-permitting tickets still cause no Chromium TCP early-data offer. Firefox compares fixed ordered normalized bytes using a 64-byte opaque rustls ticket where needed, preserving every stable extension byte. A second early-data case explicitly clears the server-dependent GREASE payload length and separately proves the NSS sizing rule with the captured PSK length. Nonempty fixture counts, exact PSK identity/binder count and fresh-to-resumed extension deltas prevent an empty oracle pass.

Three concurrent connection attempts resume exactly two Chrome tickets or three Firefox tickets and the peer independently counts total resumed handshakes. It deliberately permits peer drain tasks to run separately with runtime teardown ownership. The fixed-length rustls ticketer stores sessions behind simple indexed opaque handles, so it is test-only and does not model production ticket cryptography. Its blocking server helper has no socket read/write timeout; an outer async deadline cannot abort a running spawn_blocking task. Normal client close ends that helper, but failure-path cancellation/join is not independently established here.

Captured ClientHellos have frame/byte/deadline ceilings. PSK parsing near the file end uses unchecked indexing into known generated/frozen fields; malformed fixture input can panic the test rather than return TestResult. It is not a runtime hostile-peer parser. Chromium shape comparisons intentionally omit extension order, ticket entropy and some raw stable body bytes; Firefox's fuller normalized byte comparison has its own explicit entropy exclusions. This review claims only those asserted observations, not general browser acceptance or TLS 1.2 restored-session parity.

## Tracing observer scope

`tracing_test.rs` lines 1–345: a shared OutcomeSubscriber records exact string-valued span outcomes/error kinds/TLS version/cipher fields, body byte/outcome events with explicit parents and driver progress notifications. poll_once_then_drop installs the originating dispatcher both while polling and dropping a future, supporting cancellation outcome tests. The enter hook checks Arc identity of the active subscriber state, so migrated body polls can establish they retain the origin dispatcher. Poisoned locks recover for test observation, and dynamic callsite fallback uses sometimes interest plus disabled global events to permit scoped subscriber capture.

The observer intentionally ignores most Debug fields, arbitrary events and non-string values. Span metadata is retained for the finite test lifetime without drop pruning. It is not a production tracer, general log redaction checker or bounded logging facility. An already installed global subscriber may prevent the fallback installation; the helper discards that installation error, so test environments relying on such a global subscriber need their own interest controls. No current failing test or production behavior defect is inferred from that test-only limitation.

Existing supported findings and deferrals retain their prior status. The exact remaining 16 paths are listed in the matching JSON.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
