# HTTP/2 idle and validation test continuation

Read-only baseline df2ae9b7d87567907a2f273068220349dcd4750b. Six complete files, 1,716 lines, leave 37 paths not completed in this agent's additive records. Exact Git blob and working-file hashes are recorded separately. No tests were executed and no new supported production defect was found.

## Idle connection ownership

`http2/tests/idle_close.rs` lines 1–284: scales Firefox's 170-second timer to one second. A response head and consumed DATA reset the timer, while idle PING ACKs do not. The idle connection becomes non-reusable. Dropping its last ordinary handle yields literal GOAWAY stream 0, eight zero payload bytes and peer-observed connection closure. An extended CONNECT stream reads DATA, refreshes the timer and retains the connection after the ordinary handle drops. A peer-observed GOAWAY timestamp follows dropping that stream. The timestamp is sampled after reading the frame, so it establishes the observation order; it cannot resolve kernel arrival timing independently. Under-one-second settings are rejected both by translation and public connection setup; Chrome has no idle limit.

`http2/tests/idle_ping.rs` lines 1–201: the retained Firefox fixture has exactly one zero-payload PING in the chosen idle sequence and timestamps between the two fetches. A shortened local replay checks the same request/PING ordering. An unanswered PING produces literal INTERNAL_ERROR GOAWAY, no debug data, socket close, an open-request PingTimeout and later ReusedConnectionClosed. An unrelated WINDOW_UPDATE clears the outstanding idle PING, allowing a later request. Invalid zero, maximum and incomplete timer pairs are refused, with a valid recipe control. This is source inspection of fixture and local-test assertions, not fresh browser or live-server evidence.

## Chromium PING ordering and shutdown

`http2/tests/preface_ping.rs` lines 1–363: checks the actual recipe timer values and local request-driven PING behavior. Literal HEADERS-before-PING order and monotonically increasing payloads are observed by a raw peer. A peer probe ACK bounds the ordering check without relying solely on a sleep. Disabled configuration emits no such PING. Unanswered PING yields PROTOCOL_ERROR GOAWAY with literal `Failed ping.`, closure and typed open/later-request failures. A WINDOW_UPDATE moves the expiry relative to the last read; a matching ACK stops the prior timeout. The scaled replay compares the recorded request/PING/DATA sequence, including a POST's PING before DATA. Real-time tolerance intervals remain scheduler-sensitive; they do not independently prove the production timer at browser duration.

`http2/tests/ping_peer.rs` lines 1–240: loopback port-zero raw peer validates the connection preface and initial SETTINGS. Literal frame encoders/decoders construct independent status and PING observations. A 15-second absolute deadline bounds each timeline test, with a separate two-second close observation and Windows reset/abort/broken-pipe acceptance. Request JoinSets abort their tasks on drop; replay peer JoinHandles are explicitly aborted on success but not uniformly on early errors, so runtime teardown remains their failure-path owner. The retained fixture parser filters prefixed entries and parses fields but does not validate declared frame count, uniqueness or complete required fields. Exact nonempty expected sequences and selected timestamp assertions prevent the reviewed tests from succeeding with zero observations. This helper does not promise validation of arbitrary capture files.

## Preparation boundaries

`http2/tests/extended_connect.rs` lines 1–242: checks CONNECT method/version/full URI, WebSocket Protocol extension and repeated regular-header ordering. Forbidden and uppercase fields yield typed errors. Explicit pseudo-header order is required. Chrome and Firefox overrides match literal pseudo orders and encoded stream priorities. Missing separate priority preserves the ordinary connection priority. Self-dependency and invalid weight/range are rejected, with both first-stream choices covered. These are construction tests; actual peer negotiation and emitted extended CONNECT are covered separately.

`http2/tests/request_validation.rs` lines 1–386: a stream counts every read, write, flush and shutdown poll. Invalid settings, authority/userinfo, names, values, forbidden framing fields, too many fields and oversized fields yield zero touches. Dedicated tests assert typed self-dependency, userinfo and malformed/nonzero content-length errors. Exact content-length zero preserves supplied order. Sensitive Cookie survives both semantic and ordered HPACK inputs. Static forbidden trailer categories are rejected before stream activity. Tracing observes one preparation error with the exact safe category and no response-head outcome. These tests operate on request preparation, not an already established connection; generated-field limits, byte/count boundary positives, dynamic trailers and emitted never-indexed HPACK semantics belong to other tests.

## Limits retained

No prior deferral or supported defect is marked complete by these reads. The remaining inventory includes request wire/reuse, TLS shape/session, H3 lifecycle and additional proxy tests. Production ownership paths reviewed previously are not counted again.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
