# Audit findings

Use this ledger to connect each finding to its cause, change, and evidence.
No finding is resolved by an assignment or a proposed fix.

## Findings

| ID | Priority | Contract | Evidence | State |
| --- | --- | --- | --- | --- |
| A01 | P1 | Total deadline covers body reads | Raw and decoded ready-frame paths differ | Red/green tests; review approved |
| A02 | P1 | Invalid admission settings return a build error | Caller counts reach `Semaphore::new` above its maximum | Red/green tests; review approved |
| A03 | P1 | Disabled QUIC tickets prevent resumption | Changing the TLS profile retains an isolated cache | Red/green tests; review approved |
| A04 | P1 | Address cache bounds shared background work | Clear removes pending bookkeeping without ending work | Red/green tests; review approved |
| A05 | P2 | Proxy setup waiters receive their attempt's failure | A newer failure overwrites an older attempt's result | Red/green tests; review approved |
| A06 | P2 | EventSource owns Last-Event-ID | Templates and automatic hints can supply an unmanaged ID | Red/green tests; review approved |
| A07 | P1 | Failed WebSocket close releases ownership | Close errors retain the socket and admission | Red/green tests; review approved |
| A08 | P2 | Debug output protects arbitrary header values | Three profile field enums derive Debug over literal values | Red/green tests; review approved |
| A09 | P3 | QUIC key-update documentation matches its interface | Comment still describes an infallible interface | Source reconciled; review approved |
| A10 | P2 | GREASE parameter IDs fit their configured width | Full-range IDs overflow accepted narrow widths | Red/green tests; review approved |
| A11 | P1 | A failed boundary scan cannot report success | Manifest scan failure is lost through process substitution | Red/green tests; review approved |
| A12 | P2 | Malformed capture hex returns an error | UTF-8 slicing panics and radix parsing accepts signed pairs | Red/green tests; review approved |
| A13 | P2 | QUIC setup errors retain categories and release IDs | Provider failures report endpoint shutdown and retain an allocated ID | Red/green tests; review approved; native vendor checks pass |
| A14 | P1 | Cargo lock holders retain exclusive ownership | Stale reclamation can move a new holder's directory | Red/green tests; review approved |
| A15 | P2 | Android model constructors produce structured strings | Generic header validation accepts an embedded tab | Red/green tests; review approved |
| A16 | P2 | Tool-pin scans must finish before reporting agreement | Search status 2 is swallowed | Red/green tests; review approved |
| A17 | P2 | Freshness reports include validated fixture paths | Function-local paths are referenced outside their scope | Red/green offline tests; review approved |
| A18 | P2 | DNS test-server replies belong to their server | Detached reply tasks retain the socket after server drop | Red/green tests; review approved |
| A19 | P2 | Capture listeners accept loopback before binding | Wildcard arguments create a listener before rejection | Red/green tests; review approved |
| A20 | P2 | Captured SNI preserves the document format | UTF-8 SNI with CR/LF introduces metadata lines | Red/green tests; review approved |
| A21 | P3 | Fuzz documentation states reachable limits accurately | Short fields reach the count limit below 16 KiB | Source correction; review approved |
| A22 | P2 | Hook docs describe credential stripping precisely | Generic wording overstates protection of custom fields | Source correction; review approved |
| A23 | P1 | HTTPS discovery bounds outstanding lookup work | Pending eviction retains tasks and permits duplicate lookups | Red/green tests; review approved; lint passes |
| A24 | P1 | Replay byte limits also constrain retained metadata | Empty DATA frames grow a deque without consuming the byte budget | Three regressions red/green; breaking fix and review approved |
| A25 | P2 | Response decoding uses the actual template encoding | Forwarding-condition defaults differ from cached trust defaults | Proxy wire regression red; direct control passes; fix and composed source review approved |
| A26 | P2 | Prepared-template debug protects cached header values | Derived Debug prints copied Accept-Encoding values | Canary regression red; nested builder control passes; fix and review approved |
| A27 | P2 | SOCKS CONNECT errors retain their negotiation category | Upstream UnknownAuthMethod also denotes an unknown CONNECT reply | Red/green test; review approved; proxy suite and lint pass |
| A28 | P2 | ACK_FREQUENCY validates the selected wire format | A one-byte flag is decoded as a variable-length integer | Real connection regression red/green; review approved; vendor replay passes |
| A29 | P3 | Windows option tests survive reserved UDP ports | A raw port-zero bind bypasses the retry helper | Shared binder repair; 37 UDP tests pass; review approved |
| A30 | P2 | Capture containment owns children before they run | Job assignment follows an already-running process | Native bootstrap independently approved; 86 focused Windows tests pass; A37 shutdown gap remains |
| A31 | P2 | Profile sweeps preserve unrelated processes | Windows substring matching kills a different profile and quoted paths fail | Exact, descendant and prefix-sibling controls pass; independent review approved; A37 caller gap remains |
| A32 | P3 | ECH support documentation states what is checked | Parameter support does not validate the HPKE public key | Source correction and independent review approved; seven parser tests pass |
| A33 | P3 | Short tests stay with their module | AcceptCh's 51-line tests use a separate directory and path annotation | Inline move independently approved; all three tests pass |
| A34 | P2 | HTTP/3 control parsing bounds retained payloads | Control decoding waits for an entire peer-declared non-DATA payload | Red/green tests; 36 decoder and 52 peer tests pass; review approved; packaging pending |
| A35 | P2 | HTTP/3 cookie limits apply before splitting | Semantic validation repeats supplied-field limits over emitted crumbs | Red/green tests; 185 transport HTTP/3 and seven facade cookie tests pass; review approved |
| A36 | P2 | Known frame fields consume exactly their declared payload | Single-ID parsing leaves trailing bytes or treats a complete truncated field as partial input | Independently reviewed correction passes 41 decoder and 53 connection tests; final vendor gate pending |
| A37 | P2 | Capture shutdown continues after individual cleanup errors | First close or profile-sweep failure skips later owners and reporting | Final independent review approves owner attribution and repeated interruption; 96 capture tests pass on Windows and Linux |
| A38 | P3 | Server field-section tests use actual peer limits | Simulated limits are replaced by real SETTINGS before server assertions | Corrected controls pass; independent review and final Linux vendor check pass |
| A39 | P2 | CONNECT-UDP target ports meet the protocol contract | Template expansion accepts target port zero | Red/green Windows and Linux regressions; independent review approved |
| A40 | P3 | Shared H3 test endpoints bind loopback and handle reserved ports | Both endpoint constructors bind wildcard IPv6 with no Windows bind retry | Review approved; all 377 H3 unit tests pass on Windows and Linux; vendor replay passes |
| A41 | P3 | Stress tests execute at least one iteration | Zero iterations produce a passing test with four zero outcome counts | Actual zero now fails; parser and positive/default controls pass on Windows and Linux; independent review approved |
| A42 | P3 | Vendor checks and refresh instructions select the actual forks | Formatter commands include dependencies and notes name old package identities | Correction committed; selected formatting and ShellCheck pass; independent source review approved |
| A43 | P2 | DNS capture work is owned, bounded and observed | Detached children, unbounded query records and no operation deadlines | Authenticated baseline has three passes and nine failures; all 20 corrected tests pass on Windows and Linux; independent review approved |
| A44 | P1 | TLS message callback ownership survives an SNI context switch | Lookup uses the replacement context instead of the original callback owner | Actual process-abort regression red/green; independent review approved; native vendor checks pass; Windows staging warning qualified below |
| A45 | P2 | TLS message Debug omits message bytes | Derived Debug exposes an actual ClientHello canary as decimal bytes | Canary regression red/green; independent review approved; native vendor checks pass; Windows staging warning qualified below |
| A46 | P2 | Sensitive cookie crumbs retain diagnostic protection | Crumb policy overwrites sensitivity before dynamic-table insertion | Four regressions red/green; independent review approved; 14 captured HPACK replays pass; Windows and Linux vendor checks pass |
| A47 | P2 | Conformance image arguments cannot execute shell syntax | Whitespace-only validation forwards shell substitutions into the pinned runner | Marker reproduction and 18 failed baseline subcases; corrected eight-method suite passes; independent review approved |
| A48 | P2 | HPACK indexing arithmetic accepts legal peer limits | Three-quarter selection multiplies a peer u32 table limit in usize | Actual 32-bit debug panic and release mismatch; three corrected tests pass in debug and release; independent review and Windows/Linux vendor checks pass |
| A49 | P2 | WebSocket compression negotiation follows HTTP grammar | Unicode trim accepts non-HTTP whitespace around parameters | Two intended baseline failures and seven passes; nine corrected tests pass; independent review and Windows/Linux vendor checks pass |
| A50 | P2 | Failed downloads preserve files owned by another invocation | Planned cleanup and later path replacement lose file ownership | Initial repair passes fourteen Windows controls; both new path-replacement controls fail; repair remains open |
| A51 | P3 | Manual QUIC version reports observe at least one request | Client accepts zero and returns without observations | Zero baseline reproduced; count controls and actual default/one-request peers pass; independent source review approved |
| A52 | P2 | Autobahn failures retain finite owned cleanup | Removal exit status is ignored and cleanup operations have no deadline | Baseline has seven failures across six methods; twenty corrected methods and composed conformance suite pass; independent review approved |
| A53 | P2 | QUIC runner exits clean up only owned external resources | Outer timeout and interruption restore files without owning container cleanup | Source candidate; ownership design and bounded reproduction pending |
| A54 | P2 | Version-report servers own temporary files and close after publication failure | Certificate directory has no cleanup owner; port publication precedes close-finally | Actual controlled baseline has one pass and three intended failures; repair in progress |

## Initial source evidence

- A01: `crates/phantom/src/body.rs`, `poll_wire_frame` and
  `poll_decoded_frame`. Ready wire frames reset idle activity without
  checking total expiry. Decoded output checks expiry. Phase futures give
  a ready operation precedence; the body contract needs explicit review of
  that distinction before the remedy is chosen.
- A02: `crates/phantom/src/session.rs`, `validate_policies`, and
  `session/admission.rs`, `Admission::new`. Tokio 1.53.1's semaphore
  constructor panics above `Semaphore::MAX_PERMITS`. Check the effective
  profile bound as well as each caller override.
- A03: `crates/phantom-quic-btls/src/backend/client.rs`,
  `with_tls_profile` and `start_session`. Discarding the cache on disable
  also prevents a later early-data opt-in from using its old ticket.
- A04: `crates/phantom-net/src/address_cache.rs`, `clear`,
  `cached_or_pending`, and `Publisher`. Keep an outstanding-work reservation
  through clear and release it with the task, while excluding stale results.
- A05: `crates/phantom-net/src/proxy/http2_pool.rs`, `acquire`,
  `RouteState`, and `SetupReservation::fail`. Test two failures before an
  older waiter is polled; keep failure outcomes tied to their attempts.
- A06: `crates/phantom/src/sse/event_source/request.rs`, `SseRequest::send`,
  and `request/template.rs`, `expand_on_route`. Hook protection does not
  govern generated template defaults.
- A07: `crates/phantom/src/websocket/connection.rs`,
  `poll_pending_incoming`. Surrounding transport failure paths discard
  ownership; the stream-shutdown failure path does not.
- A08: `crates/phantom-profile/src/request_template.rs`, `websocket.rs`,
  and `proxy_connect.rs`. Redact arbitrary literal and conditional values
  rather than guessing sensitive header names.
- A09: `crates/phantom-quic-btls/src/key_schedule.rs`, `next_packet_keys`,
  compared with the implemented fallible backend key-update trait.
- A10: `crates/phantom-quic-btls/src/transport_parameters.rs` and `wire.rs`.
  Structural validation accepts narrow GREASE identifier widths, but the
  entropy draw uses the full reserved identifier range.
- A11: `scripts/ci/check-unsafe-boundaries.sh`. Injecting status 2 from the
  manifest `git grep` prints an error, then reports success and exits 0.
- A12: `crates/phantom-profile/src/request_template/capture.rs`,
  `decode_hex`. This is test infrastructure, not a runtime HTTP parser.
- A13: `crates/phantom-quic-btls/src/backend/client.rs`, `map_start_error`.
  Reconcile the pinned provider trait's error options before selecting a fix.
- A14: `scripts/dev/with-cargo-lock.sh`, `reclaim_stale_lock`. The dead
  owner check and later rename do not establish that the renamed directory
  still belongs to that owner. Reproduce the interleaving in an isolated
  repository before selecting the replacement ownership mechanism.
- A15: `crates/phantom-profile/src/browser/chrome/android.rs`,
  `model_value`, and the Edge and Opera constructors that use it. An
  embedded tab is a valid generic header value but not a structured string.
- A16: `scripts/ci/check-tool-pins.sh`, `search`, and its
  process-substitution loops. An injected ShellCheck search failure leaves
  the checker reporting agreement with exit status 0.
- A17: `scripts/ci/report-upstream-freshness.sh`,
  `built_in_chrome_recipe`, and the report arguments. The validated local
  fixture paths are unavailable in the caller. Valid mocked upstream inputs
  reach an unbound-variable failure before producing the report.
- A18: `crates/phantom-testkit/src/dns.rs`, `Drop` and `serve`.
  Aborting the main task does not abort detached delayed replies.
- A19 and A20: `crates/phantom-testkit/examples/capture_client_hello.rs`.
  Check parsed listener addresses before binding, and validate decoded SNI
  as single-line metadata before writing the capture document.
- A21: `fuzz/README.md`, `fuzz/src/http1_response/tests.rs`, and the
  fuzz workflow. The byte bound excludes the head-byte limit, but 101 short
  fields fit below 16 KiB. This is a coverage claim, not a parser defect.
- A22: `crates/phantom/src/header_hook.rs` and the customization/template
  guides. Redirect stripping names four credential headers; custom fields
  are not protected by that rule. Configured hint names have separate
  stripping, so the correction must not promise categorical retention.
- A23: `crates/phantom/src/session/alt_svc/https_records.rs`, `state` and
  `Cache::complete`. A custom resolver can remain pending indefinitely.
  Cache churn drops its bookkeeping without stopping or counting its work.
- A24: `crates/phantom/src/request/replay_buffer.rs`, `Shared::keep`.
  Examine replay cursor and wire contracts before dropping empty frames.
- A25: `crates/phantom/src/request/template.rs`, cached encodings and
  `expand_on_route`. Compare active forwarding defaults with response
  decoder policy, including malformed active values before I/O.
- A26: `crates/phantom/src/request/template.rs`, public prepared-template
  Debug. Its private cache copies arbitrary template header values, which
  bypass the profile field formatter's redaction.
- A27: `crates/phantom-net/src/proxy/socks5.rs`, `from_socks_error`.
  The resolved dependency uses `UnknownAuthMethod` both during method
  selection and for an unknown CONNECT reply status.
- A28: `vendor/quinn-proto/src/frame.rs`, ACK_FREQUENCY decoding and
  `read_as_draft02`. The older format's flag occupies one byte in
  [the IETF wire description](https://www.ietf.org/archive/id/draft-ietf-quic-ack-frequency-00.html#section-4).
  Investigate the advertised receive format and parsing boundaries before
  changing the canonical patch series or public format names.

## Executed evidence

The starting implementations fail the A01, A02, A03, and A04 regression
tests. A01 returned ready buffered data after a one-second deadline had
elapsed by two seconds. A02 accepted an oversized bound. A03 retained
resumption after disabling tickets. A04 kept two live resolver futures
under a shared-work limit of one after clear and caller cancellation.

The composed first four fixes pass 1,704 unit tests: 584 in the HTTP
client, 949 in the transport crate, and 171 in the QUIC backend. Independent
review approved their changed paths and test controls. A08's three
redaction regressions fail on the starting implementation and pass after
the fix. The documentation checker reports zero errors and warnings.

A05's original failure is replaced by a later attempt in the baseline
regression. The fixed proxy pool passes all seven unit tests, including
failure ownership and cancelled-setup controls. A10's baseline accepts a
narrow width but fails encoding. The fixed QUIC crate passes all 174 unit
tests, including the original captured-parameter and version fixtures.

A07's real reset HTTP/2 stream makes the post-Close shutdown fail while
the original WebSocket retains its socket and admission. The corrected
HTTP client passes 585 unit tests. A09 removes stale broad dead-code
allowances, confines the unused alternate constructor to tests, and
documents the implemented fallible key-update boundary. The QUIC crate's
174 unit tests also pass with that cleanup. Independent source review
approved both changes and the later Sink close-error repair. Both Sink
regressions fail on the original implementation; all three close-error
tests pass together and all-target, all-feature Clippy passes.

The isolated A14 race permits two live commands in one configured slot,
then deletes a live holder's lock when the displaced holder exits. No
Cargo command or active repository lock participates in this reproduction.
Recovery must not assume that a dead wrapper means its child work ended.

A06's original inherited-default regression stalls in network setup rather
than rejecting the default. The fixed stream binary passes all 40 SSE
tests, including active and inactive defaults, redirect activation, optional
slot order, ID reset, client-hint controls, and cross-origin redirects.
The composed client passes 593 unit tests and all-target, all-feature
Clippy. Two existing unit-test callers needed the new managed-field argument.

A12's six original profile readers fail malformed-input controls. The
corrected profile passes 307 unit tests and all-target, all-feature Clippy.
A seventh testkit reader accepts `+1` on the baseline; its strict-hex fix
passes all ten browser ClientHello fixture tests. These are fixture reader
contracts, not production TLS parsing claims.

A15's baseline accepts a tab in a model string. The checked constructors
pass the same 307 profile tests, including ASCII, quoting, escaping and
captured default-model controls. Independent source review approved them.

The complete development-tool suite passes all 35 tests on Windows and on
a native Linux checkout. The Linux run includes the offline freshness report
with jq. An initial WSL run against the Windows worktree failed because of
Windows Git paths and line endings. The native checkout also needed an
installed rustfmt toolchain; it passes with Rust 1.99.0. These failures and
the successful runs remain in the local logs.

A13's actual verification-disabled provider returns endpoint shutdown on
the original implementation. The corrected provider passes all 177 QUIC
unit tests, including invalid ECH safe formatting and valid startup.
The separate endpoint regression fails with one retained CID after failed
startup. The corrected endpoint passes its three Initial-key tests, with
repeated failures, existing connections and subsequent startup controls.
Independent source review approved the categories and CID cleanup.
Canonical archive replay and complete vendor builds remain separate checks.

The complete `quinn-proto`, `quinn`, and H3 vendor checks pass in a native
Linux checkout at `1e44399e`. That checkout preserves the four H3 license
symlinks that were flattened in Windows. These are real archive replay,
Clippy, build and selected-test checks, with no mocked Cargo steps. They
resolve the previously recorded H3 replay mismatch for this revision.

A18's baseline retains one reply socket owner after the main server task
is aborted. Its independent normal-delay control passes. A19's original
argument parser accepts a wildcard listener. A20's original UTF-8-only SNI
logic, extracted unchanged into a test helper, accepts both CR and LF.
The fixed testkit passes 88 library tests, ten fixture tests and six capture
example tests, plus a normal library build and all-target, all-feature
Clippy. The capture test iterator needed an owned-array correction to
compile, and the fixture test now returns an error rather than using a
forbidden panic shortcut. Independent review approved the production fix
and the owned-array correction.

A23's baseline starts another lookup with the configured capacity of one
while the first origin's lookup is still pending. The proposed remedy bounds
work per runtime, preserves sharing until a task ends, and keeps completed
records in the globally bounded cache. Runtime independence remains an
explicit contract; no global bound across caller-created runtimes is claimed.

The A23 fix passes all 597 client unit tests, seven HTTPS-discovery request
tests, and its 17 focused lookup tests after a fixture lint correction.
Independent review approved its task reservations and cancellation paths.

A24's baseline retains the first empty DATA frame at a zero-byte allowance.
All three new controls fail before the fix; the corrected buffer passes all
15 replay tests. This deliberately changes replayed empty-frame behavior,
with a breaking commit and migration note for both buffered APIs.

A25's loopback proxy captures `Accept-Encoding: deflate`, while the original
response reports no selected decoding. Its direct gzip control passes.
A26's generated canary appears in the original prepared-template Debug;
the nested builder control already passes after A08. The composed fixes pass
604 client unit tests, 21 response-decoding request tests, and 48 selected
SSE stream tests, plus all-target, all-feature Clippy. An initial stream
filter selected zero tests; only the corrected run supplies SSE evidence.

A27's actual no-auth SOCKS connection then receives an unknown CONNECT reply
and reports Authentication instead of Negotiation. The regression fails on
the starting implementation. The correction passes 98 proxy tests and
all-target, all-feature transport Clippy. Explicit authentication rejection
retains its category and typed source. Independent review approved the change.

## Further regression evidence

A28's real connection baseline accepts invalid flag `0x40` as a zero
threshold after consuming the following padding. Canonical flag controls
and the modern format's four varint widths pass on the same baseline.
The repair passes all 357 Quinn-proto unit tests, including every flag byte
and valid/invalid early-space controls. Independent review checks all three
parser sites and exact canonical patch replay. The renamed forks move to
Quinn-proto `.4`, Quinn `.4`, and the H3 family `.9`. Complete Windows
Quinn-proto and Quinn vendor checks pass. The full H3 vendor check passes
in the native Linux checkout at `27acd346`, with exact archive replay,
focused tests and dependent builds. Full integration gates remain pending.

A29 retains the real bound-socket option rejection and disabled-option
assertions. Its setup now uses the shared binder with no UDP options.
All 37 UDP tests pass on Windows, including the controlled reserved-port
retry and the actual `WSAEINVAL` check. No production socket behavior changes.
Independent review approves the test repair.

A30's Windows reproduction waits for an owned child before assigning its
parent to the attempt's job. The container reports containment, but the child
is outside that job and survives its close. The parent stops, and held
process handles safely stop the surviving test child. Ordinary attempt
cleanup also sweeps its temporary directory, so this does not establish
that every normal cancellation leaks. The confirmed gap is early child
creation before job assignment, including abrupt runner exit without the
sweep. A launch barrier or atomic ownership mechanism still needs design,
regression tests and independent review.

A31's separate Windows controls start harmless owned processes with profile
paths. The matching process stops, but a different profile whose path shares
the prefix also stops. An apostrophe in the target path prevents the matching
process from stopping. Every surviving control is safely terminated through
its own retained process handle. The matrix CLI rejects quoted work paths,
but the shared browser cleanup helper has no equivalent restriction.
The process-ownership lane is repairing matching and data transfer together.

A32 qualifies `EchConfig::is_supported` and its parser test comment. The
method checks supported parameters and names, while cryptographic public-key
validation happens later in HPKE setup. The native oracle in the parser test
checks configuration-list acceptance, rather than encryption or a completed
handshake. Independent review approves the source correction at `ba05c009`.
All seven existing ECH parser tests pass with the actual native oracle.

A33 moves the three short `accept_ch/tests.rs` tests inline in `accept_ch.rs`.
They need no separate fixture directory. The test bodies remain unchanged
apart from indentation, and the unnecessary path annotation is removed.
Independent review approves `44ae0f3e`; all three tests pass. No runtime
defect or broader abstraction change is established.

A34 traces the active HTTP/3 control stream through `FrameStream`,
`BufRecvStream` and frame decoding. The decoder waits for the complete
declared payload before discarding an unknown frame. The real decoder retains
16,389 bytes after the first independent 16 KiB payload chunk of an incomplete
2 MiB unknown frame. A separate oversized SETTINGS header returns Pending
instead of rejecting the declared payload before buffering. Those two tests
fail at `a077e28c`; 27 selected decoder tests pass, including a fragmented
unknown frame followed by coalesced GOAWAY. Independent review approves the
regression tests. The canonical repair remains in progress. Large unknown
frames must retain the protocol's ignore behavior. These observations concern
decoder retention, rather than a complete transport-memory measurement.

A35 compares the documented pre-split header bounds with HTTP/1.1 and HTTP/2
preparation and the actual HTTP/3 factories. One caller Cookie containing
101 short pairs passes the supplied-field bound, then fails when semantic
validation counts the emitted crumbs. A separate 100-pair Cookie whose
original name and value total exactly 32 KiB fails when repeated names count
toward the byte bound. Extended CONNECT uses the same validation path.
At `155fe999`, the three preparation regressions fail and ten controls pass,
including captured QPACK bytes and generated framing and capsule fields.
The facade's exact HTTP/3 request also fails before a successful exchange.
The remedy must retain protocol validation, supplied-field limits, generated
field accounting, and the separate peer SETTINGS field-section bound.

The initial capture repair's Windows run selects 85 tests but fails the
abrupt-runner-death control with the dependency-managed interpreter. A delayed
assignment regression then confirms that the Windows virtualenv redirector
creates the actual interpreter before job assignment. The repaired bootstrap
starts that actual interpreter, while the original tool keeps its virtualenv,
arguments, environment and exit status. Independent source review approves
those startup and matching paths. At `1d5f3f99`, all 86 focused capture tests
pass on Windows and on native Linux, where eleven Windows-only cases skip.
Shutdown after a separate cleanup failure remains open as A37.

The A34 repair at `6274e222` passes 36 decoder tests and 52 connection tests,
including actual QUIC peers, header-only excessive-load rejection and missing
SETTINGS. Independent review approves incremental skipping, cancellation,
EOF, following-frame parsing and request QPACK reservations. Identity refresh,
canonical full replay and integration gates remain pending. The declared
known-payload cap is not a whole-buffer claim; A36 examines complete malformed
known payloads separately.

The A35 repair at `a21cd99c` passes all 185 transport HTTP/3 tests and seven
facade cookie tests. Its original facade error source reports too many headers;
the correction observes all 101 distinct Cookie values in order and receives
204. Independent review confirms that original limits, generated fields,
protocol semantics and peer emitted-field limits remain enforced.

A36 concerns `proto/frame.rs`, its length-limited payload reader, and the
frame decoder's incomplete-input handling. A single-ID frame can parse its ID
without consuming the rest of its declared payload. A completely present
payload with an incomplete inner varint can also return Incomplete, even
though more outer bytes cannot repair that payload. PUSH_PROMISE shares the
inner-varint path. At `cb06e4af`, two real decoder regressions fail and 39
controls pass, including valid wide IDs and fragmented outer input. The QUIC
peer regression receives GOAWAY instead of the required frame error.
Independent review approves the regression stage; the runtime repair is in
progress through its separate canonical patch.

The A36 correction at `05357b29` maps inner truncation to a frame error only
after the declared outer payload is complete. Successful known-frame parsing
must consume that payload. Independent review approves the source and its
canonical patch. With the H3 family identity updated to `.10`, 41 decoder
tests and 53 connection tests pass. The latter includes the actual QUIC peer
that previously received GOAWAY. Final canonical vendor checks and integration
gates remain required.

A37 uses controlled failures in capture shutdown. At `ec51ac17`, both a first
container-close failure and a first profile-sweep failure leave the second
container unclosed. Two other tests show interruption propagating the cleanup
error before worker joins and publishable results. All three tests fail on
that baseline, with two failing subcases in the first test. No real processes
are killed by this fault injection. The repair must finish cleanup fan-out,
retain the original causes, join workers and publish unsuccessful results.
The first repair at `0afa0f4e` passes all four focused tests, including a success
racing interrupted cleanup and removal of its completion record. Independent
review identifies a remaining second-interruption path during cleanup or join
that can still skip reporting. That path remains open.

The final A37 correction at `e7ac6f87` protects main-thread cleanup and joins
from another SIGINT, then restores the previous handler. It matches the whole
owner name before the final attempt suffix, preserving overlapping names such
as `foo` and `foo.1`. Completed owners keep their results and resume records;
an active owner whose cleanup fails loses its success record. Independent
review approves the final source. All 96 focused capture tests pass on Windows
and native Linux at `0ad0d560`; eleven Windows-only cases skip on Linux.
The controls cover both cleanup operations, per-owner attribution, reporting,
resume, completion races and actual repeated SIGINT. Full integration remains
pending.

A38 examines the two historical server field-section failures. Both tests
install simulated peer limits before server accept polls real client SETTINGS.
The application-settings patch changed first-write state into replaceable
state, so actual default settings correctly replace those simulated limits.
The server still checks encoded field-section sizes before response and
trailer writes. The existing vendor caveat and roadmap interpret these mocks
as absent runtime enforcement without sufficient evidence. Corrected tests
must advertise real limits, assert their receipt and retain the client through
the server assertion. No production repair is supported by this source trace.

The historical two tests fail at `0ad0d560`. The first corrected source stage
does not compile because the generic builder needs a buffer type and a borrowed
header value cannot compare directly with a String. The follow-up at `0fdbaa16`
fixes both test type errors. Its two oversized-section rejections and two exact
42/539-byte acceptance controls pass on native Linux, with unchanged production
code. Independent review covers the original test design; the small compiler
correction is independently approved. Vendor notes and the roadmap now distinguish
the stale mock from actual enforcement. Final fork identity and vendor gates
remain required.

A39 traces `ConnectUdpProxy::expand`, the shared HTTP/3 proxy-path preparation,
and origin authority parsing. Explicit port zero reaches template expansion
and produces a `target_port` of zero. [RFC 9298 section 3](https://www.rfc-editor.org/rfc/rfc9298.html#section-3)
requires a target port from 1 through 65535. A pre-I/O request regression and
inclusive endpoint controls are still needed. Direct-route port policy is
outside this candidate's proposed remedy.

A40 reads the actual shared H3 `Pair` fixture. Its server and client endpoints
bind `[::]:0`, while their connection target is IPv6 loopback. This violates
the host guidance for loopback-only tests and bypasses the bounded Windows
reserved-port retry used by first-party fixtures. A standalone canonical
test-harness repair must bind loopback, retry only Windows error 10055 and
preserve every other error. This is a fixture defect, not a production listener
or fresh browser-fidelity finding.

The canonical A40 correction at `256b034a` prebinds both endpoints on IPv6
loopback, then constructs their existing Quinn configuration over those
sockets. Independent review confirms equivalent TLS and transport setup and
unchanged error returns. All 377 H3 unit tests pass on Windows with the `.11`
identity, including seven socket controls, the four real peer-limit controls,
and the earlier decoder and connection regressions. Native Linux and full
canonical vendor verification also pass at `70cf715d`: 377 package tests,
all-target/all-feature Clippy, canonical archive replay, byte comparison,
selected regression groups and dependent builds. Final integration remains
pending.

At `6b495664`, A39's unit test accepts zero instead of returning an error.
Five related template controls pass. All three public request regressions
observe an incoming proxy connection: TCP on the HTTP/1 and HTTP/2 legs,
and QUIC on the HTTP/3 leg. These are explicit failed I/O observations,
rather than timeouts or unrelated network failures. Independent review
approves the test design. The remedy rejects zero during shared preflight
with InvalidTarget and retains a distinct private cause.

A41 runs the real multi-thread stress test with
`PHANTOM_H3_STRESS_ITERATIONS=0` at `6b495664`. The runner reports success,
zero iterations, and zero outcomes for both scenarios. Invalid strings also
silently select the default in the current parser. Configuration must reject
zero and malformed values while retaining ten iterations when absent.
This is a test validity defect, not a production protocol failure.

A39's correction passes 17 focused unit tests and all 28 CONNECT-UDP
integration tests on Windows at `9f63a129`. The unit controls include private
typed causes and preserved origin-form errors. The three previously failed
requests now return InvalidTarget without the observed proxy connections;
valid requests still exercise every outer protocol. Independent review
approves the source, and its InvalidTarget documentation finding is fixed
at `779f28ea`.

A41's correction at `2cb59371` passes five parser controls on Windows.
The real stress test now fails immediately for zero. With seed 41, one
iteration observes each scenario once; the absent setting observes each
scenario ten times. These positive controls pass. Independent review
approves the function and confirms the Rust 1.88 APIs from resolved source;
that is not an executed MSRV check. The grouping finding is fixed at
`779f28ea`. Native verification initially stops on missing Cargo in PATH,
then on missing CMake before building. After supplying Cargo's path and
installing CMake 3.28.3, all A39 and A41 controls run on Linux at `2cb59371`:
17 unit and 28 CONNECT-UDP tests pass, as do five stress parser tests.
Zero exits 101 with its configuration error before either scenario runs.
The one-iteration and absent-setting controls observe both scenarios once
and ten times respectively. This remains focused evidence, not a full gate.

A42 corrects the selected fork formatter commands and package/lockfile
instructions at `01574f2e`. HTTP/2 notes now state the split-cookie and
explicit proxy-authorization exceptions to the sensitivity rule. Independent
review confirms the exceptions against the applied encoder and public docs.
The three selected package formatter checks and ShellCheck 0.11.0 pass on
native Linux. The documentation checker reports no errors or warnings.

A43 imports eleven real TLS fixture controls in `3e8d694e` and `8ab9482f`.
The initial compile fails because an example crate root needs an explicit
path to its companion test module. The corrected source compiles, but ten
controls fail while verifying the generated self-signed certificate, before
they reach the proposed resource contracts. The stalled-handshake control
reaches its outer timeout without a server operation deadline. Fixture
authentication must be corrected and positive controls must pass before
these failures can establish the remaining production defects.

A44 and A45 use canonical wrapper regression patches at `a16ab215`.
The isolated SNI test aborts inside `raw_msg_callback`: the replacement
context contains no data for the retained native callback. The test
executable exits with `0xc0000409`; the outer command reports 127. This
is an observed non-unwinding callback panic, not an observation timeout.
The separate Debug test exits 101 because the decimal ClientHello canary
appears in formatted output. The existing key-update control passes.

The production correction at `cb98b391` retrieves callback data from the
original context owned by `Ssl::new`, as the session callback already does.
`SslMessage` Debug retains direction, version, content type and byte length,
while the public message bytes remain accessible. All three controls pass
on Windows. Independent review verifies ownership against the pinned
native construction and context-switch paths and reconstructs the canonical
patch. `a80d417c` advances both wrapper-family identities to `.6`, updates
their exact pins and three lockfiles, and documents the changes. Final
native vendor checks pass, including all-target Clippy, nine selected test
groups and Rust 1.85 checks. Windows checks also exit zero and pass those
tests, but Git emits a README symlink permission error during staging.
The staging script verifies that exact link target and materializes its
contents as a regular file on Windows. Full patched-tree byte comparison
then passes. This explains the flagged line; it does not make the log clean.
Final composed gates and CI remain pending.

After fixture authentication is corrected at `03e712bc`, A43's positive
EOF, released-slot and wrong-CA controls pass. Nine production regressions
fail for the intended resource and ownership contracts. The correction at
`5fe62ee4` passes all 20 Windows and Linux tests, including actual TLS peers, corrupt
TLS versus speculative EOF, origin-error cleanup, shutdown failure retention
and a sustained body drip. Independent production review approves the
ownership and error paths. Cancellation Drop aborts owned tasks; awaited shutdown
explicitly drains them. Fixture encoding and DNS answers remain unchanged.

A46's four independent cookie-cache regressions fail at `625c85d8` because
formatted retained entries expose their canary. The canonical correction
at `bc27b126` and `5584135e` marks inserted and reused dynamic entries after
encoding, preserving the wire policy. All four tests pass. Independent
review approves the index-to-slot mapping, lookup equality and proxy rules.
With the `.11` identities, all 14 first-party captured HPACK replay tests
pass on Windows at `56fd2cf7` plus the restored lock selections committed
in `0407bc1a`. These checks do not promise redaction of every connection
buffer. Final `.11` HTTP/2 and HTTP/1 dependent vendor checks pass on Windows
and Linux at `5fe62ee4`, including canonical archive replay, byte comparison,
selected formatting and Clippy. HTTP/2 runs 47 client controls and all 157
packaged non-fixture unit tests, with one existing ignored test; HTTP/1 runs
all 61 unit tests. Whole integration and platform CI remain pending.

A47's baseline executes a harmless marker substitution through both image
roles in the exact pinned runner shell boundary. No real Docker command is
executed. The regression suite has 18 failed subcases at `e6447d5b`.
The correction at `a678ec76` permits only shell-safe image characters before
either registry mutation. All eight test methods pass, including atomic
failure and legal spelling controls. Independent source review approves
the actual assignment contexts. This validates a shell boundary, rather
than every Docker reference or an external interoperability run. All 25
conformance tests and pinned Ruff checks pass on Windows at `5fe62ee4`.

A48 traces a legal `SETTINGS_HEADER_TABLE_SIZE = u32::MAX` through frame
decode, peer settings, the writer and HPACK resize. The profile's three-quarter
choice evaluates `max_size * 3`, which can overflow usize on 32-bit targets.
Current CI uses 64-bit hosts; no explicit 64-bit-only restriction was found.
At test-only `14110f94`, the actual i686 build passes its threshold control
and fails both large-table tests with multiplication overflow. A release
build also fails the smaller large-table control: the encoded field begins
with 0 rather than the independently expected incremental-indexing byte 64.
No large allocation is needed. The correction must preserve the declared
Rust 1.68 source API and existing inclusive/fractional thresholds. The first
release launcher fails before Cargo; the corrected launcher produces this
actual optimized-build result.

The focused correction at `9f62282e` replaces both multiplications with an
exact integer threshold using subtraction and division. All three tests
pass on actual i686 debug and release builds, including maximum peer size
and twelve inclusive/fractional boundary cases. The source retains the
fork's declared Rust 1.68 API. Independent review and final composed fork
identity, replay and integration checks remain required.

A49 traces raw WebSocket extension responses from the HTTP/1, HTTP/2 and
HTTP/3 callers into compression negotiation. Unicode `str::trim` can remove
NBSP around a recognized parameter name or numeric value. RFC 6455 section
9.1 requires HTTP whitespace and token or quoted-string grammar. The
tests at `13e89d3a` pass seven controls and fail two cases because NBSP is
accepted in recognized names and values. The focused correction at
`d1319fc3` trims only space/tab and passes all nine controls. Independent
review approves the canonical source and direct handshake callers. This is
configuration/parser execution, rather than actual opening over all three
protocols. Inherited full-file formatting outside the changed block remains
unchanged. Fork identity, full replay and integration gates remain pending.

A50 traces the QUIC interoperability example's partial-file cleanup.
`create_new` rejects an existing partial file before a request starts, but
the caller then deletes that same path. Batch cleanup also removes every
planned partial path, including paths this invocation never created.
A pre-existing sentinel test can establish this without a network request.
The remedy must retain exclusive creation and clean up only owned files.

At `753ef8c0`, the actual Windows example test run passes seven controls and
fails both sentinel-preservation regressions because the existing file was
deleted. The passing controls include an authenticated loopback HTTP/3
download and a 503 response that removes its created partial. The baseline
establishes file-ownership defects. The first correction passes fourteen
Windows controls. At `c34401e7`, two further real-peer tests replace an
in-flight partial path. A 503 response deletes the replacement. A successful
response publishes its bytes instead of the body written to the original
file. Fourteen controls still pass; these two fail. Path ownership remains
unresolved, and the first correction is not final approval.

A51 is the manual Rust version-report client accepting a zero request count.
An authenticated baseline exits successfully without any request or report.
The Rust correction parses `NonZeroUsize` before reading the CA or building
the connector. The Python CLI also rejects non-positive counts before
starting its runner. Two Rust parser tests and seven Python methods pass.
The composed executable rejects zero before CA-file I/O, and actual
loopback runs finish with three default observations and one explicit
observation. Independent review approves the source. Ticket availability
wording now describes the origin-wide cache rather than promising a ticket
from the most recent connection. These runs do not refresh browser evidence.

A52 traces successful Autobahn results into a finally block that ignores
the force-removal exit code. Inspect, log collection and removal also lack
operation deadlines. A detached launch timeout occurs before the cleanup
flag is set. Controlled subprocess failures must establish these paths
before a remedy. No Docker failure or surviving-container claim is made.

At `753ef8c0`, ten controlled test methods execute the real run, CLI and
readiness orchestration. Four methods pass. Six fail, with seven reported
failures because both log and removal deadline subcases fail separately.
The results reproduce ignored cleanup statuses, missing deadlines, lost CLI
cause text and omitted cleanup after uncertain launch. External commands
are controlled fixtures; no real Docker execution is claimed.

The correction verifies a run-specific ownership label and immutable
container ID before collecting logs or removing a container. Cleanup
operations have finite deadlines. Log failures still allow removal, and
suite and cleanup failures survive together in diagnostics. Twenty focused
methods and the composed forty-four-method conformance suite pass on
Windows. Independent source review approves the correction. Real daemon
cleanup, actual signals and late creation after a timeout remain unverified.

A53 traces the outer QUIC runner timeout into file restoration without an
external resource owner. The pinned runner's ordinary timeout does stop
its case, but compliance can be interrupted before that path. Fixed global
container names make blind removal unsafe for concurrent owners. A remedy
needs verifiable ownership and scoped cleanup; actual container survival
has not been measured.

A54 executes the version-report Python runner with controlled certificate
and server boundaries and actual filesystem publication. A normal run
closes its server and retains caller outputs, but leaks internal certificate
scratch space. Preparation failure also leaks it. A real port-file write
failure after acquisition skips server close. One positive control passes
and three intended ownership controls fail. The remedy must own scratch
space for the server lifetime and cover publication with close-finally.
These controls do not prove real QUIC shutdown.

## Rejected candidates

- Nonempty `Bytes` may share a larger backing allocation. The replay limit
  explicitly counts data bytes, so this is a documented boundary rather than
  proof of a violated whole-allocation limit.
- An empty relayed datagram has stride zero. The pinned Quinn endpoint skips
  its processing loop for length zero, so this path does not divide by zero
  or spin. This is source evidence, without a new runtime test.
- TLS profile Debug includes ECH configuration. Those records contain public
  server configuration, and inspection did not establish a private-key or
  password disclosure. Arbitrary request header values remain a separate
  redaction contract.

## Integration state

All local verification so far applies to the audit lane. Integration main
remains at the starting revision. No audit change has been pushed or merged.

Local logs are retained under `target/architecture-audit` in the integration
checkout. These are focused test results, not a full gate or integration
claim. Every finding above still needs final composition and CI evidence.

These entries are source findings or candidates. Tests, independent review,
and integration evidence remain required; none is closed.

## Required evidence

Each entry records severity, affected contract, exact source locations,
cause, reproduction or inspection evidence, remedy, tests, independent
review, integration revision, and any verification limits.

Rejected candidates record the source or contract that disproves them.
Uncertain candidates remain open for investigation. A confirmed finding
cannot move to later work merely because it is difficult to fix.

## Next

- [Coverage](coverage.md): reviewed paths and gaps.
- [Audit plan](../architecture-audit.md): scope and completion criteria.
