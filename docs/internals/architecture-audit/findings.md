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
| A30 | P2 | Capture containment owns children before they run | Job assignment follows an already-running process | Windows child-survival reproduction confirmed; launch remedy pending |
| A31 | P2 | Profile sweeps preserve unrelated processes | Windows substring matching kills a different profile and quoted paths fail | Real owned-process controls reproduce both defects; repair pending |
| A32 | P3 | ECH support documentation states what is checked | Parameter support does not validate the HPKE public key | Source qualification confirmed; documentation correction pending |
| A33 | P3 | Short tests stay with their module | AcceptCh's 51-line tests use a separate directory and path annotation | Layout mismatch confirmed; inline move pending |
| A34 | P2 | HTTP/3 control parsing bounds retained payloads | Control decoding waits for an entire peer-declared non-DATA payload | Source candidate; retained-buffer and next-frame regressions pending |

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

A32 concerns `EchConfig::is_supported` and its parser test comment. The
method checks supported parameters and names, while cryptographic public-key
validation happens later in HPKE setup. The native oracle in the parser test
checks configuration-list acceptance, rather than encryption or a completed
handshake. The correction will qualify those two comments without changing
the native-compatible validation behavior.

A33 concerns `accept_ch.rs` and `accept_ch/tests.rs`. The separate file holds
three short tests and needs no separate fixture directory. Moving them inline
removes the unnecessary path annotation and follows the working agreement.
No runtime defect or broader abstraction change is established.

A34 traces the active HTTP/3 control stream through `FrameStream`,
`BufRecvStream` and frame decoding. The decoder waits for the complete
declared payload before discarding an unknown frame. The control path has
no identified retained-payload cap, while consuming transport chunks can
replenish QUIC receive credit. A retained-buffer regression and a following
valid control-frame test are required before selecting a canonical repair.
Large unknown frames must retain the protocol's ignore behavior.

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
