# Audit coverage

Use this matrix to see which paths have been examined and what remains.
Pending means that discovery or assignment has not established review.

## Source review

| Area | Pass | Evidence required | State |
| --- | --- | --- | --- |
| HTTP client and session pools | Client lifecycle | Source, callers, independent tests | In progress |
| HTTP, proxy, resolver, TCP and TLS transports | Transport lifecycle | Source, cancellation and resource contracts | In progress |
| Profiles and QUIC TLS backend | Profile and FFI boundaries | Validation, public contracts, FFI assumptions | In progress |
| Testkit and fuzz workspace | Harness contracts | Parser bounds, independent oracles, fixtures | Source pass recorded; fixes in progress |
| Vendored modifications | Fork integration | Ordered patches, relevant upstream code | In progress |
| Manifests and feature/platform matrix | Dependency boundaries | Resolved graph, enabled lints, CI rows | In progress |
| Capture and conformance tooling | Tool lifecycle | Input validation, process ownership, tests | In progress |
| Development, CI and release tooling | Maintainer workflow | Commands, failure handling, workflow callers | In progress |
| Documentation and public API inventories | Published contracts | Source comparison, examples, retained evidence | In progress |
| Repository configuration | Maintainer boundaries | Active callers and enforcement | Bounded source pass recorded; remaining configuration and enforcement pending |
| Combined architecture | Independent final review | Cross-crate lifecycles and integrated changes | Pending |

## Engineering standards

The supplied standards apply throughout the audit. The source records below
establish bounded reviews; they do not establish a whole-codebase sign-off.

The [fallback observer baseline](fallback-wire-root-baseline-5a766eee.json)
records 20 passing methods and three malformed-input rejection failures on
each host. The valid literal recipe and all earlier fallback methods pass.
The reviewed repair passes all 23 fallback methods on both hosts at
`ab754e97`. Formatting, strict Clippy and Rust 1.88 checks pass. See the
[combined fixture baseline](fixture-owner-root-baseline-ab754e97.json).
Final integration gates remain open.

The [session-reuse review](session-reuse-root-source-pass-5a766eee.json)
covers the complete 561-line owner and its request, upload, proxy and
stream-cancellation contracts. Task ownership and deadline causes need
repairs. The [independent review](session-reuse-independent-source-review-e7e47abe.json)
also finds a discarded incomplete-upload error. A causal control remains
required. No permanent leak was measured.

| Review concern | Recorded work | Remaining work |
| --- | --- | --- |
| Ownership, tasks and synchronization | Client and transport lifecycle reviews, capture cleanup regressions | Untouched paths and final composed ownership review |
| Input bounds, failures and diagnostics | Parser, buffer, credential and failure-path repairs | Remaining tooling, platform paths and integrated regressions |
| Design, visibility and dependencies | Crate consumers and dependency direction; canonical exports and migrated callers | Remaining unused layers, module boundaries and final combined review |
| Names and readable layout | Manual operation and invariant review in retained source reports | Full naming, function responsibility, grouping and test-placement pass |
| Tests and verification | Independent contract reviews and recorded failing/passing regressions | Remaining assertions and exact final gates |
| Documentation and enforcement | Bounded page, command and configuration reviews | Remaining public contracts, support claims and final roadmap reconciliation |

Structural proposals need current source evidence and a complete caller
design. A new crate needs an actual consumer, dependency isolation, or a
compilation boundary. Repeated names, file sizes and passing lints alone
do not establish that need.

### Combined capture, discovery and relay repairs

The [request-error repair](fatal-template-root-remedy-a3095217.json)
passes all 39 capture and 43 template methods on both hosts. The three
malformed QUIC inputs now receive their original fatal codes. The local
resolution cause retains its original payload identity. The template
reader retains its actual oversized-head error after socket release.
All earlier positive contracts in both selections still pass.

The [independent review](fatal-template-remedy-independent-native-review-a3095217.json)
confirms both host results and source identities. It also corrects historical
line references without changing the preserved baseline evidence.

Formatting, strict target Clippy and Rust 1.88 checks pass. Broader task
ownership, additional QUIC phase policies and final integration gates
remain open. These results do not establish a whole-workspace pass.

The [fatal-input baseline](fatal-template-root-baseline-54cbca60.json)
records all 39 capture methods and 43 template methods on both hosts.
Capture passes 35 methods. Three malformed requests receive a normal close,
and the controlled resolution error is discarded. Template passes 42
methods. Its oversized-head error is missing after socket closure and
listener release. All earlier positive contracts in both selections pass.

Strict target Clippy and Rust 1.88 checks pass. HTTP formatting passes;
three new fatal-control regions need formatting. Original failures remain
bound to this revision. The later repair and its checks are recorded above;
final integration gates remain pending.

The [resolution checkpoint](peer-resolution-root-native-3fb68a34.json)
records four proxy methods passing on both hosts after the owner repair.
The original destruction, socket, rebind and simultaneous-cause assertions
now pass. Outer timeout, panic and additional failure combinations remain
open. Auth formatting, strict Clippy and Rust 1.88 checks pass.

The new QUIC method completes its real request and resource prerequisites,
then fails because the collector discarded its controlled resolution error.
Later payload identity remains unverified. This is a synthetic failure at
the actual resolver boundary. Four QUIC helper regions need formatting.
Only these five selected methods executed at this checkpoint.

The refined incoming design drives every shared connection-fatal resolver
error before dropping its connection. Ambiguous original causes remain
failures. This direction has source review; semantic repair and its native
verification remain pending. The older design's HeaderTooBig wording is
superseded by the retained resolution-control handoff.

The [peer-phase baseline](peer-phase-baseline-root-native-638fc806.json)
records the next three QUIC and three proxy-session controls at `638fc806`.
Both systems pass 35 of 36 capture methods and two of four proxy methods.
The focused nine QUIC methods overlap the complete capture example.
All original 33 capture methods still pass.

DATA before request headers receives `H3_NO_ERROR`, so the required protocol
error and later record assertions remain unverified. Illegal control-stream
DATA and the original outgoing header-limit error pass. Proxy setup rejection
reaches the destruction deadline; proxy-first collection omits the completed
origin error. These failures remain recorded before repair. Strict target
Clippy and Rust 1.88 checks pass; five files need formatting corrections.

The proxy controls required a module-discovery correction before execution.
The original rejected review remains beside the signed one-line correction
and independent approval. This adds no claim of a natural leak or complete
incoming-error policy. Broader ownership paths and final gates remain open.

The [PR snapshot](pr197-ci-snapshot-8490d46d-green.json) records all 43 checks
passing on the earlier pushed `8490d46d`, including Windows and macOS.
It does not approve the later local baseline or establish main integration.

The [combined verification](combined-remedies-root-native-3b39526f.json)
records both-host results at `3b39526f`. All 33 capture-example methods,
11 discovery methods, 41 request-template methods, 25 early-data methods
and seven session-resumption methods pass. The six focused QUIC controls
overlap the complete example. Strict target Clippy and Rust 1.88 checks
pass; formatting flags six files. This candidate still needs correction
and final gates.

The [formatter checkpoint](combined-format-root-checkpoint-e158bcb4.json)
records the six-file layout correction. Formatting and both affected
Rust 1.88 targets pass on Windows and Linux at `e158bcb4`. The complete
diff changes wrapping, optional trailing commas and sibling module order.
Behavioral results remain bound to `3b39526f`; final gates remain open.

The [independent evidence review](combined-remedies-native-metadata-independent-review-afabcca5.md.txt)
confirms the test rosters, source bindings, retained reports and formatter
delta. Its author implemented the H3 relay repair; that repair's independent
source approval comes from the separate retained source review.

The unchanged malformed-record controls now pass, including literal
repeated-header order. Discovery tests observe an actual completed result
before asserting cache effects. The held-result control checks H2 traffic
while pending, then H3 traffic after release. The completion observation
applies to these current-thread tests.

QUIC controls now observe literal page delivery through FIN before returning
the synthetic local fault. The original error and payload assertions pass.
Relay controls retain completed local errors and external cancellation,
and observe worker destruction before backup. Ordinary relay consumers pass
alongside the controls. Incoming QUIC policy, adjacent raw serving tasks,
unexercised failure combinations and final architecture review remain open.

The [root source pass](proxy-controls-root-source-pass-3b39526f.json) adds
ten complete child reads, totaling 1,781 lines. It covers concrete CONNECT
ownership, relay and multiplex controls, and the three new private owners.
Supporting parents retain their earlier bounded coverage. No new confirmed
finding was added by this pass.

The [independent capture review](template-session-capture-independent-source-native-review-3b39526f.md.txt)
also corrects one supporting range in the earlier root report: the library
capture source ends at line 237. The retained `199–245` citation receives
credit only for `199–237`; the original report remains preserved.

### Direct, tracing, DNS and SSE fixtures

The [manual source pass](remaining-fixture-root-source-pass-b9dc4bcf.json) records
five complete files, totaling 2,022 lines. It checks literal request and
body order, canary privacy, resolver routing, pool authority, stream
cancellation and idle timeout assertions. Exceptional peer ownership,
discarded fixture errors and timer causes remain under repair.
The [independent review](remaining-fixture-independent-source-review-b9dc4bcf.md.txt)
confirms those findings. Causal controls and repairs remain required.

### Runtime and parallel-session fixture owners

The [source pass](session-owners-root-source-pass-28e9eb8a.json) records
complete current reads of two owners, totaling 933 lines. An independent
manual pass binds the same source. Listener and child failures disappear,
parallel accepted/request tasks lack eager ownership, and four timeout
mappings remove the timer cause. A231, A232 and A233 require controls and
repairs. Local import grouping also needs correction in the touched owners.

The dedicated origin runtime bounds its tasks' lifetime when dropped.
This review establishes neither a permanent leak nor a measured false green
in quiet-window assertions. Supporting reads retain their bounded scope.

The [independent paired baseline review](peer-phase-baseline-independent-native-review-638fc806.md.txt)
confirms the recorded QUIC and proxy failures. Its count correction names
16 logs and 20 sidecars, plus the separate launcher. No extra observations
or fixed-source approval follow from that correction.

The parallel baseline reproduces three defects on both hosts: lost local
read/write errors and an accepted peer surviving owner Drop. All earlier
methods and healthy EOF/abort controls pass. Accepted-child shutdown is
verified on both hosts: all seven controls and retained tests pass.
Queued callers and runtime paths remain open. The
[remedy receipt](fixture-owner-root-remedies-8d0698dc.json) binds the results.

### Request-template fixture owners

The [source pass](template-owners-root-source-pass-aebdb78f.json) records
complete reads of the parent and default-profile child, totaling 1,733
lines. The independent assessment binds the same unchanged sources.
Raw server handles cross fallible operations. The HTTP/1.1 reply loop
discards malformed-head errors, and two waits discard their timer cause.
The A234 read-error repair is verified above. A233 and A235 still require
their deadline and ownership repairs and verification.

H2 drives its connection inline. H3 retains its connection on the worker
stack. Completion channels cover their final wait, not every earlier phase.
No permanent leak was measured. Cookie assertions distinguish captured
field positions from source-only neighbors. This pass adds no execution
or final lifecycle approval.

The corrected template baseline passes 45 of 49 methods on each host.
The four failures observe three original worker lifetime gaps and lost
caller/completed-worker causes. The two canonical caller helpers now retain
those owners and causes. All 49 methods pass on both hosts. Other raw callers
and exceptional combinations remain open; see the
[remedy receipt](fixture-owner-root-remedies-8d0698dc.json).
Formatting, strict target Clippy and Rust 1.88 checks pass.

### Relay fixture control children

The [source pass](relay-children-root-source-pass-a7048ed0.json) covers two
complete unchanged children, totaling 431 lines. Literal bidirectional
traffic precedes relay shutdown. The completed-outcome control observes
actual CONNECT and response traffic before testing caller cleanup.

The read fault is injected. Its observation copies the error kind and text,
not object identity. The truncated-preface case uses an in-memory stream.
This pass adds no test execution, parent review or complete lifecycle claim.
No new confirmed finding was added.

### HTTP/2 backend teardown controls

The [teardown source review](http2-teardown-source-9d6e0e14.json) covers the
complete 170-line test owner. Its two controls use actual HTTP/2 drivers,
observe a stalled upload, and join both drivers before dropping or cancelling
that upload. Operation and cleanup errors retain their causes. No new
supported defect was found in this file.

The parent and shutdown-helper reads remain partial. These controls use
in-memory streams, and this source pass adds no execution or final-gate result.

### Fixture contract controls

The [observation and acquisition pass](observation-acquisition-root-source-pass-0340818c.json)
records complete root reads of two more control owners, totaling 535 lines.
They check named real ClientHello batches and transferred fixture task
ownership. No new supported defect was found in these bounded reads.
Supporting parent reads remain partial. This adds no execution or independent
sign-off; the combined review remains required.

The [deadline control pass](deadline-control-source-pass-c3cf32c7.json)
records complete manual reads of four HTTPS-record control owners. Each
checks entered expiry, a typed inner failure and ready success through its
actual parent wrapper. No new supported defect was found in these controls.
Supporting parents remain partial. This adds no execution or final-gate result.

The [fixture control pass](fixture-control-source-pass-a11a31e2.json)
records complete manual reads of three more owners: CONNECT-UDP observation
contracts, H2 relay teardown controls and H2 WebSocket echo controls.
The controls check actual deadlines, literal exchanges, typed failures and
owned completion. The proxy rejection returns before target connection.
No new supported defect was found in these three files. Supporting owner
reads remain partial. This source pass adds no execution or final-gate result.

### Request and response convenience tests

The [query and plaintext source pass](query-plaintext-root-source-pass-be322378.json)
covers both complete parents, totaling 1,034 lines. Their contracts compare
literal request targets, header order, redirect state and decoded bodies.
Lexical joins own both futures and retain the selected first error.
No new supported code defect was found in these parents. This adds no native
result or fresh browser capture comparison; supporting implementations and
independent combined review retain their separate scopes.

The [convenience source review](convenience-owner-coverage-reconciliation-c6d63211.json)
covers both complete parents and their peer-contract children. The
[independent layout review](convenience-pacing-independent-source-review-bc8a6f18.json)
covers the subsequent fourteen blank-line additions. Every original line and
other source object is preserved. Both parent inventory entries now record
this complete source coverage.

Lexical joins own the request and peer futures. These contracts retain the
selected first error; they do not establish simultaneous-error aggregation.
The layout change adds no behavioral test or fresh native result.

### Client test coverage reconciliation

The [client test reconciliation](client-test-coverage-reconciliation-9b4e6f6f.json)
binds twelve unchanged files to retained complete source reviews. Eight other
files retain complete historical reads plus reviewed current differences.
Root verifies their current objects and reads those differences. This adds
source coverage for twenty inventory entries without refreshing native results.

The [fallback fixture review](http2-fallback-owner-independent-source-review-664383e0.json)
supplies the missing whole-file read for the 661-line fallback owner. It finds
task ownership, deadline-cause and wire-observer gaps. These and the remaining
H3 relay error paths still need controls and repairs; source coverage does not
close those findings.

## Maintainer documents

The [maintainer document review](maintainer-docs-independent-source-review-e57dade6.json)
records full manual reads of four documents: 252 lines covering lane ownership,
vendor refresh, the PR template and security policy. Supporting code reads and
historical service settings keep their stated limits. No new defect was found
in these four documents; the broader documentation audit remains open.

## Public API inventories

The [API inventory checkpoint](api-inventory-source-checkpoint-837ff74d.json)
records complete manual reads of all eight generated inventories: 4,306 lines.
Each record binds the actual file to its independent review and current source
object. Supporting implementation reads retain their stated partial ranges.

The review found an omitted optional `zeroize::Zeroize` trait boundary in
the keylog documentation. The signed correction at `794e6e6f` updates both
READMEs and the changelog. The other inventory slices found no new supported
API defect. These source reviews do not establish whole-crate implementation
coverage, fresh generator output or downstream compilation.

## Android capture lifecycle

The [Android source and baseline checkpoint](android-lifecycle-baseline-root-checkpoint-b8e1d671.json)
records complete manual reads of six Android owners and the existing tests.
Root also completes the current launcher read. Source coverage does not close
the defects found in these files.

At `b8e1d671`, both hosts run the same 48 offline methods. All 31 existing
methods pass; the seventeen new controls have four passes and thirteen causal
failures. Capture lint and formatting pass. The failures reach refusal
mutation, post-push ownership, missing later cleanup actions and nonpositive
attempt rejection. Original assertions and failures remain retained. Later
error-aggregation and interruption assertions after an earlier order failure
remain uncredited. The device command boundary is modeled; actual local
temporary-file handling runs without contacting a device.

The [synchronous follow-up checkpoint](android-synchronous-followup-root-checkpoint-802517fa.json)
records the configuration, error-retention and rejected-command repairs.
At `802517fa`, all 63 synchronous Android methods pass on both hosts.
The related selection passes 106 methods on Windows and 104 on Linux,
with two unchanged Windows-specific skips. Capture lint and formatting pass.
Windows retains eight slow-task diagnostics. Actual local temporary files
are separate from modeled device actions; no hardware result is claimed.

At `802517fa`, the six async controls have one pass and five progress failures
on both hosts. The two new entry controls fail before requesting cancellation.
Their later worker, cancellation and failure-report assertions remain
uncredited. A separate scaffold correction passes lint and formatting while
preserving all six test bodies. Original failures and lint results remain
recorded. The worker follow-up below records their later repair.

The finite-timeout repair passes all 14 unchanged controls on both hosts at
`f9210a46`. This result remains bound to that execution. The current timeout
source is unchanged. This historical checkpoint does not add a full capture
suite or final-gate result.

## Android worker and CLI follow-up

The [worker, observation and CLI checkpoint](android-worker-ui-cli-root-checkpoint-a68e171c.json)
records the later repairs and preserves the original failing controls.
Workers remain owned through cancellation. Required device and UI commands
report failed status before their output can authorize a launch or input.
The direct CLI rejects negative and nonfinite holds and keeps cold-boot
permission within one launch.

At `0b1f3bcd`, all 635 capture methods pass on Windows. Linux passes 624 with
eleven platform skips. At `a68e171c`, all thirteen new CLI controls pass on
both hosts. The full capture suite passes 648 methods on Windows and 637 on
Linux, with the same eleven skips. Capture lint and formatting pass on both.
Independent review preserves every prior method's outcome and relative order.

Device commands and UI state are modeled. Worker controls use actual local
children and pipes where their individual records state that scope. Expected
child disconnects are accepted at two fixture closure waits; unrelated errors
remain reported. These results do not establish hardware acceptance, natural
hold duration, universal thread joining or the final workspace gate.

## H3 vendor comparison

The [fixed comparison receipt](h3-license-path-normalization-independent-native-addendum-17ad91de.json)
records the license-link repair at `17ad91de` on both hosts. Linux passes all
nine controls. Windows passes seven and skips two actual-symlink controls
because the host cannot create symlinks. Both vendor checks and pinned Python
lint and formatting pass. Linux also passes pinned ShellCheck.

The helper validates exact tracked link targets and checkout representations,
then compares the referenced full license text. It leaves the checkout intact.
The original Windows path failures remain in the
[baseline receipt](h3-license-comparison-independent-native-addendum-9d6e0e14.json).
The 285 successful filtered vendor test invocations include overlapping
selections. These checks do not establish a full workspace gate.

## Recent verification

The [template capture baseline](template-capture-root-native-baseline-37c22108.json)
executes four independently reviewed controls on both hosts at `37c22108`.
Signed acceptance, UTF-8 slicing and duplicate-record rejection fail at their
original assertions. The literal repeated-header-order control passes.
Strict requests-test Clippy and Rust 1.88 checks pass. Formatting flags two
new control assignments. The parser repair remains separately unverified.

The [template and session source review](template-session-root-source-pass-da262bae.json)
covers four previously pending files, totaling 389 lines. The capture reader
needs strict hex and duplicate-record rejection. The authenticated proxy
session test needs peer ownership across failures and sibling collection.
The wire observer and session module index have separate bounded dispositions.
This source pass adds no runtime or independent review result.

The [outgoing QUIC checkpoint](quic-response-root-native-checkpoint-0b018777.json)
records the response-error repair at `0b018777` on Windows and Linux.
Both hosts pass four of five QUIC controls and 31 of 32 example methods.
All older 27 methods still pass. The focused five overlap the full roster.
The failing control now retains the local response error alongside a remote
`H3_NO_ERROR` close. Its final error-type and payload-identity assertions do
not execute. This is an incomplete remedy, not a passing capture result.

The controlled fault fires after the server writes the response. That does
not establish that the client has received its page and FIN. Dropping the
H3 server explicitly closes the connection and can interrupt delivery.
A matching client-delivery observation is required before fault injection.
Incoming-phase policy, relay ownership and final integration remain open.

Both hosts pass formatting, strict net all-targets and HTTP3-test Clippy,
and their Rust 1.88 checks. The discovery import correction is independently
reviewed and passes these format and compilation checks. Its completion
observer remains separate work.

The [relay and fallback checkpoint](relay-fallback-root-native-checkpoint-a896be8b.json)
records the reviewed nested-driver repair on both hosts at `a896be8b`.
All nineteen unchanged fallback methods pass, including actual cancellation,
driver destruction and I/O closure before backup. The trusted upload and
literal 204 response remain green. Formatting, strict HTTP3-test Clippy and
Rust 1.88 checks pass.

The corrected relay scaffold now executes nine early-data methods with three
passes and six failures, plus two passing sniffer methods. The two new
negatives reach discarded completed-sibling errors and discarded external
cancellation. Their later original-cause and task-identity assertions remain
unreached. The four original relay failures remain. These controls use real
UDP traffic with controlled faults. Coordinator ownership, other fallback
owners, malformed-wire observations and final gates remain open.

The [QUIC and relay checkpoint](quic-relay-root-native-baseline-400a900e.json)
records the corrected QUIC scaffold on both hosts at `400a900e`. The five
QUIC controls have four passes and one causal missing-error failure after a
trusted response and actual worker completion. The full example has 31 passes
and the same failure among 32 methods. The focused five overlap that roster.
Original error-type and payload-identity assertions remain downstream.

Net all-targets Clippy and Rust 1.88 checks pass, including these test controls.
The H3 and fallback selections stop at an unresolved fixture import before
execution. No new relay or fallback runtime result is credited. Formatting
flags one relay literal wrap. Earlier failed compilation and causal baselines
remain recorded. Semantic repairs and the full integration gates remain open.

The [discovery parent review](https-records-parent-independent-source-assessment-86bf000a.json)
and root reread cover all 461 lines. Three imports required grouping correction.
The 200 ms wait does not observe cache publication, and unchanged query counts
do not distinguish a completed failed lookup from a still-pending one.
These oracle gaps need explicit completion checks. No natural flake or
production routing defect was established by this source review.

The [QUIC and fallback checkpoint](quic-fallback-root-native-baseline-1efa55d8.json)
records the next baseline on both hosts at `1efa55d8`. All eighteen fallback
positives pass. Parent cancellation still fails at the original nested-driver
destruction deadline. The separate I/O observer makes backup cleanup succeed
while preserving the original operation results. The later closure assertion
remains unreached. Earlier read-only observations retain their original scope.

Both QUIC test invocations stop at a fixture type-conversion compile error.
No QUIC control runs. Production-example checks pass but exclude these test
controls. Strict fallback-test Clippy and Rust 1.88 checks pass. Formatting
flags only new QUIC wrapping. Compile correction, the causal QUIC baseline,
ownership repairs and final gates remain open.

The [H3 relay baseline](h3-relay-baseline-root-native-fc224c8c.json)
records the same nine methods on Windows and Linux at `fc224c8c`.
Five pass and four fail. Both abandonment controls reach the original
destruction deadline. Both completed-read controls observe their actual
worker finish before the unchanged stop path discards its error.

Socket reacquisition and original fault identity assertions after those
failures remain uncredited. The controls exchange real UDP datagrams with
controlled local faults. They do not establish an authenticated H3 exchange.
Formatting and strict Clippy reject the new scaffold; Rust 1.88 checks pass.
The [source review](h3-relay-named-contract-independent-addendum-604b1c29.json)
preserves the earlier bounded reads and follow-ups. Scaffold corrections,
the ownership remedy and final gates remain open.

The [corrected scaffold run](h3-fallback-controls-root-native-84b9e51a.json)
preserves those nine outcomes on both hosts at `84b9e51a`. Strict Clippy and
Rust 1.88 checks pass. The fallback selection passes eighteen methods and
fails its new nested-driver destruction control after a trusted upload.
Its original deadline remains the primary error. Backup also reports
`ConnectionAborted` on Windows and `BrokenPipe` on Linux. The later client
read-closure assertion remains unreached. Both formatting checks flag one
fallback expression. Ownership repairs and final gates remain open.

The [TCP and fallback checkpoint](origin-fallback-root-native-checkpoint-4c55e280.json)
records the reviewed TCP worker-result repair on both hosts at `4c55e280`.
All seven serving controls and all 27 ECH example methods pass. Strict
example Clippy and Rust 1.88 checks pass. Formatting rejects wrapping in
three test files; those follow-ups remain pending.

The same revision reproduces the fallback deadline defect on both hosts:
two positives pass and the entered, pending operation loses its concrete
timer cause. That baseline remains red. QUIC serving errors, final drain
limits, process-level publication and the full gate remain separate work.

The [fallback remedy receipt](fallback-deadline-remedy-root-native-4d99e490.json)
records all sixteen fallback methods passing on both hosts at `4d99e490`.
The original expiry assertion now observes its concrete timer cause. The
deadline, message and inner operation result stay unchanged. Formatting,
strict HTTP3-test Clippy and Rust 1.88 checks pass. This also verifies the
ECH control formatting follow-up; TCP execution remains bound to `4c55e280`.
Fallback ownership and wire-observer repairs remain open.

The [CLI and logical-source checkpoint](cli-logical-source-root-checkpoint-b08163ee.json)
records the actual zero/negative-repeat publication failures on both hosts.
The reviewed guard rejects these counts before output work. All nine combined
CLI and retirement controls pass at `b08163ee`. Full capture passes 557 methods
on Windows and 546 on Linux, with eleven unchanged platform skips. All previous
554 methods retain their status, relative order and skip text. Capture lint
and formatting pass on both hosts. The positive CLI control observes awaited
dispatch without starting a browser. Original failures remain recorded.

Four logical-comparison owners have complete root and independent manual
source reviews: the comparison command, logical projection, summary schema
and tests. The paragraph-only correction at `854839b4` resolves the recorded
grouping findings with identical source ASTs. It does not add a behavioral
test run. Normalized metadata consistency does not authenticate a capture or
establish browser parity. Supporting analyzer and decryption reads retain
their partial scope. Broader tooling and final gates remain open.

The [retirement checkpoint](retirement-root-checkpoint-83f793cf.json)
records six passing connection-retirement controls on both hosts at `13ba3a93`.
The full capture suite passes 554 methods on Windows and 543 on Linux, with
eleven unchanged platform skips. Every previous method retains its status,
relative order and skip text. Both formatting checks flag one exception-list
layout. The separate correction at `83f793cf` passes the six controls and
capture-wide lint and formatting on both hosts. Full-suite execution remains
bound to `13ba3a93`.

Ordinary retirement write errors retain their original connection and allow
the remaining connections to retire. Expected disconnects keep record tags;
other ordinary errors retain their original objects for cleanup reporting.
The controls inject faults after actual writes. They do not establish natural
OS-fault behavior or browser parity. Historical prerequisite failures and
additive corrections remain recorded. Broader error classification, whole
capture-owner review and final integration gates remain open.

The [loopback QUIC checkpoint](loopback-quic-root-checkpoint-8b544ea1.json)
records ten passing native cleanup controls on both hosts.
The full capture suite passes 548 methods on Windows and 537 on Linux, with
eleven unchanged platform skips. Every prior method retains its status,
relative order and skip text. Pinned Ruff lint and formatting pass on both
hosts. Expected parser rejection output and Windows slow-task diagnostics
remain recorded; no ResourceWarning occurs in these final logs.

Four small publication/bind helpers and tests now have complete source
dispositions. Supporting callers stay partial. Current source bindings and
immutable historical corrections are retained in the checkpoint. These
checks do not establish a final workspace gate or complete the wider audit.

The [exact ECH finish checkpoint](exact-ech-normal-finish-root-checkpoint-e8069b42.json)
records the pending-handshake shutdown failure and repair. All 26 exact-module
tests pass on both hosts, including destruction and socket closure before backup.
Focused strict Clippy and Rust 1.88 checks pass. Serving cancellation and QUIC
budget boundaries remain open.

The [PR checkpoint](pr197-ci-success-7d47406f.json) records all 43 checks passing
at `7d47406f`, including Windows and macOS. It does not cover later local work.

The [handler overlap checkpoint](handler-overlap-root-checkpoint-e57dade6.json)
records two causal failures per host before repair. All four unchanged controls
and twenty related methods pass on both hosts at `e57dade6`. The full capture
suite passes 538 methods on Windows and 527 on Linux, with eleven platform
skips. Independent comparison preserves every previous method's status,
skip reason and relative order. The related selections overlap.

The repair keeps later scopes filtering after an earlier scope exits and
restores the original caller handler after both finish. Remaining handler edge
cases retain source-only review; the capture owner and final gates remain open.

The [full gate checkpoint](full-gate-root-checkpoint-837ff74d.json) records all
24 steps passing at `837ff74d`. Windows passes all 4,029 workspace tests,
143 doctests with five ignored examples, and nineteen fuzz tests. The optional
feature and Rust 1.88 matrices pass. WSL checks strict workspace Clippy and
Rust 1.88 compilation; Linux native test runs remain separate records.

Independent review confirms the commands, terminal results and preserved logs.
The capture suite retains slow-task and expected parser diagnostics. This gate
does not cover later commits or close the remaining manual and combined reviews.

The [PR checkpoint](pr197-ci-success-837ff74d.json) records all 43 checks
passing at `837ff74d`, including Windows and macOS. Later commits need their
own CI results before integration.

The [TLS reader checkpoint](tls-peer-errors-root-checkpoint-c5fe57a8.json)
records six passes and two local-reader cause failures per host before repair.
All eight unchanged controls pass at `c5fe57a8`, including the original
cause identities and record tags. Deferred responses retain their original
HTTP/2 owner when another HTTP/2 or HTTP/3 peer releases them.

The full capture suite passes 534 methods on Windows and 523 on Linux,
with eleven Windows-only skips. Independent comparison preserves all
526 previous statuses, skip reasons and relative order. Windows has nine
slow-task diagnostics; both hosts have six expected parser diagnostics.
Separate independent source reviews cover the controls and their recorded
scaffold corrections. The native reviewer authored the controls.

The capture owner remains source-partial. Flush, BIO and ALPN failures,
other established TLS/reset categories, concurrent handler scopes and
final gates remain open. This record does not close all of A191.

The [QUIC coordinator checkpoint](quic-coordinator-root-checkpoint-145552a1.json)
records six causal failures among eight controls on each host before repair.
The same eight controls pass after repair at `145552a1`, along with all
29 selected QUIC, TCP, deadline and ordinary methods on each host. These
selections overlap. Formatting, strict test-target Clippy and Rust 1.88
checks pass on both hosts.

Independent review confirms original failure identities, externally
cancelled worker identity, pending-handshake shutdown and destruction before
backup. Drop abort does not establish a synchronous join. Exact serving
cancellation, outcomes beyond the cleanup budget, broader TCP classification
and final gates remain open.
The completed TCP child retains its earlier observation-warning correction.
This record does not establish whole A180 or A181 closure.

The [capture classification checkpoint](capture-classification-root-checkpoint-d2bfd093.json)
records two missing-error regressions on each host before repair. The four
unchanged controls pass after repair at `d2bfd093`, and all 31 related
controls pass on both hosts. The full capture selection passes 526 methods
on Windows and 515 on Linux, with eleven Windows-only skips. Independent
review confirms every previous method's status, skip reason and order.

Windows logs contain eleven asyncio slow-task diagnostics in proxy browser
driver methods. Both hosts contain six expected argument-parser diagnostics.
The completed suites are not described as diagnostic-free. Deferred response
attribution, broader TLS and transport classification, QUIC owners and the
final integration gate remain open. The pushed `80c7b019` checkpoint has all
43 PR checks passing; those checks do not cover these newer local changes.

The [handler scope checkpoint](handler-scope-root-checkpoint-6fee7a53.json)
records four caller-handler failures on each host, followed by passes for
the same controls after the repair at `6fee7a53`. All 27 related controls
pass on both hosts. Windows passes all 522 capture tests. Linux passes
511 and skips eleven platform-specific tests. Every previous method keeps
its status and skip reason. Independent review confirms the source
composition, original assertions and complete logs.

Documentation and capture instructions now follow the current guidance.
The CodeQL comment includes its configured JavaScript/TypeScript languages.
Configuration behavior is unchanged. The previously pushed `61dd3e9b`
checkpoint has all 43 CI checks passing, including Windows and macOS.
Those checks apply to that checkpoint. Concurrent handler scopes, QUIC
descendants, remaining capture branches and final integration gates stay open.

The [accepted-owner checkpoint](accepted-completed-root-checkpoint-9803513f.json)
records the repaired capture owner and TCP fault controls. At `9803513f`,
Windows passes all 518 capture tests. Linux passes 507 and skips eleven
platform-specific tests. The same 23 focused Python controls passed earlier
at `c07aba49`. Independent review confirms unchanged baseline assertions
and the complete capture roster.

Both hosts pass all 21 selected Rust controls at `9803513f`, including
completed child cancellation and typed panic identity. Formatting, strict
test-target Clippy and Rust 1.88 checks pass. The earlier `c07aba49` Rust
runs passed with two compiler warnings; those logs remain preserved.
The two-line correction changes only optional observation result handling.

Accepted-handler deadline and late-callback limits remain qualified.
QUIC descendants, simultaneous failures and
the final workspace gate remain open. No new PR result is inferred from
these local checks. Earlier records below describe their own revisions.

The [TCP and accepted-handler record](tcp-accepted-root-verification-1f5c128b.json)
preserves the TCP repair at `1f5c128b`: all eighteen selected tests pass on
Windows and Linux. The lifetime controls now validate child and parent
destruction, socket closure and served counts using observations captured
before backup.
Formatting, strict test-target Clippy and Rust 1.88 checks pass on both
hosts. Completed unexpected task failures and QUIC cleanup remain open.

The same record preserves the accepted-handler baseline at `55b26d84`.
Each host passes the healthy HTTP/2 control and fails two ownership
assertions: close returns before a pending handler finishes, and capture
loses a completed handler's escaped error. The closed-time assertion is
unreached. The repair is in progress. The pushed checkpoint `22141139`
has all 43 PR checks passing, including Windows and macOS. Those checks
apply to that checkpoint; final gates and combined review remain pending.

The [interruption and TCP record](interruption-tcp-root-verification-69b42db8.json)
preserves four cleanup-interruption identity failures on each host. The
same five controls pass after the reviewed repair at `1df5404c`. The full
capture suite passes 515 tests on Windows and 504 on Linux, with eleven
platform skips. Independent review read both complete logs and confirmed
every previous method's status.

Ruff then found an import-order error in the new test file. The correction
at `69b42db8` preserves every test body. The five controls pass again on
both hosts, and all 78 capture files pass Ruff lint and formatting. The
full-suite results remain bound to `1df5404c`.

The same record preserves the TCP descendant baseline at `fa97832b`:
one healthy pass and two child-destruction failures on each host. Both
negatives reach actual pending TLS reads before the lifetime assertion.
Later parent, socket and count assertions remain unreached in that baseline.
The later TCP record above preserves the repair. These records do not
replace the final gate.

The [race capture verification](race-capture-root-verification-4074c370.json)
records eight startup and five allocation failures on both hosts, followed
by passes for the same nine startup and six allocation controls. The full
capture suite at `4074c370` passes 510 tests on Windows and 499 on Linux,
with eleven platform skips. Original controls and UDP accounting assertions
remain intact. Independent review approves the focused causal comparisons.

The initial Windows socket harness queried unsupported state and changed
a socket type used by the event loop. Those failures retain no causal
closure credit. The corrected harness reaches the five intended assertions
on both hosts. Accepted tasks, loop handler restoration, undriven interruption
combinations and protocol classification remain open. These
results do not replace the final gate or combined architecture review.

The [confirmed lifecycle batch](confirmed-lifecycle-batch-5973305d.json)
passes all 66 selected HTTPS/ECH tests on both hosts at `5973305d`.
Formatting, strict Clippy and Rust 1.88 checks pass. All seven parallel
worker controls retain their original assertions. Other exact-serving and
QUIC/TCP ownership paths remain open.

The same batch records the capture suite at `dcb664a5`: Windows passes
495 tests; Linux passes 484 with eleven platform skips. Capture source is
unchanged through `5973305d`. Both deferred launch-worker controls now
pass, including exact failure, Future and cancellation identities.
Undriven cleanup combinations remain open. Final gates remain pending.

The [launcher checkpoint](launcher-push-checkpoint-4ecba88a.json) passes
all seven cleanup controls within the full capture suite at `4ecba88a`.
Windows passes 493 tests. Linux passes 482 with eleven platform skips.
Independent review confirms that earlier source and changelog. The newer
deferred executor verification appears above. Undriven removal-error
combinations and final integration gates remain pending.

The earlier [focused launcher verification](browser-launch-root-fixed-6dd79222.json)
records the original seven-control comparison and remaining boundaries.

The historical [ECH and launcher baselines](ech-launcher-root-baselines-c1f659e3.json)
confirm four causal failures in each area on both hosts. The ECH controls
exercise actual primed HTTP requests and pending workers. The launcher
controls observe harmless child processes and temporary profiles before
backup cleanup. Original test prerequisite flaws remain separate. Repairs
and verification of the combined changes are in progress.

The [browser-driver fix](proxy-browser-context-root-fixed-59634fd7.json)
passes the same seven controls on both hosts at `59634fd7`. The corrected
baseline passed two and failed five. Cleanup now destroys the acquired
resources and retains the original and ordered cleanup failures. The full
capture suite passes 486 tests on Windows and 475 with eleven platform
skips on Linux. Constructor and reporting failures have source review;
these seven controls do not drive them or installed Firefox and Android.
The earlier cross-task identity test flaw remains recorded separately.

The [UDP listener review](udp-listener-accounting-independent-source-review-c0dc392b-compact.md.txt)
approves separate listener/address records at `c0dc392b`. All 15 focused
methods pass on Windows and Linux. The same selection at `14e43021`
passes thirteen and fails the two new accounting controls. These controls
call the actual recorder with literal observations and a synthetic QUIC
path. They establish no browser or UDP packet-delivery parity.

The [remote-client checkpoint](remote-client-root-native-receipt-e4544b67.md.txt)
passes all 35 focused methods on both hosts at `e4544b67`. Original cause,
pending-command, credential and socket assertions remain unchanged.
The unsolicited-handler control fails at the intermediate `8761b046`
and passes after the final receive-boundary correction.
Independent source and native reviews approve this bounded remedy.

The complete capture suite passes 477 methods on Windows. Linux passes
466 and skips eleven Windows-specific methods. Both guarded runs exit
zero. These tests use scripted peers and controlled faults. Browser-driver
cleanup and the remaining capture findings are still open.

The [owner and tooling checkpoint](owner-roster-root-native-receipt-fd518ed0.md.txt)
passes the same 63 focused Rust methods on both hosts at `fd518ed0`.
Negotiated origin abandonment now reaches destruction before backup and
socket closure. Facade all-target Clippy and Rust 1.88 checks pass.
All 35 development methods pass on both hosts. The initial Linux run's
eleven missing-formatter errors remain recorded beside its setup repair.
These checks cover the named changes; the full gate remains pending.

The [remote baseline review](remote-client-lifecycle-baseline-native-independent-addendum-2e9995c1.md.txt)
records 34 methods on each host at `2e9995c1`: 24 pass and ten fail.
The failures follow actual loopback upgrade, command and event exchanges.
They concern socket cleanup, command causes and registrations, navigation
failure retention, and benign credential canaries. The fixed result is above.

At `3a68a39f`, the [local checkpoint](ci-repair-root-native-receipt-3a68a39f.md.txt)
passes the same 105 focused methods on Windows and Linux: 57 HTTPS-record,
44 client-hint and four HTTP/2 upload methods. The two count deadline
regressions now retain the original `Elapsed` cause and context.
The [independent focused review](checkpoint-focused-tests-independent-native-addendum-3a68a39f.md.txt)
binds unchanged controls and method sets to the earlier baselines.

Both hosts pass formatting, workspace strict Clippy with all targets and
features, Rust 1.88 workspace checks, and JSON-only all-target Clippy and
Rust 1.88 checks. The [CI source review](ci-test-dependencies-conversions-independent-source-review-c0794ff4.md.txt)
approves the explicit test dependency and two removed identity conversions.
The [terminal review](checkpoint-ci-repairs-terminal-independent-native-addendum-3a68a39f.md.txt)
confirms all eight steps and clean revision guards. The full gate and final
review remain.

The [hint remedy review](hint-ownership-remedy-native-independent-addendum-d9418c3a.md.txt)
confirms all 44 unchanged methods pass on Windows and Linux at `d9418c3a`.
The seven baseline failures now pass their original destruction and concrete
peer-cause assertions. Formatting, strict Clippy and Rust 1.88 pass.
The later import/drain cleanup at `f78f63ca` has separate source approval.

The [exact collector review](https-record-origin-serving-fixed-independent-native-e8a0c593.md.txt)
confirms all 52 unchanged methods pass on both hosts at `e8a0c593`.
Both completed serving payload identities are retained. Seven ordinary
QUIC methods exercise the pre-spawn acquisition correction; no OS lookup
fault is injected. All ancillary checks pass. Remaining descendants and
drain-error paths are separate open work.

The [count baseline review](quic-count-deadline-baseline-native-independent-addendum-24857484.md.txt)
confirms five new synthetic controls within 57 methods at `24857484`.
Both hosts pass 55 methods and fail the two missing-Elapsed assertions
after entered, pending waits and the original 20-second expiry. This tests
private owner/counter state, without endpoint or handshake evidence.

The [capture-owner source pass](capture-owner-evidence-reconciliation-7fd07b02.md.txt)
completes manual reads of remote, launcher and race owners: 2,466 lines.
Exact source and range identities bind those reads. Eight findings were
recorded as A186 through A193; their current states are in the findings
ledger. Source coverage adds no execution credit.

The [exact serving baseline](https-record-origin-serving-baseline-native-independent-addendum-f75f148b.md.txt)
runs the same 52 methods on both hosts at `f75f148b`: 51 pass and one fails.
Two real successful requests and completed worker witnesses precede the
discarded-error assertion. Formatting, strict Clippy and Rust 1.88 pass.
The collector repair remains in progress.

The [QUIC acquisition review](https-record-quic-port-independent-source-73804ad4-working.md.txt)
approves address lookup before task creation. The correction is integrated
at `f0939302`; composed native verification remains pending.

The [schema layout review](quic-schema-paragraph-independent-root-review-6b433577.md.txt)
approves 22 paragraph boundaries in two complete manually read files.
Integrated `73804ad4` preserves all statements, location-free syntax trees,
the analyzer and controls. No runtime suite was repeated for spacing.

The [hint ownership baseline](hint-ownership-baseline-native-independent-addendum-82d9e082.md.txt)
reproduces seven failures in 44 selected methods on each host at `82d9e082`.
Thirty-seven methods pass. Six failures concern finite task destruction
after caller exit; one concerns a discarded completed peer error. Actual
request and cause prerequisites pass before those assertions. The repair
is in progress. Formatting, strict Clippy and Rust 1.88 checks pass.

The [fixed HTTPS review](https-record-origin-fixed-independent-native-aed0b559.md.txt)
independently approves the identical fifty-method roster on both hosts.
The unchanged abandonment control now observes destruction before backup
and socket closure. Serving-child outcomes remain separate open work.

The [native progress receipt](native-progress-aed0b559.json) records the
outer deadline repair, exact-origin cancellation repair and reserved-port
fixture correction. All fifty selected HTTPS methods pass on both hosts
at `aed0b559`, with formatting, strict Clippy and Rust 1.88 checks passing.
Completed serving failures and QUIC/TCP descendant ownership remain open.

The QUIC analyzer correction passes nineteen unchanged controls at
`8c519464`, following two causal baseline failures. The complete capture
suite passes 465 methods on Windows; Linux passes 454 and skips eleven.
The correction was integrated at `c8f7e98e` with its complete capture tree
matching the verified `8c519464` lane. The later paragraph-only follow-up
is recorded above.
These are synthetic packet and fixture checks, not browser acceptance.

The [hint admission review](hint-admission-native-independent-addendum-8fb745de.md.txt)
confirms all thirty-three selected methods pass on Windows and Linux at `8fb745de`.
The retained waiting request reaches actual same-key HTTP/2 capacity before
the first response is released. Every pending probe is dropped before that
request advances. Formatting, strict focused Clippy and Rust 1.88 pass.
This verifies a source-supported timing correction, not a historical flake.
Hint peer ownership and structural cleanup remain separate.

The [HTTPS-record source pass](https-record-fixture-standards-review-1088701d.md.txt)
records four complete independent owner reads and bounded root checks of
actual acquisition, serving, finish and deadline scopes. New fixture
ownership/error findings await causal controls and repairs. This does not
establish a production ECH failure or a whole-owner root sign-off.

The [certificate repair](certificate-inline-origin-fixed-native-independent-addendum-1088701d.md.txt)
passes all forty-three unchanged methods on Windows and Linux at `1088701d`.
The two inline-origin controls first failed after their actual protocol
prerequisites at `48c41af8`. They now retain the original request and origin
errors. Earlier missing-certificate and completed-peer controls also pass.
Formatting, strict focused Clippy and Rust 1.88 checks pass on both hosts.
The complete requests suite then passes all 489 methods on each host, with
no skips. The [composition receipt](certificate-repair-and-request-composition-1088701d.json)
records actual outcomes without treating them as source-review coverage.
Final workspace gates, CI and architecture sign-off remain separate.

The [remote fixture repair](remote-peer-fixed-native-independent-addendum-d27da0c1.md.txt)
passes all twenty-three unchanged methods on Windows and Linux at `d27da0c1`.
All six controls that failed at `496c38c1` now reach and pass their original
handler, writer and typed-cause assertions. The complete capture suite passes
461 methods on Windows. Linux passes 450 and skips eleven platform methods.
Neither focused nor broader logs contain resource warnings. Ruff and formatting
pass. These checks cover cooperative fixtures, not the final integration gate.
The [root checkpoint](remote-and-certificate-checkpoint-d27da0c1.json) retains
the exact logs and distinguishes source review from execution.

The corrected certificate baseline at `14eb6aae` reaches all seven causal
negatives on both hosts. Its wrong-authority QUIC control now passes the exact
DecryptError prerequisite before rejecting the broad observer. Thirty-four
positive methods and ancillary checks pass. The [intermediate review](certificate-remedy-independent-source-review-31d67845.md.txt)
requires another fix: two HTTPS callers discard a completed origin failure
when the request also fails. The later unchanged-control repair is recorded above.

The [prepared upload repair](prepared-body-remedy-independent-native-0418ee46.md.txt)
passes all nineteen methods on Windows and Linux at `0418ee46`. Three
unchanged causal controls now observe finite peer destruction and retain
the concrete completed peer failure. The corrected baseline and source
reviews remain recorded. The known form length is checked before allocation;
no adversarial large allocation was attempted.

The [proxy writer repair](proxy-writer-fixed-native-independent-addendum-0418ee46.md.txt)
passes all thirty-two methods and the isolated traced proxy test without
resource warnings on both hosts. Its [launcher correction](proxy-writer-native-launcher-independent-correction-0418ee46.md.txt)
binds the actual seven-stage run. Formatting, Ruff, strict focused Clippy
and Rust 1.88 checks pass. These are focused checks, not the full gate.

The broader capture run passes 455 methods on Windows. Linux passes 444
and skips eleven platform methods. Four Linux warning headers remain.
The [isolated attribution](browser-remote-warning-independent-attribution-0418ee46.md.txt)
then identifies accepted browser-remote fixture resources on both hosts.
Its three methods pass despite warnings. Exact cancellation timing remains
unmeasured. The later repair is recorded above. The old warnings remain
historical evidence.

The [trust review](trust-oracle-native-independent-addendum-1690c493.md.txt)
confirms all twenty-nine selected proxy methods pass on both hosts at
`1690c493`. That combined batch failed lint and MSRV on unrelated prepared
test imports. Later focused checks pass at `0418ee46`. The old
[compilation checkpoint](checkpoint-5339f15b.json) remains historical evidence.

The [certificate checkpoint](certificate-outcome-native-checkpoint-843e57c2.json)
runs forty-one methods on both hosts: thirty-four pass and seven fail.
Two TCP controls expose broad rejection assertions. Four controls expose
discarded completed peer failures. The QUIC control fails its alert
prerequisite before testing the observer; the diagnostic shows signature
verification failure. The later corrected prerequisite is recorded above.
The later focused remedy approval is recorded above.
Formatting, strict focused Clippy and Rust 1.88 checks pass.

The [capture review](alps-capture-remedy-independent-native-review-6c98bb6c.md.txt)
approves all eighteen focused repaired methods on both hosts. The original
Windows deadline also passes unchanged; its earlier failure cause remains
unknown. Historical broader warnings remain qualified. Final gates remain.

The [interruption baseline](alps-capture-interruption-native-d83c47db.md.txt)
runs eighteen capture methods at `d83c47db` on both hosts. Linux passes
fifteen and fails three. Windows passes fourteen and fails four. Controlled
interrupted-start/join bookkeeping reaches two unsafe-close assertions.
Cleanup-only interruption reaches the original-identity assertion. Windows
also fails the existing held-reader deadline control. Its cause is open.
Ruff lint passes; format reports one long signature. The later repair passes
the unchanged controls as recorded above.
Original bounds and historical failures remain recorded.

The [certificate standards review](certificate-request-standards-independent-review-7b6733fc.md.txt)
reads both complete certificate test owners and the identity support owner.
The [root source pass](client-certificate-root-source-review-7b6733fc.md.txt)
separately reads the parent and two support owners. Missing-certificate
oracles and outer peer-result handling need causal controls and remedies.
These findings concern tests; no production certificate failure is shown.
The version-byte remainder candidate has no established reachable defect.

Independent native reviews approve the reported red
[trust diagnostic](trust-rejection-diagnostic-independent-native-addendum-56e65606.md.txt)
and [capture baseline](alps-capture-baseline-independent-native-addendum-659e5576.md.txt).
The capture roster correction fixes a metadata parser that misattributed a
concatenated unittest heading. Counts and actual runtime outcomes are unchanged.

One [Linux output-holder observation](linux-output-holder-observation-113e5656.md.txt)
replays the original 108 methods at `113e5656`: 107 pass and the known trust
control fails. All ten previously retained-output methods pass. Sampling
observes 74 test processes, with no additional writer captured. It misses
short-lived processes and changes timing. The historical cause remains open.
The original failure policy and evidence are unchanged.

The [independent output assessment](linux-output-holder-independent-assessment-113e5656.md.txt)
checks the complete run logs and parses all 1,831 sampling records. It
qualifies missing processes and descriptor observations. The installed
nextest detector measures observed output EOF after child exit. Delayed
runner observation is a source-supported hypothesis, not an established
cause. A recurrence needs correlated process and runner evidence.

The [capture baseline](alps-capture-baseline-native-roster-correction-659e5576.md.txt)
runs twelve methods on Windows and Linux Python 3.10 at `659e5576`.
Six positive methods pass. Six negative methods produce eleven failure
entries, including origin subtests. Real child pipes establish unbounded
startup, partial publication and discarded reader failure. Literal NetLog
controls establish false origin attribution. Ruff lint and format pass.
The browser and capture binary are controlled substitutes. No socket or
browser refresh is exercised. The later A170 and A171 repairs pass the
focused controls recorded above.

The [trust diagnostic](trust-rejection-diagnostic-native-56e65606.md.txt)
executes the same 26 anchored proxy methods on each host. Windows passes
24 and fails two; Linux passes 25 and fails one. Both actual unrelated
expired-alert controls reach the defective broad-predicate assertion.
Windows additionally records a server SYSCALL and no captured fatal alert
for the untrusted outer proxy. Linux passes that method. This is an
observation difference, not a demonstrated production trust failure.
Formatting, focused Clippy and Rust 1.88 pass. A169 remediation remains open.

The earlier [broader trust run](trust-rejection-baseline-native-113e5656.md.txt)
retains ten Linux forward-proxy leaked-output failures after successful
inner assertions. The narrow run does not explain those output holders.
The [independent assessment](trust-rejection-baseline-independent-native-addendum-113e5656.md.txt)
approves the causal evidence and accurate red result, not integration.

The [proxy coverage reconciliation](proxy-coverage-reconciliation-113e5656.md.txt)
corrects stale inventory rows against exact complete prior manual reads.
The current five-line trust diagnostic remains separately qualified.
File identity checks and imported evidence create no fresh semantic review.
Whole-codebase standards review, final architecture review and gates remain
incomplete.

The [ALPS quiet repair](hint-quiet-remedy-native-c12d5f49.md.txt) passes
all 53 selected request methods on Windows and Linux at `c12d5f49`. Its
actual failed-read control failed at `71176f08` after a real exchange and
invoked reader. The unchanged control now observes its original typed H2
and IO cause. Formatting, strict focused Clippy and Rust 1.88 checks pass.
Independent [source](hint-alps-quiet-remedy-independent-source-review-95a2baa3.md.txt)
and [native](hint-quiet-remedy-independent-native-addendum-c12d5f49.md.txt)
reviews approve this bounded result. Hint readiness, ownership and final
gates remain open.

The [capture source review](capture-session-source-standards-review-42858688.md.txt)
records five whole owners and seven whole test modules, with supporting
reads separately qualified. Startup, accepted-task ownership, error
classification, parsing and input-validation candidates need causal
controls and assigned repairs. This report has no runtime evidence or
independent whole-source sign-off.

The [cookie cleanup result](cookie-remedy-native-42858688.md.txt) records
all 50 selected request methods and all 100 HTTP/2 proxy methods passing
on Windows and Linux at `42858688`. Formatting, strict combined Clippy and
Rust 1.88 checks pass. All five formerly failing cookie controls now observe
task release or the completed redirect causes. Independent source review
approves the ownership remedy and its import-only follow-up. The
[independent native review](cookie-remedy-independent-native-addendum-42858688.md.txt)
approves the focused cookie results. Final workspace gates remain pending.

The [HTTP/2 native review](h2-connect-registry-independent-native-addendum-a0d2c622.md.txt)
approves the earlier focused result. Historical failed cookie and HTTP/2
controls remain preserved. The [hint source review](hint-remaining-source-review-2489815a-final.md.txt)
records separate quiet-observer, readiness and ownership candidates. These
private fixture findings establish no production leak. Imported evidence
and inventory discovery add no whole-codebase sign-off.

At `e6f01439`, all three real HTTP/3 received-order controls pass on Windows
and Linux. The [native receipt](h3-trust-native-checkpoint-e6f01439-d0a45c1e.md.txt)
and [independent assessment](h3-trust-native-independent-addendum-e6f01439-d0a45c1e.md.txt)
record the exact source and checks. Linux passes the full vendor check,
including canonical patch replay. Windows passes the package commands;
archive comparison remains unavailable because native checkout links
require administrator privileges. The named request-parts change has
independent source review. These are focused results, not final gates.

At `1ac70fe1`, the [trust-anchor observer repair](trust-observer-remedy-native-1ac70fe1.md.txt)
passes all four methods on both hosts, with default features and all
features. Each named connector must have its own nonempty batch. The
unchanged control now rejects equal-count HTTP/1 substitution for HTTP/2.
The earlier `d0a45c1e` baseline failed that assertion on both hosts.
Independent source and [native review](trust-observer-remedy-native-independent-addendum-1ac70fe1.md.txt)
are approved. Final gates remain open. Original exceptional cleanup is not
newly proved.

At `3e48645c`, the [corrected HTTP/2 baseline](h2-lifecycle-baseline-native-3e48645c.md.txt)
runs 99 methods per host: 55 pass and 44 fail. All 24 original methods pass.
The EOF control now passes, and four reset controls reach their intended
missing-cause assertions. The earlier compiler and control-setup failures
remain preserved. Fixture ownership, transport causes and poisoned
observations still need repair. Formatting, selected strict Clippy and
Rust 1.88 checks pass. Failures count test cases, not production defects.
The [independent assessment](h2-lifecycle-baseline-native-independent-addendum-3e48645c.md.txt)
confirms the corrected baseline within its recorded log-reading scope.

At `85f2d58b`, the [request-session deadline repair](request-session-deadline-native-85f2d58b.md.txt)
passes all 31 cookie and hint methods on both hosts. The two actual timer
controls failed at `33715620`; all 25 previous methods and four positive
controls passed there. The reviewed private wrappers now retain their
context and concrete timeout causes. Formatting, strict selected Clippy
and Rust 1.88 checks pass. The [independent native assessment](request-session-deadline-native-independent-addendum-85f2d58b.md.txt)
approves this focused cause and context evidence. Task ownership and final
gates remain separate requirements.

At `732d3006`, the [hint observer baseline](request-hint-observers-baseline-native-732d3006.md.txt)
runs 41 methods per host: 35 pass and six fail. Real H2/H3 order controls
reach collapsed-order assertions. Four actual-client controls expose
wrong-value and unsolicited-header acceptance. All previous methods and
the positive controls pass. Strict Clippy rejects a new test-helper tuple;
formatting and Rust 1.88 checks pass. These results do not establish
production defects.

At `121bbf19`, the [current focused receipt](request-h2-checkpoint-native-121bbf19.md.txt)
records all 41 request-session methods passing on both hosts. The same six
order and value negatives now pass. The [observer source review](hint-observer-remedy-independent-review-e5a534d0.md.txt)
and [layout follow-up](hint-observer-style-independent-rebind-73a761bf.md.txt)
are approved. This proves private observer behavior, without establishing
a production emission defect. Other request-fixture findings remain open.

The same revision executes 100 HTTP/2 methods on each host: 96 pass and
four fail. Forty-three earlier negatives now pass. Poisoned recording still
loses its cause, and a new actual CONNECT control exposes completed relay
result loss. Two previously passing tunnel and WebSocket methods regress.
Formatting and Rust 1.88 pass; strict Clippy rejects two new immediate
closures. The [intermediate source review](h2-lifecycle-intermediate-independent-source-review-54cf845d.md.txt)
and [completed-child control review](h2-connect-child-baseline-independent-source-review-16486b2c.md.txt)
approve bounded source changes for execution. Their scope does not approve
this red composition. The earlier `3e148b5a` attempt stopped at private
import errors before HTTP/2 execution. Its 41 request methods passed.
The reviewed visibility correction preserves existing relay implementations
and assertions. Native review, remaining repairs and final gates stay open.

At `a0d2c622`, all 100 selected H2 methods pass on both hosts. The
[current receipt](request-h2-checkpoint-native-a0d2c622.md.txt) retains
the completed CONNECT relay's concrete cause and primary/secondary
assertions, which were unreached at `d983ad7e`. The poisoned-recording and
ordinary tunnel/WebSocket regressions also pass. The concrete owner and
[rejection caller correction](connect-registry-compiler-independent-source-review-a0d2c622.md.txt)
have independent source review. Earlier `2489815a` stops at three missing
registry arguments before H2 execution; that compiler-only attempt remains
preserved. Formatting and Rust 1.88 pass. Combined strict Clippy rejects only
the separate cookie handoff nesting. Current independent native assessment
and final gates remain pending. Drop does not join; explicit cleanup is
finite, with the recorded cancellation-classification limitation.

At `d983ad7e`, the [cookie cleanup baseline](request-h2-checkpoint-native-d983ad7e.md.txt)
executes 50 request-session methods per host: 45 pass and five fail. Two
cookie task-survival controls fail before backup. Three redirect controls
reach missing completed-driver outcomes after healthy traffic and injected
completion. The four added positive controls and prior 41 methods pass.
Later combined driver identities remain unreached. The earlier `d516faab`
attempt stops at a private import error and gives no 50-method runtime
credit. The unchanged request rosters repeat at `a0d2c622`; that comparison
adds no new whole-source or entire repeated-log reading coverage. Cookie
ownership and redirect remedies are still in progress.

At `2fb596ad`, the [cookie repair receipt](cookie-lifecycle-remedy-root-2fb596ad.md.txt)
records thirty passes per host with all original controls unchanged. Ten
formerly failing lifecycle cases now pass, including concrete combined
causes, receiver errors and expiry. Formatting, strict selected Clippy and
Rust 1.88 checks pass on Windows and Linux. The current complete 825-line
owner has root and independent source review. Independent native review is
approved; final gates remain open.

At `602284c2`, the [CONNECT repair](connect-lifecycle-remedy-root-602284c2.md.txt)
passes all 106 selected methods per host. The exact public CONNECT prefix
derives 24 passes from that execution, including all six previous failures.
This is not a separate run. The [independent assessment](connect-lifecycle-remedy-native-independent-addendum-602284c2-corrected.md.txt)
approves the focused evidence. Explicit cleanup joins owners and retains
completed causes; synchronous Drop requests abort without a join promise.
Three server-side trust-rejection assertions remain source candidates.

The [request-session source review](request-session-standards-review-5a28f55f-final.md.txt)
reads client, cookie and hint owners completely. It reconciles existing
client fixes and adds eight source candidates, without runtime claims.
The received H3 ordered-header candidate now has real failing and passing
QPACK receive controls and a reviewed canonical vendor repair.
The [broader H2 baseline review](h2-lifecycle-regression-independent-review-49c0aad0.md.txt)
reads all fifteen baseline owners and children. Later source reviews cover
the compiler corrections and actual EOF/reset control changes. The current
execution above replaces the unexecuted forecast. Source review scopes stay
bound to their stated revisions; equality checks add no semantic coverage.

The following evidence describes earlier revisions.

At `2cea08af`, the [root native receipt](h2-cookie-corrected-root-2cea08af.md.txt)
records all 41 H2 methods passing on Windows and Linux. Cookie fixtures run
thirty methods per host: twenty pass and ten intended lifecycle negatives
fail. All seventeen previous cookie methods and three positive controls
pass. The corrected H2 setup reaches actual exchange prerequisites.
Formatting, strict selected Clippy and Rust 1.88 checks pass. Both runners
terminate one. The [independent native review](h2-cookie-corrected-native-independent-addendum-2cea08af.md.txt)
confirms these focused results. Cookie remedies and final gates remain open.

The [evidence import](recent-evidence-checkpoint-2cea08af.json) preserves
sixty historical reports and the paired current root and independent native
receipts byte-for-byte.
Four unchanged complete root source reviews cover the public CONNECT owner,
its auth child, error-context tests and trust-anchor connector tests. The
first two expose ownership, deadline and layout findings. Trust-anchor tests
have a source-supported observation gap. Error-context tests have no new
confirmed defect within the reviewed owner. None receives new runtime or
final integration credit from identity checks.

The inventory also discovers fourteen tracked crate files, forty-eight
historical reports and one changed vendor patch. Discovery adds no semantic
coverage. Another 616 unchanged dependency files are context records. The
audit covers relevant upstream integration, without an exhaustive review
of untouched dependency source.

Earlier exact source bindings retain their stated revision and whole or
partial scope. Changed H2 and cookie parents are not promoted to fresh whole
reads from extraction comparisons. Remaining source, standards, combined
architecture and full-gate work stays open.

Earlier verification follows.

The [field remedy](field-classifier-capture-remedy-root-ed320379.md.txt)
passes all twenty-two methods on Windows and Linux. Formatting, strict
selected Clippy and Rust 1.88 checks pass. Concrete causes, eager recorder
ownership, preparation errors and rejected proxies are verified. The real
certificate negative and malformed capture inputs now pass. The
[independent native review](field-classifier-capture-remedy-native-independent-addendum-ed320379.md.txt)
retains the earlier failing controls and exact current candidate.

The [negotiated remedy](negotiated-proxy-remedy-native-independent-addendum-9de0a354.md.txt)
passes all nineteen methods per host and the same focused checks. Actual
deadline and combined primary/secondary error assertions now pass.
Historical seventeen-pass/two-failure evidence remains intact.

The earlier ed320379 bindings retain eleven exact manual anchors. The
field parent and cookie owner have fresh complete root reads at that
revision. Other records preserve prior source scope, including the
negotiated placement-only correction. The
[checkpoint review](evidence-ledger-independent-review-710d5114.md.txt)
keeps seven rejected whole-read candidates unpromoted. HTTP/2 findings
A141-A149 and cookie findings A151-A155 remain open. The
[cookie source review](cookie-fixture-whole-source-review-623e18fd.md.txt)
adds no new runtime credit. Final combined review and gates remain open.

At `1e23deb9`, Windows and Linux each pass 89 selected methods: 51 SOCKS,
17 credential, 14 proxy environment and seven streaming environment tests.
Formatting, strict selected Clippy and Rust 1.88 checks pass. The
[root verification](proxy-owner-remedies-root-1e23deb9.md.txt) preserves
the preceding compiler failure and its direct propagation repair.
Independent source reviews cover the local setup, environment cleanup and
credential remedy. Current source bindings replace changed baseline bytes;
historical records remain intact. The
[independent native review](proxy-owner-remedies-native-independent-addendum-1e23deb9.md.txt)
confirms both hosts and preserves the earlier failed compilation. Final
combined review and gates remain open.

Earlier checkpoints follow and describe their own revisions.

At `ff1d8452`, all 49 forward methods and selected formatting, strict
Clippy and Rust 1.88 checks pass on Windows and Linux. At `199fa9ad`, the
SOCKS selection passes 50 of 51 methods; pretransfer setup cancellation
remains open. Credential fixtures pass eight controls and fail eight
intended regressions. The [native baseline review](proxy-fixture-native-independent-addendum-199fa9ad.md.txt)
records first reached failures and unreached assertions separately.
Independent source reviews approve the forward remedy and its finite-read
follow-up. The current local setup remedy awaits review and execution.

The [evidence import review](proxy-evidence-ledger-independent-review-81d7-e214.md.txt)
validates fourteen earlier complete bindings and four configuration/helper
bindings. The preserved CONNECT-UDP range correction limits its supporting
read to lines 546-592. Current credential baseline owners have four exact
complete-read bindings. Later source edits need separate review. Copying a
report supplies no additional semantic coverage.

The [forward current-source review](forward-proxy-native-and-current-source-independent-review-ff1d8452.md.txt)
adds an actual complete manual read of the current 2,355-line owner and
independently checks both hosts' full selected logs. Four control children
retain their earlier complete reads and unchanged source bindings.

Earlier verification follows. Final gates and combined review remain open.

The [target observation repair](socks-target-native-independent-addendum-81c61f13.md.txt)
passes 50 of 55 selected methods on Windows and Linux. The five remaining
failures concern local ownership or deadlines. All five target-form controls,
31 remote SOCKS methods, two DNS overrides, two HTTP/3 fallback methods and
the mapped certificate method pass. Selected strict Clippy and Rust 1.88
checks pass without warnings. The local ownership remedy is committed in
its lane and awaits independent review and native execution.

The [forward baseline](forward-proxy-native-baseline-independent-addendum-54c60be7.md.txt)
reaches seven intended failures and passes ten positive controls per host.
Compiler checks pass. The deadline, observer, completed-cause and reader
contracts require repair. Queued-request task ownership has source evidence
without a new runtime control. Partial later assertions remain unexecuted
when an earlier causal assertion fails.

The [Alt-Svc repair](alt-svc-remedy-native-independent-addendum-b6a5acc3.md.txt)
passes all 44 methods per host. The
[source review](alt-svc-peer-outcome-remedy-independent-review-06f80364.json)
covers all three changed owners and bounded helper ranges. Existing Drop
cancellation is retained; explicit error paths now observe peer outcomes.

The [remaining proxy owner review](proxy-remaining-whole-source-54c60be7.json)
adds complete negotiated, credential-cache and field-order source reads.
Their ownership, observation, timeout and failure-classification findings
remain open. It does not audit complete production credential-cache
implementation or all capture runs. Four current target-repair sources,
three Alt-Svc owners, four forward control children and these three owners
have exact complete-read bindings in the inventory. Changed remote/local
owners and the 1,988-line forward parent retain partial current coverage.
The retained reports have separate pending evidence-review dispositions.

The [proxy remedy verification](proxy-remedy-native-root-593fc4ae.md.txt)
records 33 CONNECT-UDP and twenty SOCKS methods passing on Windows and Linux.
The [independent addendum](proxy-remedy-native-independent-addendum-593fc4ae.md.txt)
binds both native runs. Typed deadline errors preserve operation context.
The retry predicate requires a terminal request observation. Body-close and
counter-wait expiry paths have source evidence without separate failing
controls. The original invalid initial-zero expectation remains historical.

The [WebSocket source review](websocket-peer-acquisition-remedy-independent-review-2a103f5a.md.txt)
approves route-peer ownership, eager upgrade acquisition and typed deadlines.
At `43fe668c`, 42 WebSocket methods, eleven upgrade owner-result methods and
the connector-configuration test pass on each host. Formatting, selected
all-feature Clippy and Rust 1.88 checks pass. The same run has three intended
origin cancellation failures and 34 passing CONNECT-UDP methods per host.
The [responder witness review](origin-responder-witness-independent-review-5238f875.md.txt)
explains why closing only the endpoint cannot satisfy the new task-lifetime
control. Origin ownership and observed failures still need repair.

The [H2 teardown characterization](h2-teardown-characterization-native-independent-addendum-02d07e83.md.txt)
records one plain-drop pass and one post-driver CANCEL cleanup panic on each
host. The failure reaches final sender destruction after the actual exchange
and driver joins. This is distinct from test-fixture error retention.
The [fixture remedy review](h2-peer-completion-remedy-independent-review-f30e0617.md.txt)
approves owned peers and typed completion causes. The
[backend source review](h2-late-reset-production-independent-review-d0b56287.md.txt)
approves the narrow reset bookkeeping repair. The
[identity review](h2-late-reset-identity-independent-review-fd7ef84e.md.txt)
binds both dependent HTTP fork versions and their locks and patches.

At `fd7ef84e`, the [native addendum](h2-remedy-native-independent-addendum-fd7ef84e.md.txt)
records all 195 selected H2 tests passing on each host. Both HTTP vendor
scripts, focused formatting, strict Clippy and Rust 1.88 checks pass.
The package suite retains one inherited ignored test. The wider facade run
passes 894 of 896 tests per host. Two unexpected H3 WebSocket CONNECT-UDP
failures keep the candidate nonzero. Their saved outer errors do not establish
the cause. The [investigation](websocket-h3-masque-failure-investigation-fd7ef84e.md.txt)
records the source path and a diagnostic plan, with its candidate qualified.

The [SOCKS baseline review](socks-peer-regression-independent-review-3fa93b02.md.txt)
and [origin baseline review](connect-udp-origin-failure-baseline-independent-review-e331c242.md.txt)
approve controls before repair. At `7cd14620`, each host reaches all six
SOCKS negatives and passes 23 positives. Windows reaches four origin
negatives and passes 35 positives. Linux reaches the same four negatives,
passes 34 positives and also fails the existing route-reuse method.
Formatting, focused Clippy and Rust 1.88 checks pass. The unexpected reuse
failure remains under investigation rather than an accepted baseline result.

The [local and forward proxy review](local-and-forward-proxy-standards-review-3fa93b02.md.txt)
records complete manual reads of both owners. Their current committed bytes
match those records. A123-A129 retain the ownership, observation, deadline
and layout repairs still required. The
[H1 child review](h1-ownership-children-root-source-fd7ef84e.md.txt) and
[H2 child review](h2-ownership-children-root-source-7cd14620.md.txt)
add four complete child reads. A130 records three remaining timer-cause
losses. Supporting reads keep their separate partial scopes.

These focused checks and source reads do not close whole-workspace gates
or the final architecture review. New raw evidence objects remain pending
scope reconciliation in the inventory.

The [expanded baseline](capacity-peer-native-baseline-independent-addendum-82fd3695.md.txt)
at `82fd3695` reaches eight SOCKS failures and passes
23 controls per host. The new TLS acquisition control reaches completed
cause loss before its later destruction assertion. The pool control reaches
its destruction-at-return assertion. The oversized origin payload fails
while ordinary forwarding and duplicate-control error retention pass. The
actual 12-second peer deadline fails while its five companions pass.

The [composed verification](capacity-origin-remedy-native-independent-addendum-482e75dd.md.txt)
at `482e75dd` records ten H3 proxy controls, six peer
deadline controls, all 39 origin methods and both original WebSocket callers
on Windows and Linux. Formatting, focused Clippy and Rust 1.88 checks pass.
All 57 focused methods pass per host. Whole-workspace verification remains.
The earlier Linux reuse failure has no captured cause and remains qualified.

The [Alt-Svc source review](alt-svc-state-owner-standards-review-8d834d49.md.txt)
records seven complete manual reads at `8d834d49`, rebound at `7fbeaab3`.
Supporting production and dependency ranges remain partial. A132 records
caller errors skipping completed peer results, distinct from the repaired
Drop ownership. A133 records three independent-case paragraph boundaries.

The [SOCKS source review](socks-peer-remedy-independent-review-0d561bbd.md.txt)
records complete manual reads of the three repaired owners and their
235-line decoder. Their exact current source identities match those reads.
The [Alt-Svc import correction](alt-svc-baseline-visibility-independent-review-83616c72.md.txt)
records a complete read of the new 127-line control. Other supporting
ranges retain their partial scopes.

The [native verification](socks-alt-native-independent-addendum-6d6cd85e.md.txt)
at `6d6cd85e` records all 31 selected SOCKS methods passing per host.
Alt-Svc passes four controls and reaches one intended completed-cause
failure after preserving the typed HTTP/1 body error. Formatting, focused
Clippy and Rust 1.88 checks pass on Windows and Linux. Both runners remain
nonzero. These selections exclude 202 proxy and 290 HTTP/3 methods per host.
The Alt-Svc remedy and whole-workspace gate remain required.

The [proxy verification](proxy-storage-native-independent-addendum-440dc2ad.md.txt)
records twenty configuration controls and forty-five route unit tests passing
on both Windows and Linux. Focused formatting, Clippy, Rust 1.88 and rustdoc
checks pass. The earlier candidate failed Clippy because its retained
credential error enlarged an environment error. Boxing that concrete cause
resolved the diagnostic while preserving its source chain.

The [capture verification](capture-composed-native-independent-addendum-60b26063.md.txt)
records fifty-seven methods passing on both hosts. Publication controls use
real staged files. Startup controls establish acquired-server cleanup calls
and retained failures, without proving native socket drain.

The [stream retention review](capture-aggregate-stream-retention-independent-review-440dc2ad.md.txt)
identifies a separate aggregate bound missing from the capture recorder.
Five new controls fail on Windows before repair. Four positive controls pass.
The [composed verification](environment-capture-corrected-native-independent-addendum-a6368df9.md.txt)
records all sixty-six methods passing on Windows and Linux. Formatting and
Ruff checks pass. These results establish the recorder's stream limits,
without establishing whole-process memory bounds or live browser behavior.

That same corrected run observes seven intended environment fixture failures
per host. The earlier proxy baseline did not compile, and is retained in the
[original run](state-environment-native-baseline-independent-addendum-86e01bfd.md.txt).
Three nested result-propagation corrections make the baseline executable.
The [later verification](state-environment-upgrade-composed-native-independent-addendum-41f94110.md.txt)
records all twenty-one environment controls and forty Alt-Svc state controls
passing on each host after their independently reviewed repairs. Its unrelated
new upgrade controls reproduce five failures, and its Clippy check fails on a
single conditional. That failed candidate remains recorded.

The [route review](route-source-native-review-dda49bed.md.txt) records four full
owner reads. Default, HTTPS-record and all-feature checks, Rust 1.88, Clippy,
formatting, rustdoc and eleven facade route controls pass on both hosts.
The [layout follow-up](route-model-layout-followup-independent-review-505808d9.md.txt)
is independently approved. The later native selection passes three network
and thirty facade route controls per host. Final combined review remains
pending.

The [expanded upgrade baseline](cache-source-upgrade-baseline-root-c9ebfaac.md.txt)
and its [independent addendum](h3-upgrade-fourteen-native-independent-addendum-759e0002.md.txt)
record fourteen controls on both hosts: nine intended failures and five
positives. Its formatting, selected HTTP/3 Clippy and Rust 1.88 checks pass.
The [remedy review](h3-upgrade-owner-remedy-independent-review-d89883df.md.txt)
approves owner and connection-worker result collection. The later
[native addendum](upgrade-cache-remedy-native-independent-addendum-2b4a401b.md.txt)
records all fourteen controls passing within the complete 271-test HTTP/3
binary on each host. The nine original failures remain preserved.

The [current cache and interface review](net-cache-interface-current-standards-review-cb4c8388.md.txt)
adds full reads of both production owners and their direct tests. Three cache
tests need explicit readiness instead of scheduler timing assumptions. The
root's later paragraph edits preserve behavior and are independently approved.
Supporting partials and historical source identities remain qualified.

The same native run passes all forty-two cache tests and twenty-one
environment controls per host. Formatting, selected Clippy and Rust 1.88
checks pass. The [cache follow-up](cache-test-readiness-release-independent-followup-bdb07168.md.txt)
approves explicit gate release before readiness assertions. The three revised
tests establish pending selection, without claiming a measured historical
flake or a new production defect. Whole-workspace gates remain pending.

The [facade source review](facade-error-response-template-standards-review-c485de7f.md.txt)
adds complete reads of errors, root exports, responses and template tests.
The [H2 owner review](h2-connection-driver-standards-review-c485de7f.md.txt)
adds complete connection and driver reads. Test placement, export ordering,
category wording and operation grouping have scoped remedies in progress.
Separate remaining H2 test-peer failure paths need causal controls and repair.
Supporting caller and dependency ranges retain their qualifications.

The [attribute review](evidence-attributes-independent-review-b1687d15.md.txt)
approves removing thirty-four repeated rules. Effective attributes remain
identical for all tracked paths and three future report probes. Original
report bytes remain unchanged. This adds no runtime or source-review credit.

## Vendor evidence reconciliation

The [retained records](vendor-reviewed-records.json) preserve 288 validated
historical review scopes across 152 inventory paths. Repeated records are
distinct from files. Complete patch reads and partial upstream reads remain
separate. These records do not approve subsequent changes or establish current
compiler selection.

The [reconciliation](vendor-source-reconciliation.md) resolves historical
Git identities, declared Windows line endings and two reconstructed instruction
states. The original reports remain retained. Two invalid ranges remain
excluded: H3 client connection ended at line 794, and the native ECH source
ended at line 1364. Fresh bounded reads are recorded separately. The HTTP/2
lock-refresh wording reported in the historical index was corrected at
`01574f2e`; it is no longer an outstanding source defect.

## First pass evidence

Client review traced request preparation, body deadlines, redirects, replay,
admission, selected pool ownership, and EventSource and WebSocket control
paths. Transport review traced H1 and H2 leases and drivers, H3 body demand
and cleanup, address cache publication, proxy setup, TLS ticket storage,
and socket FFI. Both passes leave substantial source and test gaps.

Profile and QUIC review has a
[per-file record](profile-quic-coverage.json). Production model and provider
reads now cover every tracked file in both assigned crates, including
browser recipes and tests. Raw capture trees have group-level provenance
review, rather than an all-byte review. Source review is not a cryptographic
or live-browser proof. Changed paths still need final composed review.

Independent reviews cover the proposed admission, ticket, DNS, body,
template-debug, and proxy-waiter changes. They trace callers and test
controls separately from implementation. Final composed review is pending.

The integration owner inspected all workspace manifests and their feature,
target, and lint declarations. The two FFI crates deliberately declare
their lints separately so they can deny, rather than forbid, unsafe code
at the audited module boundary. No current baseline mismatch was found.
Resolved metadata at `efb0cb3c` confirms the production dependency direction:
the client uses network and profile crates, network uses profiles and the
QUIC backend, and the backend uses profiles. Profile and testkit crates have
no first-party production dependencies. Test dependencies are separate.
The selected forks all resolve to local renamed packages. The full feature
set resolves, which does not prove each feature combination compiles.
After the ACK parser repair, the selected-source tree confirms Quinn-proto
`.4`, Quinn `.4`, and H3 dependencies `.9` through those same local paths.

Testkit and fuzz review has a [per-file record](testkit-fuzz-coverage.json).
It covers all assigned source, tests, small configuration and prose, including
DNS reply ownership, capture parsers, oracle assertions, and harness drivers.
Packaged fixture bytes have syntax and provenance checks, rather than manual
all-byte decoding. The fuzz lock has a parsed identity check. Five legacy
fuzz targets lack separate harness seed regressions; parser tests do not
prove those exact builders. Outside-scope caller reads remain partial.

Tooling review has a [per-file record](tooling-coverage.json) with reviewed
ranges and source hashes at the starting revision. It traced CI job
classification, required checks, gate results and signal handling, release
boundaries, and candidate refresh. Isolated reproductions demonstrate a
lock-recovery race, two false-success scans, and a failed freshness report.
Its three partial reads and the untouched tooling remain explicit gaps.

Continued client review has a [per-file record](client-remaining-coverage.json)
for constructors, environment proxy snapshots, request preparation, hooks,
redirects and replay. Continued transport review has its own
[per-file record](net-remaining-coverage.json), covering direct setup, request
validation, selected HTTP/3 state, TLS configuration and early data. These
records retain the reviewed revisions and explicit partial reads. Pools,
response decoding, remaining transport tests and other gaps still need review.

The [proxy continuation](net-proxy-continuation-coverage.json) records ten
further complete file reads, including SOCKS tunnels, UDP associations and
HTTPS CONNECT. The [documentation pass](docs-contract-coverage.json) records
page reads, source comparisons and explicit gaps. A full page read establishes
text coverage, rather than proof of every linked implementation or claim.

The [client lifecycle continuation](client-lifecycle-continuation-coverage.json)
records pool and prune ownership, cookies, hints, attempts, decoding and replay.
Its 51 complete reads and one partial request read use exact committed blob
hashes. The [network lifecycle continuation](net-lifecycle-continuation-coverage.json)
adds CONNECT-UDP, TCP and independent body, upload and platform test contracts.
The [establishment continuation](net-establishment-continuation-coverage.json)
adds TLS, negotiated protocols, HTTP/3 wrappers, DNS inputs and adversarial
tests. Its final DNS range completes the earlier partial read. Network hashes
identify Windows working bytes at the recorded revision. All 99 new records
were checked against their respective hash basis and line ranges. These
passes retain their gaps and do not imply runtime verification.

The [input and runtime continuation](net-input-runtime-continuation-coverage.json)
records 34 further complete reads and one partial HTTP/3 helper read. All 35
source identities and ranges match Windows working bytes at `df2ae9b7`.
The review covers authorization, public exports and errors, request metadata,
malformed peers, cancellation and platform tests. It identifies the HTTP/3
cookie-limit mismatch and leaves the remaining transport files explicit.
The ECH support wording and inline Client Hint tests have independent review;
their seven and three existing tests pass respectively.

Capture review reproduces a preassignment child escaping Windows job cleanup,
a profile-prefix sweep stopping a different profile, and a quoted path
preventing cleanup. Tests use harmless owned processes, rather than browsers.
The sweep's exact, descendant and prefix-sibling Windows controls pass.
The initial launch remedy fails its abrupt-runner-death control with the
dependency-managed interpreter. A native bootstrap repair then passes all
86 focused tests on Windows and native Linux at `1d5f3f99`; eleven Windows-only
cases skip on Linux. Independent review identifies a separate cleanup-failure
path, so complete shutdown verification remains open.

Two actual HTTP/3 decoder regressions fail for retained unknown payload and
oversized SETTINGS. The fragmented unknown-frame and following GOAWAY control
passes. HTTP/3 cookie preparation also fails three new count, byte and
extended CONNECT regressions; ten controls pass. Its facade regression fails
before a successful exchange. Those failing tests establish the defects.
The incremental-frame repair passes 36 decoder and 52 connection tests,
including actual QUIC peers. The cookie repair passes all 185 transport HTTP/3
tests and seven facade cookie tests. Independent source reviews approve both
repairs. Identity refresh, full canonical replay and final integration remain
pending.

The frame payload-length baseline at `cb06e4af` passes 39 decoder controls and
fails two malformed-payload regressions. Its actual QUIC peer also publishes
GOAWAY instead of the required frame error. The known-payload declaration cap
does not resolve this separate parsing path. Three deterministic capture cleanup
tests fail at `ec51ac17`; the initial correction passes its four focused tests,
but repeated interruption remains under review. These are open repairs.

The final malformed-frame correction passes 41 decoder and 53 connection
tests, including the actual QUIC error control. Independent review approves
its canonical source patch. The final capture correction passes 96 focused
tests on Windows and native Linux, where eleven Windows-only tests skip.
Independent review covers repeated SIGINT, exact owner attribution, completed
results and invalidated resume records. These results apply to `0ad0d560` and
do not replace final vendor or integration gates.

The complete H3 vendor check passes on native Linux at `0ad0d560`, including
the checksummed archive, canonical patch replay, byte comparison, formatting,
all-target/all-feature Clippy, selected test groups and dependent builds.
At that revision the later server-limit test patch still needed its final
identity and repeated vendor check. Its two rejection and two exact-boundary
tests pass at `0fdbaa16`; the subsequent `.11` verification is recorded below.

The [consumer configuration review](consumer-configuration-coverage.json)
records fourteen complete integration-owner reads, totaling 1,030 lines.
It covers issue forms, ownership, license files, independent consumer source
and the downstream checker. Windows path and Git consumer checks pass at
`0ad0d560`: each runs eight default and ten optional-feature tests and validates
the renamed dependency graph. The initial run fails because Git Bash resolves
the Store Python alias; the rerun supplies pinned Python 3.10 for that command.
Git reports normal CRLF conversion warnings in its temporary snapshot. This
does not establish registry publication or final candidate verification.

After the peer-limit test type corrections and loopback fixture repair, all
377 H3 unit tests pass on Windows and native Linux with the `.11` identity.
The native check at `70cf715d` also passes canonical archive replay, byte
comparison, formatting, all-target/all-feature Clippy, selected test groups
and dependent builds. This is a complete
package unit-test run, rather than a filtered selection. Independent source
review approves both test patches. The full integration gate remains pending.

Eighteen further contract records add 62 complete and seven partial file
reviews, with 31,916 lines across the complete records. Exact committed
object IDs, SHA-256 values, line counts and inclusive ranges were verified.
The records retain previous partial credit and distinguish cache/setup
reinspection from first inspection. Net records describe `df2ae9b7`; the
[public stream review](client-public-stream-continuation-coverage.json)
describes `0ad0d560`. They establish source coverage, not new runtime results
or final-candidate review. The port-zero and empty-stress corrections pass
focused Windows and Linux controls; other assertion gaps remain open.

The [resolver tests](net-resolver-tests-continuation-coverage.json),
[upgrade and ALPS tests](net-upgrade-alps-continuation-coverage.json), and
[TLS controls](net-tls-controls-continuation-coverage.json) add thirteen complete
source reads, totaling 2,165 lines. Each source hash and inclusive range was
verified against its recorded Git blob or Windows working bytes at `df2ae9b7`.
Adjacent reports state test contracts, timing and platform assumptions, and
remaining gaps. These are source reviews without execution evidence.

The [network manifest, example and benchmark review](net-manifest-examples-bench-continuation-coverage.json)
adds eighteen complete reads and 3,801 lines at `df2ae9b7`. Exact committed
blob identities, hashes, line counts and inclusive ranges were checked.
It covers the manifest, six benchmarks, seven examples and four external
tests. The DNS capture lifecycle finding now has failing authenticated
baseline controls and twenty passing corrected Windows and Linux tests. Remaining
tool configuration and stale capture-label candidates stay open.

Three retained independent reviews cover DNS capture ownership, cookie-cache
diagnostics and image arguments. Their seventeen exact source identities,
line counts and ranges were checked before import. Full and partial reads
remain distinct. The [conformance continuation](new-tooling-source-pass-04-coverage.json)
adds eighteen complete repository reads, two partial documentation reads and
bounded pinned upstream source records. Its report separates manual counts,
file ownership and external cleanup candidates from runtime observations.

The [maintainer configuration record](maintainer-configuration-coverage.json)
contains seven complete integration-owner reads covering optional command
hooks, review duties, permissions, byte-preservation attributes, ignored
artifacts and dependency policy. Its 335 lines were read as source. The optional
hooks deliberately fail open on absent tooling; they do not replace the full
gate. This establishes configuration coverage without claiming runtime
permission enforcement or an executed advisory/license scan.

The ACK parser repair passes 357 Quinn-proto unit tests and its complete
Windows vendor check. Its renamed Quinn dependent also passes that check.
The H3 family passes its complete native Linux vendor check at `27acd346`,
including exact archive replay and the updated dependencies. The UDP test
repair passes 37 Windows tests. Independent source review approves both
repairs; these checks do not establish final integration or whole-fork review.

The composed client passes 604 unit tests, 48 selected SSE stream tests and
21 response-decoding request tests, including proxy and redirect controls.
Seven HTTPS-discovery request tests pass, as do 17 focused lookup tests after
the fixture correction. The composed all-target, all-feature lint check passes.
Development-tool
tests pass all 35 cases on Windows and native Linux, including the offline
freshness report with jq. Pinned ShellCheck 0.11.0 passes all CI, development
and release scripts in the native checkout. These checks support specific
changes; they do not replace the remaining source review or full gate.

Testkit passes 104 tests across its library, fixture and capture targets,
and its all-target, all-feature lint check passes. The QUIC provider passes
177 unit tests, including startup failure controls. Native Linux vendor
checks pass for the Quinn, Quinn-proto and H3 forks, including their actual
builds and selected tests. This verifies those changes and fork packaging,
rather than every untouched upstream implementation.

The HPACK and WebSocket parser corrections pass their complete vendor
checks on Windows and native Linux at `4a16416d`. The checks validate
checksummed archives, canonical patch replay, selected formatting and
build/test contracts for HTTP/2 `.12`, wreq `.12`, and the WebSocket family
`.3`. The three HPACK indexing regressions also pass on the composed
32-bit fork in debug and release builds. Packaged upstream HTTP/2 fixture
tests remain filtered where their assets are absent; this is not an
exhaustive untouched-upstream audit or the final integration gate.

Independent count-validation review covers the complete Rust version-report
example, Python peer and tests, with bounded connector and cache traces.
The composed Rust parser tests pass. Actual loopback runs reject zero before
CA-file I/O and complete the default three-request and explicit one-request
paths with matching peer observations. Independent Autobahn review covers
its implementation, tests and actual workflow caller. Twenty focused
methods and the composed forty-four-method conformance suite pass on
Windows. Those controlled tests do not establish live Docker cleanup.

The [WebSocket continuation](client-websocket-continuation-coverage.json)
records sixteen complete reads at `04aa870b`, including all three protocol
dispatch paths. Further tooling passes retain their own revisions and gaps:
[development and docs](new-tooling-source-pass-01-coverage.json),
[Autobahn](new-tooling-source-pass-02-coverage.json),
[initial WPT](new-tooling-source-pass-05-coverage.json), and
[WPT and TLS-Anvil](new-tooling-source-pass-06-coverage.json).
Together with the two ownership reviews below, 96 historical records passed
source-identity, hash and range validation before import. Repeated reads do
not count as additional distinct files; historical complete reads do not
approve subsequent changes automatically.

The [private download review](a50-private-staging-independent-review.json)
approves separate, exclusively created staging directories and create-only
publication. The initial fourteen-pass/two-failure replacement baseline is
retained. At `73a08ed8`, eighteen tests pass on Windows and Linux, including
two owners competing for one output, actual HTTP/3 downloads, cancellation,
and platform-specific cleanup or permission controls. The Linux example
also compiles on Rust 1.88. Deliberate modification inside private staging
and ancestor replacement remain outside its documented contract. The
[two-owner review](a50-two-owner-independent-review.json) also approves
the added portable control at `73a08ed8`. It exercises overlapping owners
with sequential publication, rather than simultaneous scheduling stress.

The [WebSocket bounds review](a55-production-independent-review.json)
approves the authored remedy and composed source at `66d20201`. Six controls
pass on Windows and Linux, and the Linux Rust 1.88 library check passes.
The iterator control establishes bounded consumption. It does not measure
allocation or bound arbitrary iterator implementations.

The [version-server review](a54-production-independent-review.json) covers
scratch ownership and close-finally across publication and cancellation.
The composed 51-method conformance suite passes on Windows and Linux.
Actual loopback runs complete three default and one explicit observation,
retain caller outputs and remove certificate scratch. Controlled failure
tests and normal loopback completion do not prove every native shutdown path.

Six test placements preserve production text and test behavior. Source
review and parsed Rust comparisons cover the moved bodies. The composed
selection passes 73 tests on both platforms. Windows reports one lingering
output warning for the retry timeout test; an isolated rerun passes without
that warning. Its cause remains unresolved, and the combined gate must
check it again. Linux reports no such warning. These checks remain focused
verification rather than a full gate.

The [TLS cleanup review](a57-production-independent-review.json) approves
the source at `78e664a0` with a required workflow trigger correction. Twelve
source identities and ranges and eight retained log hashes were verified
before import. Composition removes duplicated Autobahn container inspection
and removal in favor of the same concrete owner checks. The combined
84-method suite passes on Windows and Linux. The
[composition review](a57-shared-composition-independent-review.json)
then requires two interrupted Autobahn retention repairs. The
[follow-up](a57-shared-composition-followup-review.json) approves their
exact source at `54ebd468`: 88 composed methods pass on Windows and Linux,
and an independent 21-method run confirms both CLI diagnostics. Thirty
further historical source records were checked before importing the two
composition reviews and the WPT review below. Full and partial credit remain
distinct. These checks do not establish actual Docker cleanup, cancellation
of late daemon work, or bounded initial log memory. Final gates remain open.

The [WPT acquisition review](a56-production-independent-review.json)
records a required repair at `18319655`. Its actual Windows child control
exposes files deleted before the acquired child exits. The existing 25
methods passing does not approve that ownership boundary. The subsequent
[acquisition review](a56-acquisition-independent-review.json) confirms the
native ownership repair but requires another interruption correction. The
[final review](a56-acquisition-followup-independent-review.json) approves
the corrected source at `91caf511`. Twenty-eight source records passed hash,
identity and range checks before import. Earlier request-changes reports
remain retained at their original revisions.

The WPT composition at `d0ee3e97` passes 122 conformance methods on each host,
with one explicit platform skip per host. Native Windows serialization and
Linux bootstrap-write controls observe child exit before file cleanup. These
fixtures do not run TLS or live WPT scenarios. Private native fields rely on
the inspected CPython 3.10 runtime. Failed OS termination can still leave an
unreaped child and an interpreter finalizer waiting without a deadline.

The QUIC runner composition at `cb935f2f` adds an owned Linux process group,
verified Docker resources, independent byte restores and recovery backups.
It preserves the image-input guard. The shared Docker helper now applies a
caller-supplied environment, keeping cleanup on the launch's selected daemon.
Two selected-daemon regressions fail before that addition and pass afterward.
The combined suite runs 143 methods: Windows has two explicit platform skips;
Linux has one. The actual Linux descendant control observes child exit before
restoration. Controlled resource fixtures do not establish real Docker cleanup.
The [initial independent review](a53-composed-independent-review.md) requires
two further recovery corrections.

The reviewer reproduces two further recovery failures at `cb935f2f`. A log
inspection error escapes before file restoration and reporting. A later
automatic-checkout cleanup error omits previously retained scratch paths.
The signed regression-only checkpoint at `9fd7b1a7` passes eighteen controls
and fails the two added recovery contracts. The correction at `de146f12`
preserves cleanup after log inspection failure and all retained recovery
paths. The [follow-up review](a53-composed-followup-independent-review.md)
approves that source. Thirty-four first-party and sixteen bounded upstream
records passed source, range and evidence validation before import.

The corrected composition runs 145 methods on each host. Windows passes 143
with two platform skips. Linux passes 144 with one Windows skip, including
the actual descendant-exit control. The independent Windows snapshot runs
43 methods, passing 42 with one Linux skip. Final gates, live Docker cleanup
and CI remain separate verification.

## Continued standards reviews

The [source reconciliation](new-source-review-reconciliation.json) checks
261 records against their exact source revisions and the aggregate at
`eb2c3fd0`. The [import receipt](new-source-review-import.json) records 164
existing-row updates. Historical changed files, declaration scans and
mechanical API comparisons receive no new full-source credit. Original
prose reports remain byte-exact in adjacent `.md.txt` files.

The retained reports cover crate consumers and public paths, integration
fixtures, trailer oracles and client examples. Canonical imports and their
callers have independent source approval. Windows and Linux checks pass
Clippy, 339 selected profile and transport controls, 143 doctests,
default/all-feature rustdoc, Rust 1.88 checks and path/Git downstream builds.
All eight API inventories were regenerated with the pinned tools. These
checks do not complete the remaining source review or final gate.

The repaired support selection passes sixteen controls on both hosts.
Thirty-one WebSocket/proxy callers and thirty CONNECT-UDP-related callers
also pass on each host. Trailer checks pass eight selected methods,
including six actual raw HTTP/2 and HTTP/3 uploads. Four example controls
pass. These results describe `c8aae33a`, with later fixture repairs separate.

The HTTP/3 fixture baseline at `6db61767` passes two positive controls and
fails eight malformed-peer and cancellation controls on each host. The
repair at `eb2c3fd0` passes all 28 selected early-data, resumption and retry
tests, plus formatting and targeted Clippy on both hosts. A native Linux
mutation disabling early data fails its control; exact restoration passes.

The registered H3 MASQUE baseline at `cc5452b9` passes one positive and
fails six authenticated cancellation controls on each host. The independently
approved remedy at `b0891f1c` passes all 36 selected controls on Windows and
Linux, plus formatting and targeted Clippy. The Alt-Svc baseline at `6535bd75`
fails three controls on each host. Its remedy first passes 30 of 31, with
one incorrect expected error category. The precise assertion correction at
`585ba5ab` passes all 31 on both hosts. The observer-health follow-up adds
three causal regressions below. These results do not replace final gates.

The committed nextest policy retains its 200 ms output-detection interval.
Actual finite-child negative controls fail with the strict policy on Windows
and Linux; waited-child positives pass. The original retry warning remains
unexplained. A late Linux PID-only census is distinct from process identity
or native reaping proof.

Two fresh eight-file production standards passes identify DNS provenance,
error-cause retention and streaming-peer ownership findings. The continued
import retains their original reports and reconciles supported records with
current source bytes. Partial and historical records retain their scope.
The composed five-control baseline at `d9b1746b` passes two positives and
fails three intended regressions on both hosts. The provenance and peer
repairs at `3af0404e` pass all 38 selected cache, route and peer controls on
each host, plus formatting and targeted Clippy. Independent source approval
requires one test-paragraph repair and exceptional outer-handle cleanup.
The paragraph is corrected. A83's exceptional ownership and simultaneous
typed-cause controls now reproduce both defects on Windows and Linux, then
pass with the concrete owner. At `7e358667`, all 71 selected network controls,
formatting, all-target Clippy and Rust 1.88 checks pass on both hosts.
Independent review covers both final peer files and the retained logs.

The continued source import adds 96 evidence appends and 175 discoveries,
with 42 raw original report copies. Independent replay validates each
update and preserves bounded, full, historical and artifact distinctions.
The 142 discovery-only annotations leave those rows pending. The report
storage correction preserves original hashes across Git checkouts; it adds
no new semantic review credit.

Fresh manual passes cover four request and certificate files and two
diagnostic files, with supporting callers read separately. They identify
A84-A86 fixture ownership and cleanup findings. Their original causal
baseline at `7c6ff2fc` runs 23 controls on each host: fourteen positives pass
and nine intended regressions fail. Diagnostic disconnect controls are
corrected before the remedy comparison; all five diagnostic negatives still
fail and three positives pass on each host at `4e018d29`. A84's lexical
request-peer repair passes all fifteen controls and focused formatting,
Clippy and Rust 1.88 checks on both hosts at `6e55867e`. Shared fixture
repairs and final composed review remain in progress.

The cause-preservation baseline first fails compilation because two test
helpers omit borrowed lifetimes. After that narrow correction, `bf6cb33d`
passes 53 of 66 network controls and fails thirteen intended regressions
on each host. Five cover cached resolver causes and eight cover binding
causes. The uncached typed-cause positive passes. The source-approved
remedies at `7ae9a390` pass all 66 controls on Windows and Linux.
Formatting, focused Clippy, Rust 1.88 library checks and all-feature rustdoc
also pass on both hosts at that revision.

The observer-health baseline at `bf6cb33d` passes two identity controls
and fails three health controls on each host, after actual UDP observation.
These cover injected handler error, awaited receiver cancellation and actual
lock poison. The corrected observer passes all 34 Alt-Svc controls on both
hosts at `7ae9a390`. Source review, focused verification and full integration
remain separate requirements.

## Current controls and source findings

The [facade verification](facade-api-native-independent-addendum-96ee6074.md.txt)
records twenty-two selected tests per host and eighteen passing focused
stages. Eight API generators succeed. Six retained outputs match. Two stale
outputs are refreshed at `96ee6074` and independently approved. These checks
do not establish a full workspace gate or a new review of every API line.

The [H2 baseline](h2-peer-completion-baseline-independent-review-a1df13f2.md.txt)
records seven passes and seven failures per host at `ba6e60c3`. Four failures
reach the intended assertions. Three are masked by client connection cleanup
panics, as confirmed by the separate Windows backtraces. The baseline needs
correction before those three error and ownership claims can be tested.
Formatting, focused Clippy and Rust 1.88 pass. No remedy is approved yet.

The [WebSocket and acquisition review](client-websocket-upgrade-independent-disposition-96ee6074.md.txt)
supports three new findings after four full owner reads. Supporting source
reads remain partial. The [proxy test review](proxy-test-owner-independent-disposition-96ee6074.md.txt)
supports four further findings after complete CONNECT-UDP and SOCKS owner
reads. Controls and remedies remain pending. Test-fixture defects do not
establish production connection leaks. The repaired upgrade parent remains
intact; the new acquisition finding concerns construction of its controls.

## Limits of the record

The shared HTTP/2 relay and diagnostic repairs at `09d974c3` pass all 25
cleanup controls and 118 affected callers on Windows and native Linux.
Formatting, focused Clippy and Rust 1.88 checks also pass on both hosts.
The reset and failed-send controls fail before their respective repairs,
including loss of an observed protocol reason and an observed I/O cause.
These checks do not replace the full gate or final combined review.

The HTTP/1 baseline at `04c2b1b6` passes two controls and fails five intended
ownership and typed-deadline controls on each host. The reviewed repair at
`6ee7d658` passes all 88 H1 tests on Windows and Linux.

After the shared helper lifetime correction, `91a4fb7a` runs fifteen request
controls per host: four pass and eleven fail for the intended defects.
Its six H2 WebSocket controls have four passes and two intended failures.
The reviewed composition at `880b29de` passes all six WebSocket controls
and 118 selected callers on both hosts. It passes 56 of 57 request tests
and fails Clippy on three unchecked read amounts. Formatting, Net Clippy
and both focused Rust 1.88 checks pass. This candidate is not green.

The new accept-error baseline at `b6bdd294` has two passes and two intended
failures per host. The unexpected protocol and unrelated I/O positives
pass. The dependency retains I/O kind and inner text, rather than arbitrary
nested I/O payload types. The original stronger downcast assertion is
retained as historical source, without a causal runtime claim.

At `c688c255`, all seventeen request controls pass, but the original
failed-upload caller still fails: 58 of 59 selected tests pass per host.
The accept-only correction has not resolved that caller. Focused Clippy
fails on one nested guard in the new control; formatting and Rust 1.88
checks pass. The later diagnostic at `39f3e2e7` identifies request DATA
as the failing peer operation on both hosts. Keeping the client alive
through peer completion at `abd05c96` passes all 59 selected request tests
on both hosts. Formatting, focused Clippy and Rust 1.88 checks also pass.
DATA error allowances and the original request error assertions stay intact.

The same `39f3e2e7` baseline runs thirteen H2 shutdown controls per host:
four pass and nine fail for the intended ownership, deadline and observer
defects. The actual CANCEL and forced-close positives distinguish a reset
from transport termination. The approved source controls do not mutate
the process-global deadline service. At `b7b7676e`, the reviewed remedy
passes all 151 selected H2 tests on Windows and Linux. All thirteen
unchanged controls and four original driver-shutdown tests pass.
Formatting, package Clippy and Rust 1.88 checks also pass on both hosts.
Independent review verifies the complete logs and exact source mapping.
Forced closure through blocked writes does not establish RESET delivery.
Simultaneous-error and cleanup-deadline branches remain source-assessed.
These selected checks do not replace the full workspace gate.

A fresh route source pass reads the facade route module, connected stream
and datagram route modules in full. Supporting authentication and authority
reads remain partial. Independent bounded review supports A97's validation
cause losses. This does not establish a full end-to-end proxy review.

All native logs and their exact revision receipts remain retained. These
checks do not replace the full gate, and inspection does not establish a
permanent WebSocket socket leak.

Assignments do not establish coverage. Each completed pass must list the
files and functions read, the paths traced, the relevant test contracts,
and remaining uncertainty. Follow-up passes cover gaps before completion.

The managed-ID SSE and H1 retry repairs pass 69 and 15 selected methods on
both hosts. The capture reader passes 13 controls per host. Full capture
discovery passes 661 methods on Windows and 650 with 11 skips on Linux.
The separate session-reuse baseline had five intended failures across 26
methods per host. Its reviewed peer repair now passes all 33 selected
methods on both hosts. Raw proxy, upload and HTTP/1 owners remain open.
See `owner-netlog-root-checkpoint-02cad4f2.json` for exact revisions and limits.
These selected checks do not replace the full gate or current candidate CI.

The session-reuse receipt `session-reuse-owner-root-checkpoint-6c55672d.json`
records exact source, focused checks and remaining ownership limits.

The terminal-status repair passes all 22 selected retry methods on Windows
and Linux at `f8a009cf`. Four unchanged controls fail for their intended
causes before repair and pass afterward. The added collector-expiry control
also passes. Formatting, focused strict Clippy and Rust 1.88 checks pass.
The receipt `terminal-status-owner-root-checkpoint-f8a009cf.json` preserves
the earlier invalid prerequisite, corrected baseline and independent reviews.
Thirteen raw tasks and other setup, deadline and accept paths remain open.

The status-retry body assertions pass all 18 selected methods on Windows
and Linux at `cabbe4dd`. Both assertions reject a changed second recorded
body and pass after source restoration. This checks the assertions against
actual received bytes; it does not establish a production corruption defect.
Focused quality passes. The initial formatting failure remains recorded in
`status-retry-body-oracle-independent-native-review-cabbe4dd.json`.
Task ownership, serving errors and full integration checks remain open.

The request-caller baseline at `d917ca1a` has two healthy passes and five
qualified failures on each host. Three reach the original request destruction
watch after caller exit. Two reach discarded completed request or H2 causes.
Earlier `90e4387c` does not compile; `4697a57b` retains three ambiguous
timeouts and one lint failure. The later phase controls resolve that ambiguity
without changing owners. See `session-request-phase-independent-native-review-d917ca1a.json`.

The scripted status baseline at `d35ac16e` passes eighteen old contracts and
two positives per host. Four accepted TCP/TLS child destruction controls fail
after their prerequisites; one consumed post-flush serving error is discarded.
The failed controls do not reach their socket or retained-error assertions.
Both baselines pass formatting, strict affected Clippy and Rust 1.88 checks.
These are pre-repair observations. Full gates and CI remain open.
See `status-child-baseline-independent-native-review-d35ac16e.json`.

A whole source review of the 536-line HTTP/1 session fixture confirms nine
raw server owners and two queued request handles with incomplete cleanup.
Its deadline loses the original timeout cause. The disabled-authentication
test observes replacement requests but does not observe session resumption.
These extend A236/A233 and qualify the test title; no production defect or
native outcome is claimed. See `session-http1-whole-owner-independent-source-disposition-d35ac16e.json`.

The request-caller repair at `30e4999b` passes all 41 selected session
methods on Windows and Linux. The mixed baseline at `3aa01318` had 35 passes
and six causal failures. The same eight control bodies now pass actual
request destruction, both original request errors, the original H2 serving
cause and the completed request cause alongside the real caller deadline.
Later peer and socket checks pass before backup. Focused formatting, strict
Clippy and Rust 1.88 checks pass. See
`session-request-owner-remedy-independent-native-review-30e4999b.json`.
Earlier compiler and phase qualifications remain in the baseline records.
The five-second setup/caller deadline precedes finite peer collection.
These checks do not measure every race or the total cleanup duration.

The scripted status repair at `aeea9a48` passes all 29 selected methods on
both hosts. All eighteen original contracts and seven unchanged controls
pass after the five causal baseline failures. Four added methods pass
actual read/write fault retention, fresh versus truncated request EOF,
finished foreign cancellation and original caller/flush cause composition.
Focused quality passes. The earlier `5b0e57b6` compile failure executed no
tests; the correction changes one error-object lifetime annotation. See
`status-child-owner-remedy-independent-native-review-aeea9a48.json`.
Raw shared-cap ownership, decoder bounds, acquisition failures and wider
cleanup races remain open. These checks do not replace full gates or CI.

The HTTP/1 disabled-authentication test title now describes replacement
requests. Its body does not establish session-resumption behavior.

The HTTP/1 baseline at `bb1769ff` passes all nine original methods on
Windows and Linux. Five controls fail at their intended checks: three
original peers remain live after caller exit, the caller deadline loses
Elapsed, and a completed TLS error is lost beside the URI error. Later
socket and retained-error assertions are unreached in those failures.
Focused formatting, strict Clippy and Rust 1.88 checks pass. See
`session-http1-peer-baseline-independent-native-review-bb1769ff.json`.
The repair, queued request joins, other peer paths and full gates remain open.

### HTTP/1 and shared retry-cap verification

The queued HTTP/1 baseline at `b47e3ab5` passes nine original methods and
has eight causal failures per host. Three concern queued request destruction
and an uncollected sibling result. The other five concern peer ownership and
error causes. The held five-second selection expires after actual Pending
and Capacity observations; it is not an ordinary Capacity-request timeout.
See `session-http1-queued-baseline-independent-native-review-b47e3ab5.json`.

The bounded peer repair at `0398751f` passes all nine original methods and
five unchanged peer controls on Windows and Linux. Original destruction,
socket closure, Elapsed and composed TLS/URI causes pass before backup.
Three unchanged queued controls still fail. The earlier `9c901b3e` compiler
failure executes no tests. See
`session-http1-peer-remedy-independent-native-review-0398751f.json`.

A separate source finding shows that exhausted scheduler budget can make a
finished join report Pending. The peer collector can then mislabel an
already completed external cancellation as local. The prior controls did
not exercise this condition. Its correction and causal control remain open.
See `session-http1-peer-cooperative-budget-independent-source-finding-13dedda4.json`.

The shared-cap baseline at `acdbf923` passes 31 of 35 selected methods on
each host. Four causal controls fail before later cleanup or cause checks.
The repair at `13dedda4` passes all 37 selected methods on both hosts:
29 prior status contracts, six prior shared-cap controls and two new cause
controls. The four original failures now reach their later oracles before
backup. Original serving errors retain their payload identity. The added
controls retain the original deadline with a completed serving failure and
an already completed external cancellation with its original task ID.
See `shared-cap-owner-remedy-independent-native-review-13dedda4.json`.

Focused formatting, strict Clippy and Rust 1.88 checks pass for both repairs.
The shared-cap operation has ten seconds; collection can add two seconds
and backup another two. The new timed caller has no received-head oracle.
These are fixture repairs. Queued ownership, cancellation races, other raw
workers, acquisition and parser paths, full gates and candidate CI remain
open. No whole-workspace or final architecture approval follows.

### Runtime deadlines and queued HTTP/1 verification

At `0dec79bb`, all 16 earlier runtime methods and two new positive controls
pass on both hosts. Three actual request deadline controls fail after the
original send enters Pending and its complete GET head is received. The
original ten-second deadline loses Elapsed. At `d7005dea`, all 21 selected
methods pass with the original error source retained. Ready response/body
and hook-error payload identity also pass. This verifies the shared request
deadline helper; raw H2/H3, held and thread-origin ownership remains open.
See `runtime-send-deadline-baseline-independent-native-review-0dec79bb.json`
and `runtime-send-deadline-remedy-independent-native-review-d7005dea.json`.

The real cooperative-budget control at `ad366637` fails on both hosts.
It observes the original peer Pending, externally cancels that peer, waits
for destruction and completion, then exhausts the actual scheduling budget.
The completed join returns Pending. Collection retains only the URI error;
the final composed-cause guard fails before JoinError and task-ID checks.
No socket-closure oracle belongs to this control. See
`session-http1-peer-budget-baseline-independent-native-review-ad366637.json`.

At `0fad2783`, all 19 HTTP/1 methods pass on both hosts, but strict Clippy
rejects the oversized Ready variant. That checkpoint is behavior evidence
with a quality failure. Boxing the moved result changes three expressions.
At `86e7ab92`, all 19 methods and focused quality checks pass on both hosts.
All nine ordinary methods and eight earlier controls retain their contracts.
The three queued cleanup failures now reach their later observations before
backup. The unchanged budget control retains the original URI/parser error
and actual cancelled JoinError with its original task ID. The added queued
control retains a completed foreign cancellation with the original
five-second Elapsed and joins both tasks. It does not assert a task ID.
See `session-http1-queued-remedy-independent-native-review-0fad2783.json`
and `session-http1-queued-boxed-remedy-independent-native-review-86e7ab92.json`.

Package formatting, strict requests/streams/sessions Clippy and Rust 1.88
checks pass on both accepted revisions. These are fixture repairs. Cleanup
can add a separate finite interval after the original caller deadline.
External Drop requests abort but cannot asynchronously join or report
errors. Unfinished foreign/local cancellation races, other raw peers,
acquisition and parser paths, remaining deadline mappings, final combined
review, full gates and candidate CI remain open.

### Stale-connection fixture verification

The baseline at `41e4831b` selects 17 methods on each host: ten ordinary
contracts and two positive controls pass; five causal controls fail.
Three fail at original-worker destruction before their socket observations.
The actual five-second caller deadline loses its Elapsed source. The combined
caller/worker error guard fails before the target serving-payload assertions.
Explicit backup retains the original serving failure. See
`stale-replay-owner-baseline-independent-native-review-41e4831b.json`.

At `e0228c78`, all 17 unchanged methods pass on Windows and Linux. The five
earlier failures now reach their later socket, no-backup, original Elapsed,
typed serving payload and identity observations. Package formatting, strict
requests/streams/sessions Clippy and Rust 1.88 checks also pass on both hosts.
The canonical fixture owns its peer before awaiting the caller and preserves
caller and collected worker failures. See
`stale-replay-owner-remedy-independent-native-review-e0228c78.json`.

This is bounded fixture evidence. Drop requests abort without asynchronous
collection. At that checkpoint, an outer deadline could discard an already
completed worker error. Seven other raw ordinary workers,
acquisition, parsing and allocation, quiet-accept errors, cancellation races,
timeout owners, final architecture review and integration gates remain open.
Replay-body I/O and redirect late-write errors also need their recorded fixes.

### Partial-response timeout fixture verification

At `0612bfc9`, each host passes eleven ordinary timeout methods and two
positive controls. Seven controls fail after their actual TLS response head,
Content-Length 2 and received `x` prerequisites. Three fail at worker
destruction before later body-closure or no-backup checks. The real body
watchdog loses Elapsed. Completed write and foreign-cancellation results
are discarded. The combined caller/worker guard fails before serving-payload
checks; explicit backup retains that original I/O failure. See
`total-body-timeout-baseline-independent-native-review-0612bfc9.json`.

At `711ca477`, all twenty methods pass on Windows and Linux. The same nine
control targets now reach actual destruction, incomplete-body failure,
no-backup, original Elapsed, serving-payload identity, composed caller/worker
causes and completed cancellation with its original task ID. One equivalent
task-ID accessor changes for the existing peer guard. The original eleven
ordinary contracts, response bytes and timeout policy stay unchanged.
Formatting, strict requests/streams/sessions Clippy and Rust 1.88 pass on
both hosts. See
`total-body-timeout-remedy-independent-native-review-711ca477.json`.

This repairs one fixture owner and its body watchdog. The original body
deadline is five seconds; explicit worker collection can add another finite
interval. External Drop requests abort without asynchronous collection.
Other raw timeout workers, acquisition, cancellation races and mixed outer
deadline retention remain open. Full gates and candidate CI remain open.

The root also reads the complete PING-failure and unprocessed-replay test
owners. Their raw task trees, ignored drain and driver errors, deadline
cause loss, body bounds and H3 error classification need further fixes.
These source findings have no new native regression results. Their exact
reads and preserved wire oracles are in `ping-replay-root-source-pass-711ca477.json`
and `unprocessed-replay-root-source-pass-711ca477.json`.

### Mixed caller deadline and body/tunnel baselines

At `e1f309e2`, the mixed replay control reaches its original completed worker,
literal held request head, real socket Pending and in-window prerequisite.
It retains the actual deadline and Elapsed, then fails at the missing combined
serving cause. All seventeen prior methods pass on each host. At `7a69d906`,
all eighteen methods pass on Windows and Linux. The unchanged mixed target
now retains the original PermissionDenied payload identity beside the deadline
before backup runs. Formatting, strict Clippy and Rust 1.88 also pass.
See `stale-mixed-deadline-remedy-independent-native-review-7a69d906.json`.

The remedy keeps the original peer and caller outcome outside the timed
caller. Healthy setup, caller and join share one absolute five-second budget.
Failure collection uses finite separate intervals. No-server setup errors,
healthy join timeout/final collection failures and finished foreign task-ID
retention are source-reviewed paths without new native controls. Seven raw
ordinary peers, parser bounds, quiet-accept classification and broader A245
remain open.

The body/tunnel baseline at `aef7eea1` runs fifty-four methods on each host:
forty-one pass and thirteen fail. Nine failures reach lifecycle targets.
Four stop at the URI prerequisite, so they do not prove cause-retention loss.
The input-only correction at `59c28617` keeps every assertion. Those four
controls now pass actual InvalidUri/parser-source checks and fail at the
missing original cancellation cause. Returned JoinError/task-ID comparisons
remain unreached. See `session-body-uri-baseline-independent-native-review-59c28617.json`.

Eight Drop/deadline targets fail at destruction before later socket checks.
The queued-setup target captures destruction, task completion and same-socket
failures before backup. Its original RecvError and operation context remain.
These are accepted TCP/TLS acquisition observations before Phantom upload,
stream reset or tunnel forwarding. All forty-one prior methods and focused
quality checks pass. At this baseline, body/tunnel ownership and queued
acquisition need repair.

Whole expect-continue source reads also confirm fifteen raw worker owners,
missing aggregate byte ceilings and discarded deadline/quiet/cancellation
causes. Expected quiet expiry is success. The original sixteen HTTP1/HTTP2/
HTTP3 contracts and timing windows remain the acceptance criteria. These
findings have no new native regression results. See
`expect-continue-independent-source-review-9b5c539a.json`.

Final architecture review, full gates, candidate CI and integration remain open.

### Verified body and tunnel ownership

At `36f6c695`, all fifty-four selected session methods pass on Windows and
Linux. Thirteen unchanged controls that failed at `59c28617` now reach their
later assertions: actual accepted-peer destruction, task completion and
closure of the same socket before backup. Four deadline cases retain their
original contextual Elapsed. Four completed-cause cases retain the actual
InvalidUri/parser source and original cancelled task IDs, including both
tunnel peers. The queued case retains its resume RecvError/context and
recovers the real Setup before checking destruction, completion and closure.
See `session-body-tunnel-remedy-independent-native-review-36f6c695.json`.

The four ordinary upload, reset and tunnel wire contracts remain unchanged.
Both host runs pass formatting, strict requests/streams/sessions Clippy and
Rust 1.88 checks. Socket draining uses a fixed buffer and waits for EOF or
the existing disconnect classification under the original bound.

These controls cancel at accepted TCP/TLS reads before upload, reset or
forwarding starts. The ordinary methods exercise those normal paths.
External Drop cannot report outputs through its abandoned caller. Unfinished
cancellation races, cleanup expiry/recovery variants and broader session
owners still need work. Full gates, candidate CI and integration remain open.

### TCP early data and TLS resumption source review

Whole root and independent reads cover the early-data server and both TCP
session owners. Six raw server factories cross fallible caller paths inside
consuming watchdogs. First-close failure branches join the worker, but erase
the original channel error. Rejected-stream read errors are discarded and
the failure helper accepts every second-accept error as expected rejection.
These findings require controls and remedies. See
`early-data-resumption-independent-source-review-36f6c695.json`.

The eleven ordinary contracts retain their original ALPN, resumption,
early-data offer sequences, request bytes and timing windows. Both bounded
helpers already retain Elapsed. Frame truncation handling and aggregate
storage ceilings remain candidates pending the intended early-data contract
and resolved TLS limits. The fifty-four session tests above exclude these
modules, so they provide no new native evidence for this source pass.

The negotiated session source passes at `5aa2f5bb` cover the complete
1188-line direct owner and 957-line parallel owner. Root and independent
reviews confirm task ownership, result retention and deadline-cause gaps.
See `negotiated-independent-source-review-5aa2f5bb.json` and
`negotiated-parallel-independent-source-review-5aa2f5bb.json`.

The direct cancellation case already aborts and awaits its tasks, but does
not check cancellation provenance. Quiet accept errors fail its observation
while discarding the actual cause. The parallel owner aborts its listener
on Drop but does not collect descendants. Its handshake cancellation
assertion and seven expected Capacity observations remain valid.

These source dispositions do not establish remediation or new native
results. Incomplete H2 receive closure, strict request parsing and finite
fixture budgets still need contract controls. Findings A251 and A252 remain
open alongside the remaining lifecycle, proxy and streaming source passes.

### Production admission and address-family pruning

The production reassessment at `5aa2f5bb` reads all six manifests and five
public crate roots, admission, stream counting, the prune timer, shared
address-family registry and H2 connection selection. Pool, TCP, request and
WebSocket callers have bounded reads. This does not establish complete
driver, proxy, QUIC or combined architecture coverage.

Independent source review confirms A253: a prune can clear an origin's
address-family memory after a real connection starts. Each entry's empty
observation precedes the final reset under a different mutex. A newly
registered runtime key can also be omitted. The affected production blobs
are unchanged at `cce7aca5`. Reproduction and the complete activity/reset
repair remain pending. Stable all-empty pruning must still clear memory.

Separate exact and negotiated pools retain different setup and admission
contracts. Declared template slots and send-time header hooks also serve
different callers. Inspection does not justify merging these mechanisms or
adding a crate. Complete redirect, retry and SSE interaction review remains
in progress.

### Remaining raw stale-worker baseline

At `44c4ab8b`, both hosts run 27 stale-replay methods: 21 pass and six fail.
All eighteen prior contracts and three new positive controls pass. Four
failures reach worker destruction after real priming and caller Drop,
failure or timeout. Two reach the missing combined caller/worker error.
Later socket assertions and returned combined-cause identity checks are
unreached. These failures establish fixture gaps, not production leaks.

Formatting and Rust 1.88 pass at that revision; strict linting fails on one
owned-result expression. Its correction at `cce7aca5` preserves the actual
success and error values. Formatting, strict three-target linting and Rust
1.88 pass on Windows and Linux. The first Linux launcher and diagnostic
wrapper fail on a trailing carriage return; the corrected LF runner exits
zero with all three checks passing. The historical baseline stays intact.
The six regressions, acquisition and parser paths, and full gates remain
open.

## Next

- [Audit plan](../architecture-audit.md): acceptance and verification.
- [Findings](findings.md): defects and their disposition.
