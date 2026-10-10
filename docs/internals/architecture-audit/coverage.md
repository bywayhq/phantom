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

## Recent verification

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
Owner and connection-worker result collection remain under repair.

The [current cache and interface review](net-cache-interface-current-standards-review-cb4c8388.md.txt)
adds full reads of both production owners and their direct tests. Three cache
tests need explicit readiness instead of scheduler timing assumptions. The
root's later paragraph edits preserve behavior and are independently approved.
Supporting partials and historical source identities remain qualified.

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

## Next

- [Audit plan](../architecture-audit.md): acceptance and verification.
- [Findings](findings.md): defects and their disposition.
