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
| Documentation and public API inventories | Published contracts | Source comparison, examples, retained evidence | Pending |
| Repository configuration | Maintainer boundaries | Active callers and enforcement | Bounded source pass recorded; remaining configuration and enforcement pending |
| Combined architecture | Independent final review | Cross-crate lifecycles and integrated changes | Pending |

## Engineering standards

The supplied standards apply throughout the audit. The source records below
establish bounded reviews; they do not establish a whole-codebase sign-off.

| Review concern | Recorded work | Remaining work |
| --- | --- | --- |
| Ownership, tasks and synchronization | Client and transport lifecycle reviews, capture cleanup regressions | Untouched paths and final composed ownership review |
| Input bounds, failures and diagnostics | Parser, buffer, credential and failure-path repairs | Remaining tooling, platform paths and integrated regressions |
| Design, visibility and dependencies | Workspace manifests, resolved crate direction and selected API callers | Canonical exports, unused layers and justified module boundaries |
| Names and readable layout | Manual operation and invariant review in retained source reports | Full naming, function responsibility, grouping and test-placement pass |
| Tests and verification | Independent contract reviews and recorded failing/passing regressions | Remaining assertions and exact final gates |
| Documentation and enforcement | Bounded page, command and configuration reviews | Remaining public contracts, support claims and final roadmap reconciliation |

Structural proposals need current source evidence and a complete caller
design. A new crate needs an actual consumer, dependency isolation, or a
compilation boundary. Repeated names, file sizes and passing lints alone
do not establish that need.

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

## Limits of the record

Assignments do not establish coverage. Each completed pass must list the
files and functions read, the paths traced, the relevant test contracts,
and remaining uncertainty. Follow-up passes cover gaps before completion.

## Next

- [Audit plan](../architecture-audit.md): acceptance and verification.
- [Findings](findings.md): defects and their disposition.
