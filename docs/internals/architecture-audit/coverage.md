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
| Repository configuration | Maintainer boundaries | Active callers and enforcement | Pending |
| Combined architecture | Independent final review | Cross-crate lifecycles and integrated changes | Pending |

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

Capture review reproduces a preassignment child escaping Windows job cleanup,
a profile-prefix sweep stopping a different profile, and a quoted path
preventing cleanup. Tests use harmless owned processes, rather than browsers.
The launch and sweep remedies are in progress.

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

## Limits of the record

Assignments do not establish coverage. Each completed pass must list the
files and functions read, the paths traced, the relevant test contracts,
and remaining uncertainty. Follow-up passes cover gaps before completion.

## Next

- [Audit plan](../architecture-audit.md): acceptance and verification.
- [Findings](findings.md): defects and their disposition.
