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
| Vendored modifications | Fork integration | Ordered patches, relevant upstream code | Pending |
| Manifests and feature/platform matrix | Dependency boundaries | Resolved graph, enabled lints, CI rows | Pending |
| Capture and conformance tooling | Tool lifecycle | Input validation, process ownership, tests | Pending |
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
The resolved dependency graph still needs a separate recorded check.

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
