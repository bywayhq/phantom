# Audit coverage

Use this matrix to see which paths have been examined and what remains.
Pending means that discovery or assignment has not established review.

## Source review

| Area | Pass | Evidence required | State |
| --- | --- | --- | --- |
| HTTP client and session pools | Client lifecycle | Source, callers, independent tests | In progress |
| HTTP, proxy, resolver, TCP and TLS transports | Transport lifecycle | Source, cancellation and resource contracts | In progress |
| Profiles and QUIC TLS backend | Profile and FFI boundaries | Validation, public contracts, FFI assumptions | In progress |
| Testkit and fuzz workspace | Harness contracts | Parser bounds, independent oracles, fixtures | Pending |
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
reads are further along than browser recipes, capture assets, and the larger
test suites. Source review is not a cryptographic or live-browser proof.

Independent reviews cover the proposed admission, ticket, DNS, body,
template-debug, and proxy-waiter changes. They trace callers and test
controls separately from implementation. Final composed review is pending.

The integration owner inspected all workspace manifests and their feature,
target, and lint declarations. The two FFI crates deliberately declare
their lints separately so they can deny, rather than forbid, unsafe code
at the audited module boundary. No current baseline mismatch was found.
The resolved dependency graph still needs a separate recorded check.

Testkit review has read its public exports, UDP binding/retry helper, TCP
port reservation, and future-size test assertions. DNS, HTTP and TLS capture
parsers and matching tests remain pending. A documented test assertion
panic is distinct from a recoverable runtime failure.

Tooling review has found a reproducible false-success boundary scan and
is investigating lock ownership and related scanner failure paths. This
does not establish completed CI, development, or release-tool coverage.

## Limits of the record

Assignments do not establish coverage. Each completed pass must list the
files and functions read, the paths traced, the relevant test contracts,
and remaining uncertainty. Follow-up passes cover gaps before completion.

## Next

- [Audit plan](../architecture-audit.md): acceptance and verification.
- [Findings](findings.md): defects and their disposition.
