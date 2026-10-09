# Consumer and repository configuration review

This pass reviews downstream test contracts and repository configuration at
`0ad0d560`. It records source inspection, separately from pending consumer
execution and remote enforcement.

## Repository ownership and reports

The ownership file assigns every path to one team. Whether that team exists
and can approve changes requires GitHub permission evidence. The issue forms
request a revision, reproduction, environment and sanitized evidence. Both
the bug form and contact links direct vulnerability reports to private
reporting. These files do not enforce secret filtering on submissions.

Both root license files were read completely. This is an inventory and
packaging review; it does not establish compliance for every dependency or
authority to grant rights. Dependency-license checks remain separate.

## Consumer contracts

The independent consumer manifest declares Phantom and testkit directly,
without a patch table. Its optional feature forwarding covers JSON, SSE and
HTTPS records. Ignored lock and target files are local build artifacts. Its
attributes preserve fixture bytes.

The public-type tests compile named customization, error and response types.
Status-policy and authorization assertions state independent outcomes.
The ECH test constructs literal configuration bytes and checks public parsed
values and the empty-list error. It does not exercise an encrypted handshake.

Workflow tests prepare requests without sending them. They cover explicit
routes, inherited environment snapshots, templates, bounded bodies, timeout
overrides and retries. The single-poll cancellation function and SSE trait
assertions are compile-only examples. They establish API availability, rather
than cleanup or streaming behavior.

Wire tests use a loopback listener under an outer deadline. Retained browser
requests supply expected bytes. Target, authority and Chrome's headless
User-Agent adjustment are explicit. Reordered headers, changed values and
case, omitted fields, empty input and truncation must fail comparison.
The spawned peer is joined on success; early errors rely on test runtime
teardown. This source does not establish a production task leak.

The adjacent fixture README states the original paths, hashes and capture
conditions. Raw fixture review in this pass is limited to metadata and selected
request sections. Neither byte identity nor this retained corpus establishes
a fresh browser capture or every transport/profile combination.

## Consumer verification script

The script copies tracked and nonignored files into isolated consumers,
generates a lockfile, validates the resolved dependency graph, and tests it
with default and optional consumer features. Both path and local Git modes
enable Phantom's full feature set. The graph check rejects stock packages,
requires one renamed fork per package and verifies the pinned native source.

Temporary consumers share build artifacts within one identical source
snapshot. Cleanup runs on exit and signals. Registry mode requires an explicit
version and is distinct from path/Git verification. Source inspection does
not prove registry availability. No package was published.

## Next

- [Coverage](coverage.md): reviewed files and execution boundaries.
- [Findings](findings.md): defects and their verification.
