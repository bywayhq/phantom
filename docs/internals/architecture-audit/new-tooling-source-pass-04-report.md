# Conformance lifecycle source continuation

Snapshot: `5fe62ee4c5b8c7a8e3aa0d34f37ad3d85a9cc757`. Eighteen repository files were freshly read in full, two documentation files partially, plus exact pinned upstream source ranges. The JSON preserves raw Git blob SHA-256/OIDs, line counts, read ranges and prior records without replacing their original revision/hash basis. No Cargo, tests, controlled subprocess failure, Docker command or container was executed. Read-only primary source retrieval is separate from conformance execution.

## Actionable source findings

- `crates/phantom-net/examples/quic_version_interop.rs:26: minor`: a zero count skips every request and returns success with zero observations. No dry-run contract is documented. Require a positive count in both manual CLIs before setup; keep default three. This does not invalidate the documented three-request measurements. The actual Python name is `aioquic_versions.py`; there is no `quic_version.py`. Its zero count does not immediately succeed without traffic: it times out, or stops after an actual first request.
- `scripts/conformance/autobahn.py:391: major`: successful conformance can return after force removal exits nonzero because its status is discarded. Log collection/removal have no deadline; readiness inspect also escapes its claimed 30-second bound. A detach timeout before `container_started = True` skips cleanup despite uncertain container creation. Establish ownership before launch, attempt finite checked cleanup, preserve the original suite cause and retain failed cleanup in the final outcome. Do not use an ignored cleanup result as success evidence.
- `scripts/conformance/quic_interop.py:306: major`: outer timeout/interruption has no external-resource owner cleanup; the finally block restores files only. This can interrupt upstream compliance before any per-case timeout stop. The pinned Compose file uses fixed global names, so blind removal would risk unrelated owners. A remedy must establish verifiable ownership and stop the process tree and owned containers before restoring configuration. Actual container survival has not been reproduced in this pass. Python documents that run's timeout kills/waits for its child; it does not promise external Docker cleanup. [Python 3.10 subprocess](https://docs.python.org/3.10/library/subprocess.html), [pinned runner Compose](https://raw.githubusercontent.com/quic-interop/quic-interop-runner/740c05a10b61d65e8abd3ad38d60898004d335d9/docker-compose.yml).
- `crates/phantom/examples/quic_interop/main.rs:221: major`: cleanup removes a pre-existing `.first.part` after create_new fails; batch cleanup at 195–200 also removes planned paths never created by this invocation. Preserve create_new refusal and restrict cleanup to actual successfully created ownership. Root assigned this A50 and authorized a separate regression-only lane after this checkpoint.

## Exact boundary traces and test controls

Autobahn loads a bounded case selection, builds the adapter, generates trusted loopback material, launches one named detached container, probes TLS, runs the adapter under its mode deadline, reads the independent peer report, and only then executes finally cleanup. Summary validation rejects empty/wrong-agent/missing/miscounted reports. The adapter runs each discovered case and updates reports under deadlines; receive errors alone intentionally do not decide malformed-protocol cases. Independent peer classification and the adapter exit code decide the outcome. Three Python tests cover report classification only; they do not exercise launch, timeout, log or removal failures.

The QUIC wrapper verifies a clean exact upstream checkout, validates selected roles/images, retains metadata, temporarily changes three files, runs one upstream HTTP/3 pair and requires its exact succeeded result plus process success. Its eight current Python tests exercise registry/result contracts, including rejected-input atomicity and preserved legitimate image spellings; no current lifecycle fault-injection tests cover run(). The endpoint refuses empty or excessive URL sets, uses owned JoinSet downloads under a batch deadline, requires HTTP/3 and successful response status, and bounds bytes per file. Its cleanup currently confuses planned file paths with ownership.

The upstream CLI passes the pair to InteropRunner. Compliance launches Compose without a timeout; ordinary cases use a timeout and stop branch. This rejects the blanket claim that every ordinary timeout leaks. The outer wrapper can terminate before that inner branch runs. Fixed `sim`, `client` and `server` names also mean a new owner policy must account for concurrency and foreign containers, not merely add a global down command. Docker down is a cleanup mechanism rather than proof of ownership. [Pinned runner](https://raw.githubusercontent.com/quic-interop/quic-interop-runner/740c05a10b61d65e8abd3ad38d60898004d335d9/interop.py), [Docker Compose down](https://docs.docker.com/reference/cli/docker/compose/down/).

Manual version reporting is a diagnostic reproduction rather than an assertion suite: status/body/resumption are printed, and the documented three requests compare an independently reporting aioquic peer. The client zero path still violates a useful positive-observation configuration. Python's five tests cover reporting, loopback refusal and bind retries only. Neither documented default measurements nor existing platform coverage are discarded because of that unused zero configuration.

## Bounded reproductions to delegate

Use subprocess fakes for Autobahn: exact valid smoke peer results followed by removal exit one must fail; inject log plus removal failure and preserve the earlier cause; force a detached-launch timeout and assert scoped cleanup. Check finite timeout arguments directly. Do not invoke Docker for these initial controls.

For QUIC ownership, use a controlled runner/process tree and fake container registry. Inject timeout during compliance and the ordinary case, plus interrupt/error/normal exits; require attempted owned cleanup, restored bytes, failed summary and preserved cause. A fake establishes local control flow; actual Docker survival needs a separately owned reproduction. Do not delete real or foreign containers to prove a candidate.

For A50, retain independent sentinels on create_new refusal and batch failure before creation, then verify only newly created staging files are removed. Positive download controls should use owned loopback if feasible. Root runs the red baseline and chooses a production remedy; no production changes belong to this pass.

## Readability and remaining coverage

The scripts' domain grouping and CLI entry points are clear. The actual complexity comes from launch flags and cleanup/failure state separated across scopes. Narrow ownership objects or one explicit owned-run scope may be justified; a generic runner framework, broad reformat or configuration churn is not required.

Additional unclosed source boundaries are retained in JSON: manual temporary certificate directories have no cleanup and listener port publication precedes its close-finally; QUIC stdout is fully buffered before its retained-log truncation; wildcard Autobahn modes prove cardinality rather than exact expanded IDs. These were not reproduced here or folded into the prioritized defects.

TLS-Anvil runner/tests/configs and WPT EventSource runner/tests/configs remain genuinely unread in this continuation; the QUIC requirements file retains its earlier partial read. The JSON names all twelve prior partial/unread records explicitly. Seventy-five capture rows remain with their separate owner. Current PR/push QUIC workflow green proves image build and unsupported-case checks, while upstream peer execution is limited to scheduled/manual runs. No blanket tooling closure or fresh runtime verification is claimed.

## Next

- [Findings](findings.md): verification and integration state.
