# WPT acquisition and interruption followup review

Approve exact signed revision `91caf511a80d1550b5d5d326195bf053143e4e16`
for this bounded change review. Both independently confirmed findings are
fixed. No actionable finding remains in the reviewed ownership and reporting
paths. Earlier request-changes reports remain preserved at their revisions.

## Reviewed correction

The final production and test source identities are recorded in the paired
JSON. Complete source at `4effbe69` was read, followed by every changed
production function and test in both signed regression checkpoints and the
final correction. Git confirms the signed failing baseline's test blob is
identical to the final test blob. Its production blob is identical to the
previously reviewed `4effbe69` source.

The owner-local native constructor retention, serialized state exclusion and
SIGINT deferral repair the original acquired-child ownership loss. Exact
installed CPython 3.10 Windows and POSIX constructor, process and cleanup
methods support the field assumptions. No global registry mutation or
unrelated process cleanup is introduced. Pending readiness is consumed before
final shutdown status within the same deadline. Known unreaped and incomplete
acquisition states preserve and report scratch.

The final correction also preserves the first original parent interruption
when constructor/start/stop cleanup produces another error or interruption.
Independent failures remain in the cause list. Constructor endpoint cleanup
attempts both endpoints. Start still closes its child endpoint after recovery.
Stop still attempts control and process handle cleanup after observing exit.

Temporary-file removal, rotated-log removal and summary publication now apply
the same interruption priority. A deferred summary SIGINT combined with a
write error retains both causes, and a prior adapter interruption remains the
same object. Child interruption remains serialized infrastructure failure,
since a child exception object is not the parent's interruption object.

All new tests assert independently selected failure identities and observable
cleanup outcomes. The signed failing controls protect the exact paths repaired
by the production diff. They retain the original manifests, ordered adapter
arguments, full observed case map and earlier lifecycle assertions. Native
acquisition tests still execute real spawn, SIGINT and post-creation
serialization failure, rather than substituting a fake native owner.

The private process subclass has one current ownership responsibility. The
final error handling remains explicit, with operations and guards grouped by
resource and failure phase. The runner's increased size warrants inspection;
it does not establish a need for another crate or an arbitrary file split.

## Independent verification

At the clean exact final revision, the reviewer executed and read full logs:

```
uv run --no-project --python 3.10 python -m unittest scripts.conformance.tests.test_wpt_eventsource -v
uvx ruff@0.16.9 check scripts/conformance/wpt_eventsource.py scripts/conformance/tests/test_wpt_eventsource.py
uvx ruff@0.16.9 format --check scripts/conformance/wpt_eventsource.py scripts/conformance/tests/test_wpt_eventsource.py
```

All 38 applicable Windows methods pass; the POSIX-only bootstrap-write
control is explicitly skipped, for 39 total. The reviewer also reran the
original constructor interruption reproduction: original identity and both
endpoint closes now pass. A separate real-signal control verifies the custom
previous handler is restored before fixture cleanup, receives the signal only
after acquired ownership, and coalesces two signals without losing the first
interruption object. Both pinned Ruff checks and diff check pass. Signature
verification reports `G` with the required author and committer identity.
HEAD and clean working state were checked before and after verification.

The integration owner separately executed the signed `2cdeff1b` baseline.
Its full log records nine failing assertions, one error and one explicit
platform skip. The reviewer read the log and checked all 26 snapshot raw
hashes against the execution metadata and the exact Git sources. Twenty-four
files are Windows CRLF renderings of canonical LF Git bytes; two shell files
match canonical bytes directly. The paired JSON records that distinction.
No changed test or dirty production execution is inferred from this baseline.

## Scope and limits

This review establishes the inspected Windows spawn, signal, serialization,
owned cleanup and reporting behavior. Local server-interface fixtures and
file markers establish resource lifetime. They create no TLS socket and do
not establish live WPT scenario acceptance or browser parity.

The private hook relies on inspected CPython 3.10 native fields. Other
interpreter implementations remain unverified. Incomplete native state is
explicitly unobserved ownership. If OS termination and kill both fail, an
unreaped owner remains and scratch is preserved. Python's finalizer can join
remaining children without a deadline, so absolute interpreter exit is not
guaranteed. Unwritable summary publication cannot guarantee an updated disk
artifact; the inspected CLI paths retain the causes and failed outcome.

Original workflow, manifests and main Rust adapter were reviewed. The pinned
server lifecycle boundary was reviewed separately. Broader upstream
configuration/router contracts, scenario handlers, native Linux/macOS
execution and final composed integration gates remain outside this verdict.

## Next

- Compose the reviewed source and breaking summary migration documentation.
- Run native Linux/POSIX and final platform verification on the composed source.
- Complete the combined architecture review and integration gate.
