# Conformance ownership and reporting review, pass 06

Reviewed root main `df2ae9b7d87567907a2f273068220349dcd4750b`.
The paired coverage JSON records sixteen complete first-party file reads,
their Git blob IDs, canonical and working-byte hashes, and exact ranges.
WPT runner, parser tests and manifests repeat the earlier pass 05 reads;
they are not newly counted as additional files. The root checkout remains
clean. No tracked files, Cargo builds, browsers, Docker or native servers
were changed or executed.

## WPT cleanup and reporting: confirmed controlled failures

`scripts/conformance/wpt_eventsource.py:331-342` publishes the scenario
summary and announces its result before shutdown. Server and logging cleanup
run at `362-369`, outside the exception branch that records infrastructure
failure at `343-361`. A shutdown or handler-close error therefore fails the
CLI while leaving a retained summary with zero failures. A shutdown error
also replaces an earlier scenario error in the CLI message at `384-387`.

The ignored scratch regression `wpt-lifecycle-repro.py` invokes actual
`run` and `main`, strict parsing and filesystem summary publication. It
controls checkout, certificate creation, adapter subprocess and server
boundaries. It uses the complete ordered full manifest, not a one-case
stand-in, and verifies every emitted `--case` argument and configured
subprocess deadline. Synthetic files are explicitly boundary artifacts;
they are not valid certificates or a native server.

Actual Python 3.10 baseline command:

```
uv run --no-project --python 3.10 python target/architecture-audit/wpt-lifecycle-repro.py
```

`wpt-lifecycle-baseline-windows.log` records seven methods: the complete
successful case set and complete scenario-failure control pass; five
regression assertions fail. Specifically:

- Server-stop failure: CLI exit 2, but summary `failure_count` is zero.
- Handler-close failure: CLI exit 2, but summary `failure_count` is zero.
- Scenario and stop failures: case detail remains in JSON; CLI reports only
  `stop marker`, losing the earlier scenario cause.
- Lifetime ordering: controlled stop observes both source and certificate
  paths already absent, although it is still the active server owner.
- Startup handoff: the actual pinned WebTestHttpd class, extracted from its
  AST and run with controlled Httpd and failed Thread.start boundaries,
  receives no explicit close through Phantom's `_start_server` failure.

The last assertion proves missing explicit cleanup, not a persistent native
socket leak: it deliberately retains the acquired fake owner for observation.
No claim about garbage-collector timing or surviving OS threads follows from
that control.

## Exact pinned server ownership trace

Read WebTestHttpd's constructor, start, stop and URL methods and the relevant
WebTestServer constructor, bind, serve and shutdown methods. The downloaded
file belongs to WPT revision `7dbbcb8bcbf62683e6ac095da7d95a84b3672ab5`;
GitHub's exact-ref Contents API reports blob
`e34cd3601d42dbee60ac318c251e27261d929499`, which matches the independently
computed blob hash. The file's SHA-256 and bounded ranges are in the JSON.

WebTestHttpd owns a server socket and daemon thread. Start marks `started`
before starting the thread. Stop performs shutdown, close and join when
started, but catches AttributeError and then clears `httpd`. Request threads
are daemon threads. There is no subprocess owner in this normal path.
See the [pinned server source](https://raw.githubusercontent.com/web-platform-tests/wpt/7dbbcb8bcbf62683e6ac095da7d95a84b3672ab5/tools/wptserve/wptserve/server.py).

Calling upstream stop after any startup error is insufficient as a
general design: the thread may never have initialized its shutdown socket.
Any remedy must deliberately close an acquired but unstarted server socket,
while using normal stop for a successfully started server. Constructor
failure before returning an owner is a dependency boundary, not newly proved
as a retained native leak here.

## Proposed bounded WPT remedy

Keep the source and certificates alive through server shutdown. Register
logging ownership before fallible setup, and keep ownership of the constructed
server across start. Attempt every acquired cleanup owner even if another
cleanup fails. Preserve the primary cause and secondary shutdown/logging
causes deliberately in CLI diagnostics and the retained summary. Preserve
the actual case map and counts; do not convert successfully observed cases
to failures merely to represent infrastructure failure.

Publish the final success message only after required cleanup succeeds. The
summary should retain explicit infrastructure errors and make the overall
run failure visible, with a documented relationship between case failures
and infrastructure failures. Do not infer completed native server teardown
from fake controls. Before production edits, regression-only lane tests
should cover successful start/stop, startup failure, both scenario and cleanup
failure, all cleanup owners attempted, and ordinary scenario-only failures.
No public knob, compatibility shim, protocol change or new dependency is
needed.

## TLS-Anvil cleanup: independently confirmed

Fully read `tls_anvil.py`, its existing parser tests, Dockerfile, trigger,
client configuration, exact two-ID profile and expected result set, workflow,
and `tls_anvil_client.rs` adapter. The wrapper builds a pinned suite image,
runs it in an isolated network namespace with the loopback adapter, and
strictly checks exactly two independent report IDs. The adapter performs one
TLS connection with a five-second timeout; its disabled authentication is
explicit in this test harness, not claimed as authenticated client coverage.

Runner `scripts/conformance/tls_anvil.py:248-255` removes a named container
with `check=False`, no subprocess deadline, and no result inspection.
It then validates reports and writes/announces success at `257-274`.
A failed required removal is consequently ignored and can leave the CLI and
retained summary successful. The intended five-minute execution timeout also
cannot bound a blocked removal in the finally block.

`tls-anvil-lifecycle-repro.py` controls all subprocess boundaries and creates
real report files containing the two literal expected IDs and complete strict
counts. No Docker is invoked. Actual command:

```
uv run --no-project --python 3.10 python target/architecture-audit/tls-anvil-lifecycle-repro.py
```

`tls-anvil-lifecycle-baseline-windows.log` records three methods: the complete
two-test positive passes, failed-removal and finite-deadline assertions fail.
An initial fixture accidentally intercepted Python's Windows platform query;
that invalid run is retained separately as
`tls-anvil-lifecycle-invalid-platform-fixture-windows.log` and is not defect
proof. The corrected fixture controls platform metadata explicitly.

A remedy must bound cleanup, retain its causes, and fail the overall run
when owned cleanup fails. Ownership must be proved with a unique label and
immutable verified container ID before removal; blindly removing a generated
name after an uncertain launch can affect a preexisting owner. Existing
report checks, selected IDs, suite configuration and build/run deadlines
must stay intact. This is a separate supported candidate from WPT.

## Independent contract checks and remaining gaps

The nine existing WPT/TLS-Anvil parser tests pass under Python 3.10. The log
`conformance-pass06-existing-tests-windows.log` was read in full. Those tests
validate manifests, exact result sets, duplicate rejection and strict counts;
they do not validate cleanup.

The Rust WPT adapter's three files were fully read. Main gives each selected
case an eight-second deadline and emits bounded one-line diagnostics plus an
exact summary. Stream helpers limit retained event counts. Request cases
assert event fields, reconnect count, retry behavior and typed HTTP status
rejection. The bogus-retry case uses wall-clock tolerance; this review did
not measure it. The adapter requests its configured localhost HTTPS root,
uses the supplied trust root and isolated clients for state-sensitive cases.

This pass did not execute or fully compare those Rust assertions to upstream
JavaScript scenario bodies. It does not prove fresh WPT parity, native TLS
acceptance, Docker behavior, indefinite request-thread shutdown, or a live
heap bound for captured subprocess output. WPT config/router/request
dependencies remain unread except through the bounded server ownership
trace. No broad cleanup abstraction is proposed from duplicate code alone.

## Next

- [Findings](findings.md): verification and integration state.
