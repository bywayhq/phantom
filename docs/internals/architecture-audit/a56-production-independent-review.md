# WPT process ownership independent review

The exact signed revision `18319655224556055006f13ef4d08a0bf6ff3afa`
requires a repair before integration. All 25 existing Python 3.10 controls
pass independently, but they miss an acquired-child interruption window.

## Finding

At `scripts/conformance/wpt_eventsource.py:334-357`, `Process.start()`
can launch its native child before `BaseProcess.start()` assigns `_popen`.
Python 3.10's actual source sets `_popen = _Popen(self)`. The constructor
creates the child and serializes its startup data before returning.
An ordinary SIGINT can raise `KeyboardInterrupt` before the assignment.

The runner then observes `process.pid is None`, marks the owner unstarted,
skips stop/reaping, closes the process object and removes its source and
certificate files. Assigning `_ServerOwner` before `start()` does not close
this inner acquisition window.

The retained reproduction uses an actual Windows spawned child and the
actual runner. Its independent local server fixture writes an external
startup marker. After observing that marker, the injected interrupt occurs
between the native constructor returning and the process owner assignment.
This is a deterministic injection at a real interruptible boundary, rather
than a claim that a random SIGINT race was observed.

The full log confirms:

- The native child remains alive after `run()` finishes its cleanup.
- The temporary root has already been deleted.
- Child stop observes its source and certificate files absent.
- The child exits with status 1 after its final pipe send fails.
- The retained summary reports only the startup interruption.

The review retains the exact native handle separately and waits/reaps and
finalizes only that child. The external fixture creates no TLS socket.
Its delayed stop makes the file-lifetime violation observable without a
native WPT execution claim.

Defer real SIGINT across process acquisition until the handle is installed,
then propagate it through owned cleanup. Add a real-SIGINT acquisition
boundary control, alongside an actual spawn file-lifetime control. A
deliberately raised `KeyboardInterrupt` bypasses a signal deferral handler,
so that injection alone cannot validate the proposed remedy. Inspect
synchronous native construction/serialization failures separately: the
standard-library constructor can also fail after creating a child.

## Reviewed contracts

Production and test modules were read in full. Workflow, both manifests and
the main Rust adapter were also read in full. The paired JSON records exact
Git blobs, canonical and working-byte hashes, line counts and review ranges.
The pinned upstream server review is bounded to construction, serving,
start and stop. The Python 3.10 review is bounded to process start, Windows
native construction and interpreter finalization.

Apart from the acquisition finding, the inspected cleanup correctly owns
the server in the child, closes acquired-unstarted sockets, attempts socket
and log cleanup after stop failure, retains primary and cleanup causes,
observes final status and process exit, and preserves scratch for a known
unreaped owner. Main-thread SIGINT during shutdown is deferred while owners
and files are cleaned, with the previous handler restored.

The original ordered manifests remain unchanged: full has 29 scenarios,
smoke has 11. Observed case maps and counts remain separate from
infrastructure failures. Setup failure has zero observed cases and
`run_failed=true`. Adapter arguments and deadlines remain applied. Final
success is printed after cleanup. Root must add the breaking migration note
for summary readers.

The implementation uses one concrete private process owner with current
callers. It does not add a generic process framework. New operations and
tests have readable setup, action and result groupings. The real spawn
control tests child imports, actual logging and reaping, while the fault
fixtures cover owner escalation and failure aggregation. Those fixtures do
not establish a live TLS handshake or upstream scenario execution.

## Independent verification

Executed at the reviewed revision and read in full:

```
uv run --no-project --python 3.10 python -m unittest scripts.conformance.tests.test_wpt_eventsource -v
uvx ruff@0.16.9 check scripts/conformance/wpt_eventsource.py scripts/conformance/tests/test_wpt_eventsource.py
uvx ruff@0.16.9 format --check scripts/conformance/wpt_eventsource.py scripts/conformance/tests/test_wpt_eventsource.py
uv run --no-project --python 3.10 python C:/code/phantom/target/architecture-audit/a56-independent-acquisition-repro.py
```

All 25 existing tests pass. Both pinned Ruff checks pass. The reproduction
passes its observation assertions describing the defect; those assertions
are not successful regression coverage. Diff check and the production
signature pass, and the inspected lane was clean.

Explicit owner waits have finite budgets. Python 3.10's actual
`multiprocessing.util._exit_function` subsequently joins remaining active
children without a timeout. An OS failure that defeats both termination
and kill therefore prevents an absolute interpreter-exit guarantee. Keeping
scratch and reporting unreaped ownership is accurate. The remediable
acquisition gap above is a separate issue and cannot use that OS limit as
its disposition.

No live WPT suite, Linux/macOS process control, Cargo gate or whole
architecture approval is claimed. Scenario handlers and the broader
upstream configuration/router contracts remain outside this change review.

## Next

- Repair the acquisition boundary and retain a failing regression baseline.
- Repeat independent review at the corrected signed revision.
- Compose migration documentation and platform verification before integration.
