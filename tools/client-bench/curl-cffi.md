# Run the curl_cffi adapter

Use `curl_cffi_client.py` with CPython 3.12 and `curl_cffi==0.16.3` in an
isolated environment. Add its absolute path and interpreter to a client
descriptor as described in the [controller guide](README.md#use-another-client-executable).
Pin the installed Python sources, native modules, runtime libraries and
dependency lock in that descriptor too. An interpreter hash alone does not
identify a Python environment.

The first adapter supports direct HTTPS GET requests to the controlled IPv4
loopback peers. It covers exact HTTP/1.1, HTTP/2 and HTTP/3, cold or shared
clients, streaming or collection, multiple origins, and planned arrivals.
Set `workers: 1` explicitly. This adapter uses one Python event loop.
`peer_workers` can hold the independent server's worker count fixed.

Use the same workload parameters for each library. Start with a short
diagnostic matrix before collecting timing data. Unsupported routes, profiles,
compression, templates and Phantom diagnostics fail before warmup.
Uploads, redirects, proxy authentication and cancellation need separate
workloads and are not covered by this adapter yet.

## Settings and measurement boundaries

- Recipe: curl_cffi's `chrome150`, with automatic browser headers disabled.
- Trust: the peer's generated root, with certificate and hostname checks.
- Protocol: an explicit version, checked again on every response.
- Limits: 5-second connect, 15-second native transfer and application deadlines.
- Replay: application retries and redirect following disabled.
- Proxy: disabled explicitly, including environment proxy settings.
- Handles: `max_clients` equals configured concurrency. Connection pools keep
  library defaults, so equivalent per-origin pool limits are not established.

`profile: "chrome"` selects the stated curl_cffi recipe. It does not promise
the same wire fingerprint or browser version as Phantom's Chrome recipe.
The public streaming API uses an unbounded body queue. Its prefetch and
backpressure semantics differ from pull-based response bodies.

Head timing is unavailable: streaming readiness follows body delivery.
`first_byte_ns` measures the application's first nonempty body delivery.
Collection has no first-delivery timestamp. Completion includes EOF and
payload verification. Cold samples include client construction, with cleanup
outside request completion but inside phase elapsed time and CPU.
Cleanup failures mark the operation failed and retain any request error too.
The peer records QUIC transport `NO_ERROR` closes separately after all response
tasks on that connection finish successfully. A close before any completed
response or an interrupted response still fails the trial.

The result records effective settings and Python version. Observation storage
is the sum of unique shallow object sizes before measurement. It excludes
allocator slack and later replacement integers. Process memory includes the
Python runtime, bindings, native libraries and subsequent observer growth.
This storage count is not interchangeable with Rust's fixed sample buffer.

The controller measures the adapter process directly. Keep native compiler
flags and dependency provenance before attesting that a wheel is optimized.
A package version or wheel hash alone does not establish those flags.

## Windows interpreter selection

Windows virtual environments can start a redirector that launches a second
Python process. The controller samples its directly launched process. Measuring
the redirector would omit the client's CPU and memory.

Launch the base interpreter directly with `-I` and a pinned bootstrap script.
Pass the adapter path and the isolated environment's `Lib/site-packages` as
the bootstrap's first two arguments. The controller appends the run arguments.
This example also records the executing PID beside the trial result:

```python
import json
import os
from pathlib import Path
import runpy
import sys

adapter, packages = sys.argv[1:3]
with Path(sys.argv[-1]).with_name("adapter-runtime.json").open("x") as stream:
    json.dump({"pid": os.getpid(), "executable": sys.executable}, stream)
sys.path[:0] = [str(Path(adapter).parent), packages]
sys.argv = [adapter, *sys.argv[3:]]
runpy.run_path(adapter, run_name="__main__")
```

Pin the bootstrap, adapter, base interpreter and package files in the
descriptor. Check that the recorded PID matches the controller's client PID
in `process.json` before using process counters. Keep these receipts with
the results. A passing payload check alone does not verify process attribution.

## Next

- [Interpret measurements](README.md#interpret-the-measurements).
