# A53 independent review: request changes

Revision: `cb935f2f32caa3cd7eaf0c588a5b0d9d3d003ed0`, good Git signature.
The paired JSON records exact Git blob IDs, SHA-256 values, line counts,
full or partial read ranges, and independent command evidence. This review
does not approve integration, a Docker run, or later revisions.

## Findings

1. **A53-R1, high, quic_interop.py:612.** `_RunnerOwner.finish` probes
   `runner-output.log.exists()` outside its failure aggregation. A
   `PermissionError` escapes after process reaping and before Docker cleanup,
   three independent restoration attempts, or the failure report. An actual
   `run` control with an outer timeout returned the log error with no retained
   timeout cause, no summary, no restoration attempts, and all three original
   checkout files still modified. Scratch remained but was absent from the
   error's recovery paths. Include the probe in guarded log collection and
   continue the other cleanup steps while preserving both causes and backups.

2. **A53-R2, medium, quic_interop.py:844.** When automatic checkout removal
   fails after `run` already retained its owner scratch, `main` rewrites the
   failed report with `[temporary]` only. The actual main control retained
   owner scratch and its three original backups, but the final summary named
   only the automatic checkout. Merge previously retained recovery paths
   with the failed checkout path before writing the replacement report.

Both controls were repeated from an immutable source snapshot exported from
the reviewed Git objects. Their exit status zero means the assertions
confirmed the defects; it does not mean the runner satisfied its contract.
Reproduction source and full observation logs are retained beside this report.

## Other reviewed contracts

The owner snapshots the three original files before mutation, adds a unique
owner token to selected Compose services and networks, and labels the pinned
Alpine helper. Fixed-name containers must be absent before launch. The
captured environment removes ambient Compose overrides, installs the private
absolute Compose configuration, and accompanies Docker inspection/removal.
Shared helpers accept the environment without changing existing callers.

The Popen launch uses a new Linux session and defers SIGINT until the child
handle is assigned. Cleanup ignores repeated SIGINT temporarily and restores
the previous handler. TERM and KILL have finite deadlines; group liveness
checks require both the original process group and session, excluding
zombies. Failed reaping preserves the modified checkout and scratch and
prevents restoration. These are source and controlled test conclusions; the
actual Linux descendant control is root-owned and skipped in this Windows run.

Docker cleanup checks full immutable IDs and owner labels before removal.
Network removal requires owned labels and no attached endpoints; a foreign
endpoint prevents removal. Final absence checks must pass. Independent
controlled tests verify ID use, wrong ownership, foreign endpoints, daemon
selection after environment changes, and cleanup errors preventing success.

The original image shell-character guards and their literal accepted/rejected
reference tests remain. The pinned upstream runner's shell Compose invocations,
temporary directories, subprocesses, and Alpine cleanup helper were read.
The copied Compose and testcase fixtures match the pinned source after LF
normalization. All five introduced lifecycle/process test and fixture paths
were fully read. `testcases_quic.py` was read only across base/HTTP3 boundaries;
that extra local file is absent from the seven-source provenance manifest.

Autobahn and TLS-Anvil shared-helper consumers were fully read. Their omitted
environment argument retains their existing ambient behavior. Their workflow
push filters cover the helper. The QUIC workflow covers the new runner tests
and fixtures, but the full external interop suite runs on schedule/manual
dispatch; its usual push/PR job performs the adapter image smoke check.

The Breaking/Migrate entry states the Linux and exclusive checkout/daemon
requirements. Contributor recovery instructions are accurate in intent but
their promised restoration/reporting is contradicted by the two findings.
Responsibilities remain explicit. Module length alone is not a defect; an
arbitrary split would not repair these concrete recovery paths.

## Independent verification

- Exact snapshot Python 3.10 focused suite: 41 methods, 40 passed, one explicit
  Linux process-identity skip. Full log read.
- Ruff 0.16.9 configured check: all six Python files passed. Format check:
  six already formatted. Full logs read.
- An initial isolated-snapshot Ruff invocation lacked the repository import
  root and reported one import-group classification error. Repeating with the
  exact unchanged repository configuration passed. Both logs are retained.
- Both recovery reproductions confirmed at the exact immutable snapshot.

No real Docker daemon, Compose network, live QUIC suite, Cargo build, full
gate, or CI run was executed by this reviewer. Frozen environment values do
not snapshot external Docker configuration or certificate files. Finite
deadlines cannot guarantee teardown of an unkillable OS process or an
unreachable daemon. Failure must remain visible and preserve recovery data.

## Next

- [Findings](findings.md): remaining verification and integration.
