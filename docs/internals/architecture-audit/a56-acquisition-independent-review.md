# WPT acquisition independent review

Revision `4effbe6952bd67a655dc846bbd1ed7fcc45dfbb1` repairs the independently
reproduced native acquisition loss. One interruption identity defect remains
before approval. The earlier review of `18319655` is preserved separately.

## Acquisition ownership

The complete updated runner and test module were read at the exact Git
revision. Original manifests, workflow and main Rust adapter were previously
read in full and remain unchanged. The paired JSON records exact source
identities and the installed Python 3.10 boundary review.

The private `_ServerProcess` retains the native constructor before its
initialization. Its serialized state excludes that parent-owned constructor
and finalizer. Recovery installs an acquired native object only after checking
the platform fields needed by actual join, poll, terminate and close methods.
No global child registry is changed by the repair.

Complete installed Windows and POSIX native constructor sources support those
field assumptions. Windows installs its native handle, PID, sentinel,
returncode and finalizer before serializing process data. POSIX's inherited
constructor initializes returncode, then the post-spawn write path installs
its finalizer before propagating a write failure. Complete BaseProcess source
confirms the recovered object works with normal process ownership methods.

Actual SIGINT is deferred through native acquisition and endpoint close, then
the previous handler is replayed after its restoration. Pending readiness is
consumed before final status within the same shutdown budget. Incomplete
native state is explicitly reported as unobserved ownership and preserves
scratch. The runner also retains nonzero exit status after forced shutdown.

Independent Windows tests execute the real native acquisition interval,
actual SIGINT, constructor failure after acquisition and second serialization
dump failure after native creation. Their assertions require observed child
exit and file lifetime through shutdown. These controls remain meaningful
after retargeting the hook to the concrete private process owner.

A separate reviewer control raises real SIGINT twice during owned start. It
verifies the custom previous handler is restored before returning, is called
once after an acquired PID, and preserves its original interruption object.
The check observes restoration before the fixture restores its outer handler.

## Remaining finding

`_ServerOwner.__init__` preserves cleanup causes, but wraps a process
construction `KeyboardInterrupt` in `_ServerFailure` when endpoint close also
fails. The CLI consequently raises `SystemExit` instead of the original
interruption object. The documented parent interruption contract applies to
this acquisition phase as well as `start`.

The retained controlled reproduction executes the actual runner, injects the
original interruption at process construction, and closes the acquired child
endpoint before raising an `OSError`. Both endpoints are closed and both
causes appear in the summary. The original interrupt identity assertion fails.
No native child is created by this reproduction.

The integration owner assigned this confirmed repair to the lane author.
Approval awaits the corrected signed source and regression results. Related
secondary interruption paths are being reviewed by the author.

## Verification and limits

Fresh reviewer execution at `4effbe69` passes 31 methods with one explicit
POSIX-only skip: 32 total. Both pinned Ruff checks pass. The controlled
construction reproduction fails its original identity assertion as intended.
Full logs, source hashes and the independent signal control are retained.

This review establishes Windows spawn and controlled resource lifetime,
including actual handler behavior. Fixtures create no TLS sockets. It does
not establish live WPT scenario execution, Linux/macOS process behavior or
combined integration gate results.

The hook relies on inspected CPython 3.10 native fields. Other interpreter
implementations remain unverified. Incomplete native state is reported rather
than guessed. An OS failure defeating both terminate and kill remains an
unreaped owner. Python finalization can join remaining children without a
timeout, so an absolute interpreter exit deadline is not claimed.

## Next

- Fix constructor interruption identity and verify related cleanup paths.
- Independently review the resulting exact signed revision.
- Run native platform composition and update the summary migration notes.
