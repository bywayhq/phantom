# A57 independent production review

Reviewed exact signed lane `78e664a0b6abcf67f160435c59415d8ce17f6a9f`,
its two regression checkpoints and both production diffs. The working tree
is clean. Paired JSON records twelve full source files, canonical Git blobs,
working-byte hashes, complete inclusive ranges, eight fully read execution
logs and a bounded resolved Python subprocess source pass.

The production source is approved for composition. One integration repair
is required: add `scripts/conformance/docker_owner.py` and
`scripts/conformance/tests/test_docker_owner.py` to the TLS-Anvil workflow's
push path filter. Changes confined to that imported dependency currently
skip its main smoke workflow. Autobahn's existing `scripts/conformance/**`
filter already covers both paths. No source files were edited by this review.

## Ownership and failure paths

Launch is marked attempted before the subprocess call. Cleanup therefore
runs after a launch failure or interruption, rather than requiring a returned
process result. Inspection requires the complete lowercase hexadecimal ID
and the exact UUID owner label. Missing-name responses require both status 1
and exact diagnostics for that name. Malformed output, foreign ownership,
daemon errors and unexpected absence wording fail visibly without removal.
Removal takes only the verified immutable ID. A later name replacement does
not redirect deletion. Both commands receive finite positive deadlines and
preserve subprocess or JSON parse causes where applicable.

The runner retains suite validation and process status independently.
Unvalidated reports use empty result data plus `suite_report_validated=false`.
A valid strict two-test report remains visible when cleanup fails. Suite,
cleanup, log retention and interrupted summary retention causes reach the
combined diagnostic. The original primary exception is the explicit cause
of the combined failure. A lone interruption is re-raised after report
retention; an interruption during the first log does not skip the second.
Failure to write the summary does not promise that a summary exists on disk.
Success output follows cleanup and summary writing.

The shared module has two actual command responsibilities and small private
validators. It does not own suite readiness, reports or launch policy. Its
second consumer remains the integration owner's pending Autobahn migration;
that composed change needs a separate review. The local cleanup helper's
errors and notes are both consumed, and its return shape represents an actual
reporting requirement. No unused configuration, new dependency, broad lint
suppression or redundant exported path was introduced.

## Tests and readable layout

The original exact regression checkpoint shows five passing controls and
two intended failures for ignored removal status and missing deadline. The
later exact retention checkpoint shows eighteen passing controls and three
intended failures. Full logs were read, including the original independent
retention reproduction and narrow read-denial reproduction.

An independent current Python 3.10 run passes all 37 owner/TLS tests. The
positive lifecycle fixture writes the literal IDs `5246-jsdAL1vDy5` and
`8446-jVohiUKi4u`, and checks both strict counts and actual command order.
These match the expected map and selected profile. The original strict
validator, duplicate-key JSON loader and integer validator are AST-identical
to the base revision. Assertions exercise actual runner/main publication,
CLI errors, immutable IDs, original interruption objects and retained
filesystem content. The controlled subprocess boundary does not calculate
expected validation by copying the production parser.

Manual review covers grouping in every changed function and test. Setup,
independent checks, report parsing, cleanup, retention and final publication
have distinct paragraphs. Related assertions remain together. The runner
has a sequential lifecycle rather than a generic execution framework.
Pinned Ruff 0.16.9 lint and format checks pass on all four changed Python
files; diff check passes. These mechanical checks supplement source review.

## Interface evidence and limits

The resolved Python 3.10 `subprocess.run` implementation kills the CLI on
its timeout/communication failure paths and drains or waits according to
platform. This does not cancel asynchronous daemon work. A timed-out launch
can still be followed by late creation after an absence result. The runner
retains the owner metadata and fails the timeout; this review does not infer
teardown from an absent inspection.

Docker's [official formatting documentation](https://docs.docker.com/engine/cli/formatting/)
confirms the JSON template helper. Representative official
[v28.0.4 inspection source](https://github.com/docker/cli/blob/v28.0.4/cli/command/container/inspect.go)
and [removal source](https://github.com/docker/cli/blob/v28.0.4/cli/command/container/rm.go)
support the used API commands. This is not certification of a locally
installed Docker version or an exhaustive third-party audit.

No Docker daemon, actual TLS-Anvil suite, OS signal, browser, socket or Cargo
execution occurred in this review. The retained-size log cap still reads the
whole input file first; it does not bound peak memory or initial disk output.
Existing JSON loads, captured inspect output and Git revision lookup have no
new global resource bound. Final composed Linux checks, full gates, actual
conformance CI and contract documentation remain required.

## Next

- [Findings](findings.md): verification and integration state.
