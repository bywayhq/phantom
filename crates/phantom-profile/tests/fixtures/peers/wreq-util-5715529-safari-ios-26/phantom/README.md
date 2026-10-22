# Public-client comparison

These files record Phantom at `be7d7745e261569870869fd3f25ada31cf52a05c`,
using `safari-26-ios`. They compare three fresh public clients, each making
two verified HTTP/2 requests, with the [retained peer runs](../README.md).

`wire-localization.md` explains the original mismatches. Raw HPACK differs
only in the assigned authority port; every second block is byte-identical.
SETTINGS ACK placement varies. The original false comparison fields remain
in `capture-results/`, alongside raw streams, ClientHellos and HPACK blocks.

`live-execution.json` and `capture-results/environment.json` identify the
actual build, executable, tools and collector sources. Build output and
exit codes are retained. `preparation.json` describes earlier preparation,
including failed normalizer controls; use `live-execution.json` for the
completed run.

Code fixtures have `.txt` appended to their original names. To reproduce,
restore those names under the recorded `target/tmp/safari-ios-comparison/`
on the recorded clean source checkout, then use the retained build and
capture commands. The manifest's local dependency path expects that layout.
The parent `sha256.json` seals every retained file. No executable, private
key or duplicate upstream source is included.

## Next

Read the byte localization before interpreting the comparison booleans.
