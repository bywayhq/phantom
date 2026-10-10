# Tooling source continuation 05 checkpoint

Paused for A54 implementation. Root baseline
`df2ae9b7d87567907a2f273068220349dcd4750b` was verified. Completely read the
392-line WPT EventSource runner, 77-line tests, 111-line workflow and both
case manifests. Exact Git blob hashes/ranges are in the adjacent JSON.
No runtime, build, Docker or network execution occurred in this pass.

The manifest/parser tests independently assert pinned revision, unique
ordered identifiers, duplicate-key rejection, exact observed case sets and
summary counts. They do not assert runner lifecycle behavior. The workflow
prebuilds the adapter before its timed run and always uploads reports.

A source-supported cleanup reporting candidate remains: runner lines
331-342 write success/failure results before server/log cleanup at 362-369.
Cleanup is outside the except branch that creates infrastructure failures.
A stop failure therefore leaves a successful summary intact while the CLI
fails; simultaneous scenario/stop failures are reduced to the final string
by main at 384-387. No controlled regression has run yet. Proposed controls
use independent passing/failing adapter records with injected stop failure
and inspect actual CLI plus retained summary.

Two dependency-sensitive candidates remain unresolved. The temporary
checkout/certificate context exits before server.stop, so owned resources
may disappear while the server is still alive. Also _start_server can fail
before returning an owner. Actual pinned WebTestHttpd constructor/start/stop
cleanup was not read; neither candidate is counted as confirmed behavior.

TLS-Anvil runner/tests remain genuinely unread. Rust WPT adapter behavior,
pinned WPT server lifetime and capture-output memory bounds remain explicit
gaps. The artifact log-size cap is not a runtime heap bound. Sparse Git path
or metadata counts are not claimed as completed review. Rotated backup
removal alone was rejected as a defect, and CI already prebuilds the client.

## Next

- [Findings](findings.md): verification and integration state.
