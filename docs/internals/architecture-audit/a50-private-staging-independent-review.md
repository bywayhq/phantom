# A50 private staging source review

Source approved at `ccc167167286c75f5d129a962010ec4940e23202` for the explicitly exclusive private staging contract. Actual Windows and native Linux verification remain pending. This report follows the original `320be15b90553de2c30c9bc2aa0c63d3c19931f0` source review and the replacement regressions at `18403468`; their original two red controls remain retained, rather than being rewritten as passing historical evidence.

Ordinary concurrent invocations are covered coherently: each creates a random staging directory exclusively under the destination directory. It records the directory guard before opening its private file or reaching any await. The shared legacy partial name remains a refusal boundary and is never written or removed. A competing same-output invocation loses create-only hard-link publication with AlreadyExists, then removes its own staging file and empty directory. Distinct owners never scan or clean each other's directories. Unix 0700 is applied at creation; no Windows ACL privacy claim is made.

Publication awaits the actual Tokio write through flush. Post-publication cleanup failures explicitly report that the completed output is already visible and retain their causes. Drop cleanup is nonrecursive. Internal failed batches abort and drain their tasks before collecting cleanup failures. Deliberate same-user mutation of internal owned staging entries and ancestor replacement are outside this contract. This is an appropriate ordinary concurrency boundary, not file-identity or broad filesystem atomicity protection.

All three changed files and the target parser were read in full. Test path observations use an owned test-only observer rather than a directory scan. The controlled authenticated HTTP/3 peer and independent response bytes remain meaningful. Original replacement failures are repaired by changing the ownership namespace; the new controls verify shared legacy and sibling file preservation under that contract. Nonrecursive obstruction and Windows deny-delete controls still preserve error-path evidence.

Windows runtime verification is necessary for the queued-write cancellation control: a Tokio blocking task retains its original file handle while Drop attempts both file and directory removal. Native Unix execution must check the creation-permission branch. A portable same-output two-owner publication test would directly cover the remaining normal-concurrency claim; current two-owner uniqueness/permission coverage is Unix-only. No reviewer tests, builds, source edits, Docker actions, or filesystem cleanup occurred.

Minor grouping improvements are recommended in PartialDownload::create and create_staging_directory. The paired JSON records exact hashes/ranges, source limits, retained original baseline, and required runtime controls. No overall audit completion is implied.

## Next

- [Findings](findings.md): verification and integration state.
