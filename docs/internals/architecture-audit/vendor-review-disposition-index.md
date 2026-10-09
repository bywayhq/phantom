# Vendor review disposition index

Initial reconciliation checkpoint: `779f28ea9ebd13195a45edcdcd6ba9af7d612192`. Instruction follow-up checkpoint: `779f28ea9ebd13195a45edcdcd6ba9af7d612192` (includes explicitly recorded working-tree changes).

This report reconciles manual source reads with the frozen vendor inventory. It does not certify upstream implementations, cryptographic algorithms, canonical replay, compilation, or runtime behavior.

## Import disposition

Of the original 114 vendor-boundary rows, 45 have complete source coverage, 2 have partial coverage, and 67 remain pending in this report. Other agents' reports must be imported independently.

The JSON gives an exact path, byte hash, reviewed ranges, basis revision, and disposition for every accepted record. Import those records without rewriting the historical checkpoint inventory. Add the following six missing canonical paths to a current inventory:

- `vendor/quinn-proto/patches/provider-startup-errors.patch`: see JSON lines; full source read at recorded hash.
- `vendor/quinn-proto/patches/ack-frequency-receive-format.patch`: see JSON lines; full source read at recorded hash.
- `vendor/h3/patches/receive-bounds.patch`: see JSON lines; full source read at recorded hash.
- `vendor/h3/patches/frame-payload-length.patch`: see JSON lines; full source read at recorded hash.
- `vendor/h3/patches/peer-field-section-tests.patch`: see JSON lines; full source read at recorded hash.
- `vendor/h3/patches/test-sockets.patch`: see JSON lines; full source read at recorded hash.

Five nested H3 package/example manifests also need current-inventory entries. They were fully read and compared with current .11 identities and .4 Quinn pins:

- `vendor/h3/h3/Cargo.toml`
- `vendor/h3/h3-quinn/Cargo.toml`
- `vendor/h3/h3-datagram/Cargo.toml`
- `vendor/h3/h3-webtransport/Cargo.toml`
- `vendor/h3/examples/Cargo.toml`

## Historical evidence

All 94 historical records retain their original evidence. Repository source hashes match their stated Git revision, either byte-for-byte or by explicit CRLF working-tree rendering. Native artifact hashes still match retained files. Neither native artifact presence nor a historical Cargo Git wrapper proves selection in a new build.

Unchanged canonical Quinn/proto source patches and the original H3 runtime patches retain their prior complete reads. The dynamic-client patch (1â€“3020) and live-request-runtime patch (1â€“2141) are complete at their original unchanged hashes. Earlier prose paragraphs describing remaining ranges are historical checkpoints; later reads supersede them only at matching bytes.

Changed publish identities and current series/PHANTOM notes were reread. Current receive-bounds is 667 lines rather than the historical 126-line test-only stage. Current frame-payload-length, peer-field-section-tests, and test-sockets patches were read in full. Authored repairs provide source coverage, not an independent approval of those same repairs.

## Selected contracts and boundaries

Structured root and standalone lock inspections select renamed Quinn/proto .4, H3/adapter/datagram .11, local TLS wrapper/adapter .5, and btls-sys Git f478ea16a4b2f6ebbd221ce7cafdec10a32028eb. No stock Quinn/proto/H3 duplicate was selected in those inspected fields. Root/H3 Tokio is 1.53.1; Quinn standalone Tokio is 1.52.3. This is field inspection, not executed cargo tree or a full lockfile source read.

The actual selected local TLS wrapper was checked for X509 context guards, CString SNI, live certificate-chain borrows, verification parameters, explicit host/IP lengths, and native status conversion. Exact source slices are recorded. The historical Cargo Git SSL wrapper is a comparison source, not the selected local wrapper.

Native review retains exact callback ABI/storage, context/session reference ownership, ex-data failure cleanup, copied ALPN/transport parameters, QUIC input levels/lengths, HKDF/AEAD return and output contracts, early-data reset guards, and authenticated ECH retry borrows. These are bounded ownership/API checks, not proofs of complete native state machines or cryptographic primitives.

## Instruction findings

Root A42 changes resolve the three originally reported instruction issues in source: renamed Quinn-proto refresh selection, local TLS wrapper/adapter versus btls-sys Git provenance, and package-scoped formatting without --all. The current guide text and all three changed script selectors agree with parsed exact package names. Independent command execution remains root-owned.

One adjacent minor refresh instruction remains reported: vendor/http2/PHANTOM.md:904 restricts the refreshed lock diff to the package entry alone, although a changed fork version also updates dependent references. Require inspection of both identity and dependent references.

## Remaining work

- Partial upstream source slices remain partial even when patches are fully read.
- Original report earlier Remaining paragraphs are historical checkpoints; final JSON complete ranges and later narrative supersede those only at recorded bytes.
- Authored A13/A28/A34/A36/A38/A40 repairs are coverage, not independent reviewer approval.
- Other vendor domains outside this accumulated report remain pending here; do not infer they are unread by every agent.
- The old native artifact files are hash-verified retained files; not proof current build/platform selected that exact artifact.
- Full btls wrapper/native patch series, full certificate/hostname/path algorithms, primitive crypto/assembly/platform states, all feature/runtime paths and fresh browser evidence remain outside this report.
- Canonical replay/check-vendor, compiler, sanitizer and complete integration gates are separate root-owned evidence.

This pass performed no builds, Cargo execution, canonical replay, network probes, or repository source edits. The integration owner supplies final package checks, cross-platform runs, full gate results, and independent review evidence.

## Next

- [Coverage](coverage.md): current review and verification state.
