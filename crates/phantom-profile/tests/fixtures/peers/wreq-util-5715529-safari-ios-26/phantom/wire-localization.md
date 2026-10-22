# Safari iOS26 public-client comparison localization

Offline review of existing captures, source `be7d7745e261569870869fd3f25ada31cf52a05c`.
No builds, servers or new captures ran. Original comparison booleans remain intact.
The detailed byte proofs and input hashes are in `wire-localization.json`.

## Result

No additional profile defect is established in these six requests. This is a
bounded peer-port comparison, not full-wire equivalence or Safari browser fidelity.

For each of the three pairs, the first HPACK block differs at exactly zero-based
byte offsets18,19,20,21. All four bytes fall inside the first authority's Huffman
value, span[4,22). Independently decoding those bytes gives:

| Run | Phantom authority port | Retained peer authority port |
| --- | --- | --- |
| 1 | 56452 | 42055 |
| 2 | 56455 | 43105 |
| 3 | 56458 | 36621 |

The authority remains `server.phantom.test`. Encoding prefix, representation,
length, all bytes preceding/following that value and the entire second HPACK block
are byte-identical for every pair. This explains the raw-block false results using
actual encoded bytes, not only decoded header equality. Stateful second blocks
also retain exactly the same dynamic-table index references.

All server frames, including their payloads and per-direction order, are identical.
All client frame types, flags, stream IDs and payloads match after replacing only
that authority value and comparing the SETTINGS ACK separately. The peer's ACK
follows first HEADERS in runs1/3, while Phantom's precedes WINDOW_UPDATE; run2 has
identical client order. No extra/missing frame or payload change is hidden.
Cross-direction ordering further differs by when the server ACK is observed
relative to first HEADERS. These order differences remain recorded; the three peer
runs themselves demonstrate variable ACK placement. Neither implementation emitted
an extra GOAWAY in the retained client streams.

The localization checked raw stream parsing against captured HPACK blocks, decoded
the authority's exact Huffman slice, checked complete prefix/suffix equality, and
compared all non-header payload bytes. All six reported checks passed per run.
The first analysis invocation used the wrong Python type for the parser's trailing
byte count; it failed before writing output and was corrected to integer zero.

## Minimal retained capsule

Add a `phantom-comparison` child beside the existing iOS peer capsule, following
the existing macOS retention structure. Include the small consumer source,
Cargo.toml/lock, build command/log/exit and rustc identity, execution/environment
receipts, exact capture/negative-control drivers and their hashes, all three raw
runs and their unchanged comparison JSON, this localization and a SHA-256 manifest.
Keep the current peer capsule by reference rather than duplicating upstream source,
licenses or the peer build. Public certificates are useful; no private keys,
executables, target directories or new benchmark harness belong in the capsule.
Keep preparation failures/driver corrections and both before/after offline controls
as provenance, without using stale preparation flags as current execution status.