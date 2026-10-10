# Vendor source evidence reconciliation

This pass reconciles retained source identities and ranges. It does not add
new full source coverage, execute tests, or approve authored repairs.

The comparison revision is `ad8de5d2b50d76095fc2c0abdad8ddd71b886132`.
The original 230-record validator verified 207 records and rejected 23.
Of those 23, 22 now have recoverable exact identities and valid recorded
ranges. One historical range remains rejected. Repeated records are counted
as records here, not as separate inventory files.

## Recovered byte bases

| Historical record | Exact basis | Scope retained |
| --- | --- | --- |
| Quinn-proto PHANTOM | `01574f2e`, blob `497abf0800f6012910e9d93ecf4f8eeb3306ac91` | Full 296 lines |
| BTLS PHANTOM | `01574f2e`, blob `30d6259edea84b06ae1b13a14394152848441304` | Full 383 lines |
| Wreq-proto PHANTOM | `01574f2e`, blob `2d17e0901adf77a6b6db5e4f0fd059cd6a2d4980` | Partial and later full 141 lines |
| Vendor checker | `01574f2e`, blob `1b37be65d11c716bb0ac356de0f549f863e383fe` | Three recorded slices |
| Client session | `779f28e`, blob `23e54b73eee771a1f61bd28160a324c54215c7c3`, CRLF rendering | Existing partial slices |
| Five WebSocket caller files | Exact `779f28e` blobs rendered with CRLF | Existing partial slices |
| HPACK table | `bc27b126`, blob `1d48b23121e3d807b5dcd97d63c26047d1e0823f` | Existing partial slices |

The four instruction/checker files explicitly record dirty A42 working
changes. Their hashes later became committed bytes at `01574f2e`. Do not
attribute those changed bytes to the committed tree at `779f28e`.

The client-session record has an absent, malformed recorded OID. Its correct
OID and explicit CRLF basis are independently retained in continuation
`source_reads[17]`. The canonical Git SHA256 is `4778f01bb9c8eb2b43140ee77f037487ebf13617b9fa25d218243067e088707b`.
The recorded CRLF SHA256 is `eebb714aa7a23ddec8e33c534924cc9d51c2d4786ccd29a360f18ed54fb1b1e7`.
The valid earlier full 813-line read remains separate from these slices.

Five group-9 first-party hashes are exact CRLF renderings: compression,
handshake response, HTTP/1, HTTP/2 and HTTP/3 WebSocket callers. The compression
source has since changed. Its historical 457-line bytes remain recoverable.
The 1021-line HPACK table hash is also the A46 production handoff hash.
It is not the 1018-line table committed at `779f28e`.

## Reconstructed instruction states

Two HTTP/2 PHANTOM working hashes are absent from all reachable path history.
A size-window search of all retained Git objects also found neither state.
Both can nevertheless be reconstructed with exact hash agreement:

- `7f9ab0948b868ae9b1f0d9ead8953ab3640ef990c07e5df23ae907500075b209`,
  923 lines: `779f28e` bytes with only `--all` replaced by
  `--package phantom-http2` in the package formatter command.
- `ff111a26d625520572cdfa5ad6696936c1253ad658a1eefba3c00834c3dd12f4`,
  924 lines: that state with the exact later committed lock-diff wording.

The JSON retains both complete texts, derivations, computed object IDs,
original records, and input hashes. These are reconstructed historical
working bytes, not claimed committed trees or retained Git objects. The
recorded partial/full scopes stay unchanged.

The later `01574f2e` HTTP/2 instructions also fix the sensitive-field qualifier
and dependent-reference refresh rule. Those historical prose findings are
already resolved in source at that commit; current gate execution is separate.

## Rejected ranges

- H3 client connection: exact `d1bed578` bytes have 794 lines. The historical
  range `[690, 815]` exceeds EOF. Keep the entire affected record rejected.
  Do not clip the range or turn this into a full read. A separate valid
  historical record for the same hash has its own bounded ranges.
- Encrypted ClientHello native source: the retained exact hash has 1364 lines,
  but continuation `source_reads[20]` records `[1270, 1365]`. Keep that record
  rejected pending an explicit corrected or fresh source read.

## Additional validation scope

The original validator does not visit continuation `source_reads`. This pass
checked all 60 such records against their declared Git, CRLF or retained
external basis: 59 have valid exact identities and ranges; the native EOF
range above is the sole failure. Those records include existing full and
partial scopes. Identity validation does not establish new manual coverage.

The JSON gives all 23 original rejection mappings and all 60 supplemental
checks. It preserves the original metadata alongside the corrected basis.
No source, manifest, repository documentation or original report was changed.
No Cargo, Docker, replay, network probe or runtime verification was performed.

## Next

- Import only the proved historical identities, preserving byte basis and scope.
- Correct or reread the two rejected ranges before accepting their records.
- Keep current dependency selection, independent review and gates separate.
