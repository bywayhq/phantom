# A46 cookie diagnostic production review

Approved `0dd8ce24c920dcfa7298dedf16a929637a1d634f` and trailing patch cleanup `ddd8cf8989ebc481ba821a184d09906abf7a78aa`. No actionable source findings.

The encoder indexes and writes every split cookie crumb using the existing profile policy before applying the original value's diagnostic sensitivity to the retained slot. Both named and nameless split values reach this path. Inserted slots use their direct VecDeque offset. A reused dynamic HPACK index subtracts 62, matching both `find` and `index_occupied`; static, name-only, oversized and non-indexed forms do not mark a slot. No intervening table mutation occurs during `encode_header`.

Cached marking changes only the HeaderValue sensitivity flag. Table hashes depend on the name; value matching uses HeaderValue equality, which the resolved http 1.5.0 implementation defines using inner bytes only. Table lengths, eviction accounting, subsequent wire representations and incoming sensitivity remain unchanged. Insertions are marked after the assertions and wire write, so the diagnostic flag cannot change the selected insertion representation.

The proxy-authorization FieldRule path retains its prior clear-for-wire, encode, then remark sequence. Its new helper additionally handles reuse of a previously unmarked entry. Nameless continuation values remain literal and do not create a retained entry. Existing FieldRule and default never-index controls remain present. The previously reviewed four cookie controls cover inserted and reused slots under IndexAll and NeverIndexShort, retain a real decoder across blocks, compare marked versus unmarked bytes, and assert actual named/nameless values and compact/pretty cache diagnostics. This is an encoder-cache redaction fix; it does not promise redaction of the decoder or all connection diagnostics.

The final 55-line canonical patch reconstructs both changed Rust files byte for byte against the exact regression parent in memory. All 23 series entries exist, are unique, and publish-identity remains last. This is incremental reconstruction, not a full upstream replay. The cleanup only removes final blank context from the patch; it changes no Rust bytes. Both signed commits have the required personal author/committer identities and conventional subjects. The hpack module is private; no crate public API changes.

The JSON records exact Git blob OIDs, SHA-256, physical line counts and partial read ranges. The earlier regression report retains the complete test-stage review; source scans are not promoted to complete reads. No Cargo or runtime tests were run by this reviewer. Parent-reported corrected Windows results remain separate runtime evidence.

Integration still owns HTTP/2 fork .11 identity and matching pins/lock documentation, changelog/ledger, complete canonical replay via `scripts/ci/check-vendor.sh http2`, and the exact final `scripts/dev/gate.sh --linux` output. No source disposition here waives those gates.

## Next

- [Findings](findings.md): verification and integration state.
