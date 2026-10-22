# Independent Chrome 155 Linux peer review

**Result: suitable evidence for a bounded peer-derived TLS/H2/navigation port.**
The demonstrated missing encoder choice is a full-table insertion limit. This
is not a browser capture, performance result, or proof of whole-client parity.

Reviewed Phantom `fa461b35a3fd6671321a7c22d307d81cc2f9cbc4` against
httpcloak v1.7.3, commit `3a426f92c44af452a249b388a16ae3720097e50a`,
including the resolved sardanioss/net v1.2.12 HPACK implementation. A normal
public name such as `chrome-155-linux` is appropriate; keep upstream identity
in provenance rather than adding a library prefix to the selector.

## Independent observations

Read all six raw ClientHellos and all 33 request HEADERS blocks directly.
Decoded HPACK with the separately installed, cached hpack 4.1.0 decoder, not
the capture driver's prediction flags. Parsed each representation from its
literal prefix while maintaining the connection's dynamic table.

All three boundary connections agree:

| Field | Representation | Observable result |
| --- | --- | --- |
| Cookie crumbs, first use | Incremental, static name 32 | Two table entries |
| Cookie crumbs, second use | Indexed 63, then 62 | Same two values |
| Entry size 3,073 bytes | Incremental | Present in the table |
| Entry size 4,096 bytes | Incremental | Fits the complete table |
| Entry size 4,097 bytes | Without indexing | Marker survives |
| Marker after oversized field | Indexed 62 | Prior table state reused |

Entry sizes include the HPACK 32-byte overhead and name/value lengths.
All request HEADERS carry exclusive dependency 0 and weight 256. Initial
SETTINGS are ordered 1/2/4/6 with values 65536/0/6291456/262144;
connection WINDOW_UPDATE is 15663105. The retained first/reused navigation
blocks and cookie order provide independent comparison inputs.

Every literal ClientHello has the pinned cipher sequence, GREASE plus
ML-DSA signatures, ALPS at codepoint 17613 for h2, Brotli certificate
compression, and 28 fixed ordered trust-anchor IDs. ECH GREASE payloads
vary across 218/250/282 bytes. Existing profile fields express these choices,
the observed H2 settings/priorities, cookie splitting and navigation fields.
Successful emission by Phantom remains to be checked against these bytes.

## Narrow implementation consequence

In the pinned peer, `shouldIndex` rejects `field.Size() > maxSize` before
applying Chrome's indexing policy. Chrome's policy then permits ordinary
fields and `:authority`, excluding the other pseudo-headers.

Phantom's ThreeQuarters limit incorrectly rejects the observed 3,073- and
4,096-byte entries. Unlimited inserts the 4,097-byte field and clears prior
table state, also contradicting the observation. Add an explicit FullTable
choice: entries at or below the peer's current table limit may enter;
oversized entries use without-indexing and preserve the table. Keep the
existing policies unchanged for their current profiles. No wider HPACK
rewrite is justified by this experiment.

Before landing, compare Phantom first/reused navigation, cookie crumbs and
all three sizes against these independent blocks. Test a changed peer table
limit, zero capacity, exact boundary and marker survival; preserve existing
Chrome/Safari/Firefox behavior. Serialize and round-trip the new setting,
record any vendored change through its patch series, then run the applicable
full gate and independent review.

## Provenance and limits

Verified 150 per-run payload hashes, 65 sealed preparation hashes, 57 license
resolution hashes, all nine observation identity hashes and ten reviewed API
source hashes. The actual Go1.26.5 Linux/amd64, CGO-disabled binary is SHA-256
`1a6aa330a4f568bdb61ba9175d8584f5c0ae5494fc7bf57bf416cd549dcc8274`;
the capture driver is
`170db7c004718e10cb8d9bc2615461cc8fdfe3ef3e0f1c7814fc6b59da7aaadc`.
The six retained executions report zero failures. The binary lists 15 linked
modules; their exact versions/sums match the module inventory, and every
retained notice hash matches. Preserve httpcloak's MIT notice and the
relevant dependency notices. The HTTP fork's absent LICENSE is honestly
handled by its pinned BSD declaration, copyright reference and separately
labelled official Go BSD text; do not relabel that text as a bundled fork file.

The original handoff's prep-only language is historical; actual build and
observation receipts establish the later execution. Its earlier failures
remain preserved. No source edits, builds, capture reruns or network requests
were performed for this review.

Do not claim TCP/IP, HTTP/1, QUIC, resumption, uploads, resource contexts,
DNS or browser fidelity from these bodyless controlled H2 GETs. In particular,
the peer declares a 16,375-byte DATA cap that this experiment never exercises;
Phantom has no matching public profile field. That is an explicit unported,
unverified part of the broader peer preset, not an additional demonstrated
wire mismatch or a reason to expand this patch. Keep unsupported layers and
remaining comparisons visible in the profile's provenance.
