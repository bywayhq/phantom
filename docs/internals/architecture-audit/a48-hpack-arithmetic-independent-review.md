# A48 independent source review

Approved for source integration. No actionable findings were found in the focused lane at `9f62282e3519e99d5e51799047ed657b0145930c`, including test checkpoint `14110f945448eec36776e52496948ecbc4c6766b`. This report does not review the later composed root snapshot `a777` or its final gate.

## Threshold and callers

`Table::exceeds_limit` at `vendor/http2/src/hpack/table.rs:320–332` replaces two potentially overflowing products with a subtraction expression. Let `m = 4q + r`, where `0 <= r < 4`. The expression is `m - q - (r != 0)`, giving `3q`, `3q`, `3q + 1`, or `3q + 2`. Those are exactly `floor(3m/4)`. The first subtraction cannot underflow because `q <= m`; the second subtracts one only when `m >= 1`, when `m-q >= 1`. There is no intermediate multiplication or addition. The result stays within `0..m` for every `usize`, including zero and the maximum value. For any representable entry length `h`, `h > floor(3m/4)` is equivalent to the original mathematical inequality `4h > 3m`; equality remains eligible for indexing.

Both `index_field` (235–244) and `index_profiled` (272–290) call this helper. Half and Unlimited policies, static and dynamic match decisions, sensitivity, table insertion, eviction, and name selection remain unchanged. This is an exact proof of the changed threshold expression, not a claim that every unrelated arithmetic operation or allocation in the table has been proven safe for arbitrary synthetic sizes.

Wire and seeded SETTINGS enter the shared remote application path in `proto/settings.rs`. `frame/settings.rs` keeps header table settings as `u32`, retaining minimum and final values without a new cap. `apply_remote_settings` sends minimum/final changes through `Codec::set_send_header_table_size`, `FramedWrite::set_header_table_size`, and `Encoder::update_max_size`. At the next block, `encode_size_updates` resizes the table before indexing fields and emits the same ordered size updates. The patch introduces no eager allocation based on the advertised large table setting; existing storage grows for actual entries.

Only primitive arithmetic, comparison and `usize::from(bool)` were added. The pinned Rust 1.68 source declares that conversion stable since 1.28: [core numeric conversions](https://raw.githubusercontent.com/rust-lang/rust/1.68.0/library/core/src/convert/num.rs), lines 64–83. The new production expression is compatible with the vendor manifest's declared Rust 1.68 language/API floor. No compiler was run for this review.

## Regression controls

The two large-setting tests use `Encoder::update_max_size` then the real encoder. They independently require the exact HPACK size update bytes, literal incremental indexing byte `0x40`, one 36-byte retained entry, and indexed reuse byte `0xbe` on the second block. The release regression cannot pass by merely avoiding a panic: wrapped arithmetic emits byte zero and fails the expected bytes. On 64-bit hosts these legal `u32` settings do not overflow the old expression, so the independently run i686 row is the important reproduction.

The third test covers twelve cases: below, equal and above the fixed thresholds for table sizes 128, 129, 130 and 131. The thresholds are explicit 96, 96, 97 and 98, independent of the production expression. Entry accounting uses a three-byte name plus RFC 7541's 32-byte overhead; values remain raw because `~` grows under Huffman coding. Each case checks complete bytes, retained table entry count/size, and second-block reuse or literal repetition. Existing test helper unwraps operate only on constant valid names and printable values. No network fixture or zero-observation control is involved in these unit tests.

## Canonical patch and scope

Both single-hunk canonical patches were applied in memory to their exact parent Git blobs using exact, unique context. The reconstructed encoder and table bytes equal their respective committed targets. Encoder SHA-256 is `a65d6742af609a2ece82746b6cc46df48917a066ffd34608c57608a64a564ba6`; table SHA-256 is `c3f675ee654d4c16cf7177e8c381a05cab27fccf03fd0f9611b9a50e25d2fab6`. This proves these incremental canonical hunks, not a full upstream archive replay.

The series has 23 unique entries, every named patch exists, and `publish-identity.patch` remains last. The two commits touch only the recorded encoder/table Rust deltas, corresponding patches and series. Both signatures are `G`; author and committer are Arya Alikhani <AryaAlikhani@icloud.com>, and subjects follow the repository policy. The lane is clean. Root owns publish identity/pin/lock refresh, explanatory vendor notes, central changelog and composed verification.

## Runtime evidence and remaining checks

The integration owner ran the i686 tests. I read the result portions of its four retained logs: baseline debug has one pass and two multiplication-overflow failures; baseline release runs the boundary case and fails because the literal byte is zero rather than 64; corrected debug and release each pass all three tests. I did not execute Cargo, tests, compilation, source mutation, or vendor replay.

The owner must still finish the exact composed snapshot's full gate, source identity/pin/lock checks and `scripts/ci/check-vendor.sh http2` (with the documented Windows Git settings). The standard gate covers formatting without `--all`, workspace Clippy/tests/doctests/rustdoc, MSRV, optional features, nightly recursion, script checks and Linux paths. Standalone vendor checks must also respect the no-`--all` rule; use the scoped package form. No existing full source-read coverage was promoted by this report. The JSON records the exact focused Git blob identities and full versus partial ranges; encoder/header/codec/settings-frame/ext/vendor-note coverage remains partial outside the listed ranges.

## Next

- [Findings](findings.md): verification and integration state.
