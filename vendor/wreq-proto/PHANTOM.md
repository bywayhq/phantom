# Phantom vendor notes: wreq-proto

**Audience:** maintainers auditing or refreshing Phantom's HTTP/1 dependency.
This file records provenance, local behavior changes, the refresh procedure,
and focused checks. It is not integration documentation.

The files listed in `patches/series` are the canonical local changes, in
application order. Change those patches and replay them; do not make an
unrecorded edit to the vendored crate.

This directory is the complete crates.io source for `wreq-proto` version
`0.2.5`.

- Crates.io archive SHA-256:
  `a43942f024bb303f1042c9aa3c87fa1d9149f507c65db6e5220a11ccdb207387`
- Packaged upstream commit: `74aa79439c61b8f2d92395722614bdb440bbd729`
- Upstream repository: <https://github.com/0x676e67/wreq-proto>
- The upstream Apache-2.0 license remains in `LICENSE`.

## Publish identity

`publish-identity.patch` is always the last entry in `patches/series`. It
renames the package (`wreq-proto` becomes `phantom-wreq-proto` at
`0.2.5-phantom.7`), keeps the upstream library name so source, tests, and
examples are unchanged, and points the repository metadata at Phantom. It
removes the upstream documentation link, keeps Cargo's reserved archive files
out of the packaged crate, and records the upstream package, version, and
source archive under `[package.metadata.phantom]`. Its `http2` dependency is
`phantom-http2` from `../http2`. The standalone `Cargo.lock` is packaging
metadata outside the patches and follows that path. It changes no Rust source.

Phantom depends on this package only through the renamed package with an exact
version and a path, so the stock package cannot be selected in its place and no
root `[patch]` table is required. When refreshing, regenerate this patch after
the source patches. Increase the `-phantom.N` suffix whenever the fork's
content changes without an upstream version change, and update the exact pins
in the root `Cargo.toml` and in every renamed dependent.

## Why this patch exists

The stock chunked-body decoder bounds cumulative extension bytes but does not
bound the complete chunk-size line. An arbitrarily long sequence of leading
zeroes or linear whitespace is therefore consumed one byte at a time without a
deterministic per-line ceiling.

`Http1OptionsBuilder::max_chunk_size_line_bytes` adds an opt-in limit covering
every byte from the first size digit through the terminating LF, inclusive.
The counter resets for every chunk. Exceeding the limit produces an ordinary
body error distinguishable through
`Error::is_chunk_size_line_too_large`. Leaving the option unset preserves the
upstream behavior exactly, including the existing cumulative 16-KiB extension
limit.

The canonical source and regression-test delta is
`patches/chunk-size-line-limit.patch`; `patches/series` records its application
order. `PHANTOM.md` and `patches/` are packaging metadata and are not part of
the patch.

Phantom also needs request trailers to retain caller-supplied field-name
spelling, global ordering, and interleaved duplicates. The stock request-body
path reduces trailers to `HeaderMap`, which cannot represent that wire image.
`on_preserve_trailer` adds a request extension parallel to the existing ordered
header callback. It is consulted only when a declared chunked trailer block is
encoded and receives the terminal body `HeaderMap`, allowing a validated caller
to combine its declared spelling and cross-name order with values produced by a
streaming body. Callers remain responsible for validating trailer semantics and
multiplicity before the callback runs. The canonical delta is
`patches/ordered-request-trailers.patch`.

## Refreshing the vendor copy

Download the reviewed crates.io archive into an isolated directory and verify
its checksum before extraction:

```sh
wreq_proto_version=0.2.5
expected_checksum=a43942f024bb303f1042c9aa3c87fa1d9149f507c65db6e5220a11ccdb207387
refresh_dir=$(mktemp -d "${TMPDIR:-/tmp}/phantom-wreq-proto.XXXXXX")
archive="$refresh_dir/wreq-proto-$wreq_proto_version.crate"

curl --fail --location --output "$archive" \
  "https://static.crates.io/crates/wreq-proto/wreq-proto-$wreq_proto_version.crate"
if command -v shasum >/dev/null 2>&1; then
  actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
else
  actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
fi
test "$actual_checksum" = "$expected_checksum"
tar -xzf "$archive" -C "$refresh_dir"
candidate="$refresh_dir/wreq-proto-$wreq_proto_version"

# The published archive uses CRLF. Normalize only the patched Rust sources so
# the canonical patch remains narrow and deterministic.
for source in \
  src/error.rs \
  src/proto/http1.rs \
  src/conn/http1.rs \
    src/proto/http1/conn.rs \
    src/proto/http1/decode.rs \
    src/ext.rs \
    src/proto/http1/encode.rs \
    src/proto/http1/role.rs; do
  normalized="$refresh_dir/$(basename "$source").lf"
  tr -d '\r' < "$candidate/$source" > "$normalized"
  mv "$normalized" "$candidate/$source"
done
```

Dry-apply and apply every canonical patch without fuzz, then compare the
resulting tree with this directory while excluding `.cargo-ok`, `PHANTOM.md`,
`patches`, and build output:

```sh
while IFS= read -r patch; do
  git -C "$candidate" apply --check "$PWD/vendor/wreq-proto/patches/$patch"
  git -C "$candidate" apply "$PWD/vendor/wreq-proto/patches/$patch"
done < "$PWD/vendor/wreq-proto/patches/series"

scripts/ci/check-vendor.sh wreq-proto
```

Refresh the root lockfile only after the renamed path dependency selects the
reviewed candidate. The `phantom-wreq-proto` lock entry has no registry source
or checksum.

## Focused checks

The clippy allowances below cover warnings in the unmodified 0.2.5 source that
were added after its release; all other warnings remain denied.

```sh
cargo fmt --manifest-path vendor/wreq-proto/Cargo.toml --all --check
cargo clippy --manifest-path vendor/wreq-proto/Cargo.toml \
  --all-targets --all-features --locked -- \
  -D warnings \
  -A clippy::question_mark \
  -A clippy::result_large_err \
  -A clippy::useless_borrows_in_formatting
cargo test --manifest-path vendor/wreq-proto/Cargo.toml \
  --lib --all-features --locked
```
