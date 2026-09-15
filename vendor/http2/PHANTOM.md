# Phantom patch notes

This directory is the complete crates.io source for `http2` version `0.5.20`.

- Crates.io archive SHA-256: `92d3114be2f413b2e491e686b93a28cda30c355cffc8d091a57f8be4b1342896`
- Upstream repository: <https://github.com/0x676e67/http2>
- Upstream crate license and readme remain in `LICENSE` and `README.md`.

## Why this patch exists

`http::HeaderMap` preserves duplicate values for a field name but cannot retain
the global interleaving of different field names. That prevents an HTTP/2
client from reproducing an observed browser order such as `x-a: a1`, `x-b: b1`,
`x-a: a2`.

The patch adds `http2::ext::OrderedHeaders`, consumes it when a client request
is converted into its initial HEADERS frame, and emits the supplied ordinary
fields after the configured pseudo-headers. Before encoding, a reconstructed
`HeaderMap` must equal the request's post-middleware semantic map. This checks
names, values, duplicate counts, and per-name value order while intentionally
ignoring global name order that `HeaderMap` cannot represent. A mismatch uses
the existing `UserError::MalformedHeaders` path. Requests without the extension
and all trailer frames retain the upstream `HeaderMap` iterator.

The ordinary `SendRequest` path clears request extensions before converting
the request into a frame. It now retains `OrderedHeaders` across that cleanup;
the real client-handshake regression proves the public sender preserves the
interleaved order on the wire, rather than testing only the lower conversion.

The real-client regression also exposed an upstream idle-close race: dropping
the final stream can queue an implicit reset while removing the last stream
reference. The connection now polls the open state before starting its idle
close so that queued reset is flushed. A duplex client/server regression proves
the peer observes the reset before connection shutdown.

The production diff is intentionally limited to:

- `src/ext.rs`: owned public extension value and semantic agreement check.
- `src/client.rs`: remove, validate, and attach the order to the initial frame.
- `src/frame/headers.rs`: select the exact iterator only when present.
- `src/proto/streams/streams.rs`: retain the ordered extension across request
  extension cleanup.

The patch also changes `src/client.rs` to preserve a final queued reset, adds
the required real-connection regressions in `src/client/tests.rs`, and enables
Tokio's test-only `time` feature in both Cargo manifests.

The canonical source and test delta is stored in
`patches/ordered-headers.patch`. It is deliberately separate from the complete
vendor snapshot so a candidate release can be tested without reconstructing
the changes by hand.

## Refreshing the vendor copy

The workspace's active `[patch.crates-io]` entry prevents `cargo fetch` from
fetching the registry source. Download the exact crates.io archive directly so
the patch can remain enabled throughout the refresh.

1. Choose the reviewed version and its checksum from the crates.io index. For
   the currently vendored release, create an isolated staging directory and
   verify the archive with the platform's standard SHA-256 command:

   ```sh
   http2_version=0.5.20
   expected_checksum=92d3114be2f413b2e491e686b93a28cda30c355cffc8d091a57f8be4b1342896
   refresh_dir=$(mktemp -d "${TMPDIR:-/tmp}/phantom-http2.XXXXXX")
   archive="$refresh_dir/http2-$http2_version.crate"

   curl --fail --location \
     --output "$archive" \
     "https://crates.io/api/v1/crates/http2/$http2_version/download"

   if command -v shasum >/dev/null 2>&1; then
     actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
   else
     actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
   fi
   test "$actual_checksum" = "$expected_checksum"

   tar -xzf "$archive" -C "$refresh_dir"
   candidate="$refresh_dir/http2-$http2_version"
   ```

   `shasum` covers macOS and `sha256sum` covers typical Linux environments.
   Stop if neither command exists or if the checksum comparison fails.

2. Check the canonical patch against the pristine candidate, then apply it in
   the staging directory:

   ```sh
   git -C "$candidate" apply --check \
     "$PWD/vendor/http2/patches/ordered-headers.patch"
   git -C "$candidate" apply \
     "$PWD/vendor/http2/patches/ordered-headers.patch"
   ```

   A failed dry application is expected evidence that the upstream source
   changed around the patch. Review and regenerate the patch; do not apply it
   with rejected hunks or fuzz.

3. Copy the patched candidate to `vendor/http2.next`, and update the version
   and checksum in this file. Keep the current directory as a rollback copy
   while testing:

   ```sh
   test ! -e vendor/http2.next
   cp -R "$candidate" vendor/http2.next
   cp vendor/http2/PHANTOM.md vendor/http2.next/PHANTOM.md
   mkdir -p vendor/http2.next/patches
   cp vendor/http2/patches/ordered-headers.patch vendor/http2.next/patches/
   mv vendor/http2 "$refresh_dir/http2.previous"
   mv vendor/http2.next vendor/http2
   ```

4. Refresh the workspace lock entry while the path patch is active, prove the
   selected source, and run the required checks:

   ```sh
   cargo update -p http2 --precise "$http2_version"
   cargo tree -i http2 --locked
   ```

   `cargo tree` must show `http2 v$http2_version` at `vendor/http2`, below
   `wreq-proto`. Confirm that the `Cargo.lock` diff changes only the `http2`
   package entry before committing. If any check fails, move the failed
   `vendor/http2` directory aside, move `$refresh_dir/http2.previous` back to
   `vendor/http2`, and restore the reviewed lockfile change before retrying.

## Required checks

```sh
cargo fmt --manifest-path vendor/http2/Cargo.toml --all --check
cargo check --manifest-path vendor/http2/Cargo.toml --all-targets --all-features
cargo test --manifest-path vendor/http2/Cargo.toml --all-features client::tests
cargo test --manifest-path vendor/http2/Cargo.toml --all-features --lib -- --skip hpack::test::fixture
cargo tree -i http2 --locked
cargo +1.85.0 check --workspace --all-targets --locked
```

The published crate excludes `fixtures/**`, although its generated fixture test
functions remain in `src/hpack/test`. Running the unfiltered library suite from
the crates.io source therefore reports those missing files as failures. The
second test command above runs every packaged non-fixture unit test.
