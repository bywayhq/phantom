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

The production diff is intentionally limited to:

- `src/ext.rs`: owned public extension value and semantic agreement check.
- `src/client.rs`: remove, validate, and attach the order to the initial frame.
- `src/frame/headers.rs`: select the exact iterator only when present.

Patch-specific regression tests live in `src/client/tests.rs`.

## Refreshing the vendor copy

1. Update the exact `http2` version in the workspace dependency graph and run
   `cargo fetch --locked`.
2. Locate the fetched source with
   `find /path/to/cargo/registry/src -type d -name 'http2-VERSION'`.
3. Copy that complete directory to a temporary `vendor/http2.next` directory.
4. Verify the downloaded `.crate` archive SHA-256 against its `Cargo.lock`
   checksum, then diff `http2.next` against this directory.
5. Reapply only the three production changes listed above and the focused
   tests. Replace this directory after review.
6. Run `cargo update -p http2`, confirm `cargo tree -i http2` resolves the local
   path, and execute the checks below.

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
