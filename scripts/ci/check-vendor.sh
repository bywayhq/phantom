#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  btls)
    case "$(uname -s)" in
      Darwin|MINGW*|MSYS*|CYGWIN*) btls_features=(--features default) ;;
      *) btls_features=(--features prefix-symbols) ;;
    esac
    cargo fmt --manifest-path vendor/btls/Cargo.toml --all --check
    cargo clippy --manifest-path vendor/btls/Cargo.toml \
      --all-targets "${btls_features[@]}" --locked -- -D warnings
    cargo test --manifest-path vendor/btls/Cargo.toml \
      "${btls_features[@]}" --locked ssl::test::alps
    cargo test --manifest-path vendor/btls/Cargo.toml \
      "${btls_features[@]}" --locked ssl::test::ech
    cargo test --manifest-path vendor/btls/Cargo.toml \
      "${btls_features[@]}" --locked record_size_limit
    cargo test --manifest-path vendor/btls/Cargo.toml \
      "${btls_features[@]}" --locked delegated_credentials
    ;;
  http2)
    cargo fmt --manifest-path vendor/http2/Cargo.toml --all --check
    cargo check --manifest-path vendor/http2/Cargo.toml \
      --all-targets --all-features --locked
    cargo test --manifest-path vendor/http2/Cargo.toml \
      --all-features --locked client::tests
    cargo test --manifest-path vendor/http2/Cargo.toml \
      --all-features --locked --lib -- --skip hpack::test::fixture
    ;;
  quinn-proto)
    rustfmt --check --edition 2021 vendor/quinn-proto/src/tests/key_update.rs
    cargo clippy --manifest-path vendor/quinn-proto/Cargo.toml \
      --all-targets --locked -- -D warnings
    cargo check --manifest-path vendor/quinn-proto/Cargo.toml \
      --no-default-features --locked
    cargo test --manifest-path vendor/quinn-proto/Cargo.toml \
      --locked tests::key_update
    ;;
  h3)
    cargo fmt --manifest-path vendor/h3/Cargo.toml --all --check
    cargo clippy --manifest-path vendor/h3/Cargo.toml -p h3 \
      --lib --all-features --locked -- -D warnings
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 \
      --locked client::builder::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 \
      --locked proto::frame::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 --locked qpack::
    cargo check --manifest-path vendor/h3/Cargo.toml -p h3-quinn \
      --all-features --locked
    ;;
  *)
    echo "usage: $0 {btls|http2|quinn-proto|h3}" >&2
    exit 2
    ;;
esac
