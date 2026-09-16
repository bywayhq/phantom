#!/usr/bin/env bash
set -euo pipefail

check_quinn_proto_patch_replay() {
  local staging archive candidate actual_checksum patch
  staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-quinn-proto-replay.XXXXXX")
  trap 'rm -rf "$staging"' RETURN
  archive="$staging/quinn-proto-0.11.18.crate"
  curl --fail --location --silent --show-error --retry 3 \
    --output "$archive" \
    https://static.crates.io/crates/quinn-proto/quinn-proto-0.11.18.crate
  if command -v shasum >/dev/null 2>&1; then
    actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
  else
    actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
  fi
  [[ "$actual_checksum" == a9746dbde176634f4f2f1faf2404e30a31b2bc1e9cafb5329c95d8177a18c9fc ]]
  tar -xzf "$archive" -C "$staging"
  candidate="$staging/quinn-proto-0.11.18"
  for patch in \
    vendor/quinn-proto/patches/fallible-key-updates.patch \
    vendor/quinn-proto/patches/fallible-initial-keys.patch \
    vendor/quinn-proto/patches/profiled-transport-parameters.patch
  do
    git -C "$candidate" apply --check "$PWD/$patch"
    git -C "$candidate" apply "$PWD/$patch"
  done
  diff -qr --exclude=.cargo-ok --exclude=PHANTOM.md --exclude=patches --exclude=target \
    "$candidate" vendor/quinn-proto
}

check_h3_patch_replay() {
  local staging archive candidate actual_checksum patch
  staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-h3-replay.XXXXXX")
  trap 'rm -rf "$staging"' RETURN
  archive="$staging/h3-1f3d5295833ad454343f25d55633fb6bee1027b2.tar.gz"
  curl --fail --location --silent --show-error --retry 3 \
    --output "$archive" \
    https://codeload.github.com/hyperium/h3/tar.gz/1f3d5295833ad454343f25d55633fb6bee1027b2
  if command -v shasum >/dev/null 2>&1; then
    actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
  else
    actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
  fi
  [[ "$actual_checksum" == a30747c0c9f35a57c03c17619e7231eb7f94a4629f3644228219280850d57183 ]]
  tar -xzf "$archive" -C "$staging"
  candidate="$staging/h3-1f3d5295833ad454343f25d55633fb6bee1027b2"
  for patch in \
    vendor/h3/patches/ordered-settings.patch \
    vendor/h3/patches/qpack-codec.patch \
    vendor/h3/patches/qpack-critical-streams.patch \
    vendor/h3/patches/qpack-dynamic-client.patch \
    vendor/h3/patches/cancel-safe-recv.patch \
    vendor/h3/patches/ordered-request-headers.patch \
    vendor/h3/patches/qpack-request-encoder.patch
  do
    git -C "$candidate" apply --check "$PWD/$patch"
    git -C "$candidate" apply "$PWD/$patch"
  done
  diff -qr --exclude=.cargo-ok --exclude=Cargo.lock --exclude=PHANTOM.md \
    --exclude=patches --exclude=target "$candidate" vendor/h3
}

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
    check_quinn_proto_patch_replay
    rustfmt --check --edition 2021 vendor/quinn-proto/src/tests/initial_keys.rs
    rustfmt --check --edition 2021 vendor/quinn-proto/src/tests/key_update.rs
    cargo clippy --manifest-path vendor/quinn-proto/Cargo.toml \
      --all-targets --locked -- -D warnings
    cargo check --manifest-path vendor/quinn-proto/Cargo.toml \
      --no-default-features --locked
    cargo test --manifest-path vendor/quinn-proto/Cargo.toml \
      --locked tests::key_update
    cargo test --manifest-path vendor/quinn-proto/Cargo.toml \
      --locked tests::initial_keys
    cargo test --manifest-path vendor/quinn-proto/Cargo.toml \
      --locked datagram_frame_size
    ;;
  h3)
    check_h3_patch_replay
    cargo fmt --manifest-path vendor/h3/Cargo.toml --all --check
    cargo clippy --manifest-path vendor/h3/Cargo.toml \
      --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 \
      --locked client::builder::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 \
      --locked proto::frame::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 \
      --locked proto::headers::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 --locked qpack::
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 --locked qpack_
    cargo check --manifest-path vendor/h3/Cargo.toml -p h3-quinn \
      --all-features --locked
    cargo check --manifest-path vendor/h3/Cargo.toml -p h3-webtransport \
      --all-features --locked
    ;;
  *)
    echo "usage: $0 {btls|http2|quinn-proto|h3}" >&2
    exit 2
    ;;
esac
