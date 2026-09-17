#!/usr/bin/env bash
set -euo pipefail

check_http2_patch_replay() {
  local staging archive candidate actual_checksum patch
  local listed_patches stored_patches
  staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-http2-replay.XXXXXX")
  trap 'rm -rf "$staging"' RETURN
  archive="$staging/http2-0.5.20.crate"
  curl --fail --location --silent --show-error --retry 3 \
    --output "$archive" \
    https://static.crates.io/crates/http2/http2-0.5.20.crate
  if command -v shasum >/dev/null 2>&1; then
    actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
  else
    actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
  fi
  [[ "$actual_checksum" == 92d3114be2f413b2e491e686b93a28cda30c355cffc8d091a57f8be4b1342896 ]]
  tar -xzf "$archive" -C "$staging"
  candidate="$staging/http2-0.5.20"
  listed_patches=$(LC_ALL=C sort vendor/http2/patches/series)
  stored_patches=$(find vendor/http2/patches -maxdepth 1 -type f \
    -name '*.patch' -exec basename {} \; | LC_ALL=C sort)
  if [[ "$listed_patches" != "$stored_patches" ]]; then
    echo "HTTP/2 patch series does not list every canonical patch exactly once" >&2
    return 1
  fi
  while IFS= read -r patch; do
    if [[ -z "$patch" ]]; then
      echo "HTTP/2 patch series contains an empty entry" >&2
      return 1
    fi
    if [[ "$patch" == ordered-headers.patch ]]; then
      git -C "$candidate" apply --check --unidiff-zero \
        "$PWD/vendor/http2/patches/$patch"
      git -C "$candidate" apply --unidiff-zero \
        "$PWD/vendor/http2/patches/$patch"
    else
      git -C "$candidate" apply --check "$PWD/vendor/http2/patches/$patch"
      git -C "$candidate" apply "$PWD/vendor/http2/patches/$patch"
    fi
  done < vendor/http2/patches/series
  diff -qr --exclude=PHANTOM.md --exclude=patches --exclude=target \
    "$candidate" vendor/http2
}

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
  local listed_patches stored_patches
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
  listed_patches=$(LC_ALL=C sort vendor/h3/patches/series)
  stored_patches=$(find vendor/h3/patches -maxdepth 1 -type f \
    -name '*.patch' -exec basename {} \; | LC_ALL=C sort)
  if [[ "$listed_patches" != "$stored_patches" ]]; then
    echo "H3 patch series does not list every canonical patch exactly once" >&2
    return 1
  fi
  while IFS= read -r patch; do
    if [[ -z "$patch" ]]; then
      echo "H3 patch series contains an empty entry" >&2
      return 1
    fi
    if [[ "$patch" == ordered-response-headers.patch ]]; then
      git -C "$candidate" apply --check --unidiff-zero \
        "$PWD/vendor/h3/patches/$patch"
      git -C "$candidate" apply --unidiff-zero \
        "$PWD/vendor/h3/patches/$patch"
    else
      git -C "$candidate" apply --check "$PWD/vendor/h3/patches/$patch"
      git -C "$candidate" apply "$PWD/vendor/h3/patches/$patch"
    fi
  done < vendor/h3/patches/series
  diff -qr --exclude=.cargo-ok --exclude=Cargo.lock --exclude=PHANTOM.md \
    --exclude=patches --exclude=target "$candidate" vendor/h3
}

check_tungstenite_patch_replay() {
  local staging archive candidate actual_checksum
  staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-tungstenite-replay.XXXXXX")
  trap 'rm -rf "$staging"' RETURN
  archive="$staging/tungstenite-0.30.0.crate"
  curl --fail --location --silent --show-error --retry 3 \
    --output "$archive" \
    https://static.crates.io/crates/tungstenite/tungstenite-0.30.0.crate
  if command -v shasum >/dev/null 2>&1; then
    actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
  else
    actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
  fi
  [[ "$actual_checksum" == e48ac77174b19c110a50ab2128b24215ac9cb40e0e12e093fb602d175c569d22 ]]
  tar -xzf "$archive" -C "$staging"
  candidate="$staging/tungstenite-0.30.0"
  listed_patches=$(LC_ALL=C sort vendor/tungstenite/patches/series)
  stored_patches=$(find vendor/tungstenite/patches -maxdepth 1 -type f \
    -name '*.patch' -exec basename {} \; | LC_ALL=C sort)
  if [[ "$listed_patches" != "$stored_patches" ]]; then
    echo "tungstenite patch series does not list every canonical patch exactly once" >&2
    return 1
  fi
  while IFS= read -r patch; do
    if [[ -z "$patch" ]]; then
      echo "tungstenite patch series contains an empty entry" >&2
      return 1
    fi
    git -C "$candidate" apply --check "$PWD/vendor/tungstenite/patches/$patch"
    git -C "$candidate" apply "$PWD/vendor/tungstenite/patches/$patch"
  done < vendor/tungstenite/patches/series
  diff -qr --exclude=.cargo-ok --exclude=Cargo.lock --exclude=PHANTOM.md \
    --exclude=patches --exclude=target \
    "$candidate" vendor/tungstenite
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
      "${btls_features[@]}" --locked ssl::test::key_update
    cargo test --manifest-path vendor/btls/Cargo.toml \
      "${btls_features[@]}" --locked ssl::test::ech
    cargo test --manifest-path vendor/btls/Cargo.toml \
      "${btls_features[@]}" --locked scoped_client_session
    cargo test --manifest-path vendor/btls/Cargo.toml \
      "${btls_features[@]}" --locked record_size_limit
    cargo test --manifest-path vendor/btls/Cargo.toml \
      "${btls_features[@]}" --locked delegated_credentials
    cargo test --manifest-path vendor/btls/Cargo.toml \
      "${btls_features[@]}" --locked \
      aead::tests::shared_generic_context_seals_and_opens_concurrently
    ;;
  http2)
    check_http2_patch_replay
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
  tungstenite)
    check_tungstenite_patch_replay
    cargo clippy --manifest-path vendor/tungstenite/Cargo.toml \
      --lib --no-default-features --locked -- -D warnings
    cargo test --manifest-path vendor/tungstenite/Cargo.toml \
      --lib --no-default-features --locked
    cargo clippy --manifest-path vendor/tungstenite/Cargo.toml \
      --lib --no-default-features --features deflate --locked -- -D warnings
    cargo test --manifest-path vendor/tungstenite/Cargo.toml \
      --lib --no-default-features --features deflate --locked
    cargo test --manifest-path vendor/tungstenite/Cargo.toml \
      --lib --all-features --locked
    ;;
  *)
    echo "usage: $0 {btls|http2|quinn-proto|h3|tungstenite}" >&2
    exit 2
    ;;
esac
