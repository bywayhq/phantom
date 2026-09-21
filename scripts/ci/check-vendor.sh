#!/usr/bin/env bash
set -euo pipefail

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

# Replay every patch in <vendor-dir>/patches/series onto <candidate>, after
# proving that the series lists each stored patch exactly once.
apply_series() {
  local candidate=$1 vendor_dir=$2 patch listed_patches stored_patches
  listed_patches=$(LC_ALL=C sort "$vendor_dir/patches/series")
  stored_patches=$(find "$vendor_dir/patches" -maxdepth 1 -type f \
    -name '*.patch' -exec basename {} \; | LC_ALL=C sort)
  if [[ "$listed_patches" != "$stored_patches" ]]; then
    echo "$vendor_dir patch series does not list every canonical patch exactly once" >&2
    return 1
  fi
  while IFS= read -r patch; do
    if [[ -z "$patch" ]]; then
      echo "$vendor_dir patch series contains an empty entry" >&2
      return 1
    fi
    git -C "$candidate" apply --check "$PWD/$vendor_dir/patches/$patch"
    git -C "$candidate" apply "$PWD/$vendor_dir/patches/$patch"
  done < "$vendor_dir/patches/series"
}

# Replay a rename-only crates.io fork: download the checksummed archive, apply
# its series, and compare the result with the vendored directory.
check_crate_archive_replay() {
  local name=$1 version=$2 checksum=$3 staging archive candidate
  staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-$name-replay.XXXXXX")
  trap 'rm -rf "$staging"' RETURN
  archive="$staging/$name-$version.crate"
  curl --fail --location --silent --show-error --retry 3 \
    --output "$archive" \
    "https://static.crates.io/crates/$name/$name-$version.crate"
  [[ "$(sha256_of "$archive")" == "$checksum" ]]
  tar -xzf "$archive" -C "$staging"
  candidate="$staging/$name-$version"
  apply_series "$candidate" "vendor/$name"
  diff -qr --exclude=.cargo-ok --exclude=Cargo.lock --exclude=PHANTOM.md \
    --exclude=patches --exclude=target "$candidate" "vendor/$name"
}

check_tokio_btls_patch_replay() {
  local staging archive candidate
  local revision=50e72407ac1f89cea14003004429ecf579541b6f
  staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-tokio-btls-replay.XXXXXX")
  trap 'rm -rf "$staging"' RETURN
  archive="$staging/btls-$revision.tar.gz"
  curl --fail --location --silent --show-error --retry 3 \
    --output "$archive" \
    "https://codeload.github.com/0xARYA/btls/tar.gz/$revision"
  [[ "$(sha256_of "$archive")" == f5a243c26b334b816792bb0cae92a5d3e4e13d68f3055807315be7005d58aff0 ]]
  tar -xzf "$archive" -C "$staging"
  candidate="$staging/btls-$revision/tokio-btls"
  apply_series "$candidate" vendor/tokio-btls
  diff -qr --exclude=Cargo.lock --exclude=PHANTOM.md --exclude=patches \
    --exclude=target "$candidate" vendor/tokio-btls
}

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
  diff -qr --exclude=Cargo.lock --exclude=PHANTOM.md --exclude=patches \
    --exclude=target "$candidate" vendor/http2
}

check_wreq_proto_patch_replay() {
  local staging archive candidate actual_checksum patch source normalized
  local listed_patches stored_patches
  staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-wreq-proto-replay.XXXXXX")
  trap 'rm -rf "$staging"' RETURN
  archive="$staging/wreq-proto-0.2.5.crate"
  curl --fail --location --silent --show-error --retry 3 \
    --output "$archive" \
    https://static.crates.io/crates/wreq-proto/wreq-proto-0.2.5.crate
  if command -v shasum >/dev/null 2>&1; then
    actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
  else
    actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
  fi
  [[ "$actual_checksum" == a43942f024bb303f1042c9aa3c87fa1d9149f507c65db6e5220a11ccdb207387 ]]
  tar -xzf "$archive" -C "$staging"
  candidate="$staging/wreq-proto-0.2.5"
  # The published archive uses CRLF. Normalize the five patched Rust sources
  # before replay so the canonical patch stays reviewable and deterministic.
  for source in \
    src/error.rs \
    src/proto/http1.rs \
    src/conn/http1.rs \
    src/proto/http1/conn.rs \
    src/proto/http1/decode.rs \
    src/ext.rs \
    src/proto/http1/encode.rs \
    src/proto/http1/role.rs; do
    normalized="$staging/$(basename "$source").lf"
    tr -d '\r' < "$candidate/$source" > "$normalized"
    mv "$normalized" "$candidate/$source"
  done
  listed_patches=$(LC_ALL=C sort vendor/wreq-proto/patches/series)
  stored_patches=$(find vendor/wreq-proto/patches -maxdepth 1 -type f \
    -name '*.patch' -exec basename {} \; | LC_ALL=C sort)
  if [[ "$listed_patches" != "$stored_patches" ]]; then
    echo "wreq-proto patch series does not list every canonical patch exactly once" >&2
    return 1
  fi
  while IFS= read -r patch; do
    if [[ -z "$patch" ]]; then
      echo "wreq-proto patch series contains an empty entry" >&2
      return 1
    fi
    git -C "$candidate" apply --check "$PWD/vendor/wreq-proto/patches/$patch"
    git -C "$candidate" apply "$PWD/vendor/wreq-proto/patches/$patch"
  done < vendor/wreq-proto/patches/series
  diff -qr --exclude=.cargo-ok --exclude=Cargo.lock --exclude=NOTICE \
    --exclude=PHANTOM.md --exclude=patches --exclude=target \
    "$candidate" vendor/wreq-proto
}

check_quinn_proto_patch_replay() {
  local staging archive candidate actual_checksum
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
  apply_series "$candidate" vendor/quinn-proto
  diff -qr --exclude=.cargo-ok --exclude=Cargo.lock --exclude=PHANTOM.md \
    --exclude=patches --exclude=target "$candidate" vendor/quinn-proto
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
  quinn)
    check_crate_archive_replay quinn 0.11.12 \
      4051e23e9185c255a7e33ef59cdbca87a22d359052eecd22fc6b901fb37d9d11
    cargo check --manifest-path vendor/quinn/Cargo.toml \
      --all-targets --locked
    cargo check --manifest-path vendor/quinn/Cargo.toml \
      --no-default-features --features runtime-tokio --locked
    ;;
  tokio-tungstenite)
    check_crate_archive_replay tokio-tungstenite 0.30.0 \
      17a073bfed563fa236697a068031408a93cd9522e08abf9933ead3e73411bd71
    cargo check --manifest-path vendor/tokio-tungstenite/Cargo.toml \
      --no-default-features --locked
    cargo check --manifest-path vendor/tokio-tungstenite/Cargo.toml \
      --lib --locked
    ;;
  tokio-btls)
    check_tokio_btls_patch_replay
    case "$(uname -s)" in
      Darwin|MINGW*|MSYS*|CYGWIN*) tokio_btls_features=(--features default) ;;
      *) tokio_btls_features=(--features prefix-symbols) ;;
    esac
    cargo check --manifest-path vendor/tokio-btls/Cargo.toml \
      --all-targets "${tokio_btls_features[@]}" --locked
    ;;
  wreq-proto)
    check_wreq_proto_patch_replay
    cargo fmt --manifest-path vendor/wreq-proto/Cargo.toml --all --check
    cargo clippy --manifest-path vendor/wreq-proto/Cargo.toml \
      --all-targets --all-features --locked -- \
      -D warnings \
      -A clippy::question_mark \
      -A clippy::result_large_err \
      -A clippy::useless_borrows_in_formatting
    cargo test --manifest-path vendor/wreq-proto/Cargo.toml \
      --lib --all-features --locked
    ;;
  *)
    echo "usage: $0 {btls|h3|http2|quinn|quinn-proto|tokio-btls|tokio-tungstenite|tungstenite|wreq-proto}" >&2
    exit 2
    ;;
esac
