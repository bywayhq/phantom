#!/usr/bin/env bash

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
dependency=${1:-}
candidate=${2:-}
checksum=${3:-}

die() {
  echo "probe-upstream-candidate: $*" >&2
  exit 1
}

fetch() {
  curl --fail --location --silent --show-error --retry 3 \
    --user-agent "phantom-upstream-freshness/1" "$1"
}

sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    die "neither shasum nor sha256sum is available"
  fi
}

replace_exact() {
  local file=$1 old=$2 new=$3 expected=$4
  local count
  count=$(grep -F -o "$old" "$file" | wc -l | tr -d ' ')
  [[ "$count" == "$expected" ]] \
    || die "expected $expected occurrences of '$old' in $file, found $count"
  sed -i.bak "s|$old|$new|g" "$file"
  rm "$file.bak"
}

workspace_gates() {
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test -p phantom-net --all-features --locked \
    chromium_152_macos_matches_retained_client_hello
  cargo test -p phantom-testkit --all-features --locked \
    --test chrome_client_hello
  cargo test --workspace --all-targets --all-features --locked
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked

  local msrv
  msrv=$(sed -nE 's/^rust-version = "([^"]+)"/\1/p' Cargo.toml)
  [[ -n "$msrv" ]] || die "could not derive the workspace MSRV"
  rustup toolchain install "$msrv" --profile minimal
  cargo "+$msrv" check --workspace --all-targets --locked
}

[[ -z $(git status --porcelain) ]] \
  || die "candidate probes require a clean disposable checkout"

case "$dependency" in
  wreq-proto)
    [[ "$candidate" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] \
      || die "invalid wreq-proto candidate '$candidate'"
    wreq_current=$(sed -nE 's/.*wreq-proto = "=([^"]+)".*/\1/p' \
      crates/phantom-net/Cargo.toml)
    [[ -n "$wreq_current" ]] || die "wreq-proto is not tracked by phantom-net"
    replace_exact crates/phantom-net/Cargo.toml \
      "wreq-proto = \"=$wreq_current\"" "wreq-proto = \"=$candidate\"" 1
    cargo update -p wreq-proto --precise "$candidate"
    ;;
  btls)
    [[ "$candidate" =~ ^[0-9a-f]{40}$ ]] || die "invalid btls revision '$candidate'"
    [[ ! -d vendor/btls ]] \
      || die "vendored btls needs its canonical patch applied before probing"
    btls_current=$(sed -nE \
      's/^btls = .*rev = "([0-9a-f]{40})".*/\1/p' Cargo.toml)
    replace_exact Cargo.toml "rev = \"$btls_current\"" "rev = \"$candidate\"" 2
    cargo update -p btls -p tokio-btls
    ;;
  http2)
    [[ "$candidate" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] \
      || die "invalid http2 candidate '$candidate'"
    [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || die "invalid http2 checksum"

    staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-http2-candidate.XXXXXX")
    archive="$staging/http2-$candidate.crate"
    fetch "https://static.crates.io/crates/http2/http2-$candidate.crate" > "$archive"
    actual=$(sha256 "$archive")
    [[ "$actual" == "$checksum" ]] \
      || die "http2 $candidate checksum mismatch: expected $checksum, found $actual"
    tar -xzf "$archive" -C "$staging"
    candidate_dir="$staging/http2-$candidate"

    # Apply while the canonical patch is still in the checked-out vendor tree.
    patch_file="$repo_root/vendor/http2/patches/ordered-headers.patch"
    git -C "$candidate_dir" apply --check "$patch_file"
    git -C "$candidate_dir" apply "$patch_file"
    mv vendor/http2 "$staging/http2.previous"
    mv "$candidate_dir" vendor/http2
    cargo update -p http2 --precise "$candidate"

    cargo fmt --manifest-path vendor/http2/Cargo.toml --all --check
    cargo check --manifest-path vendor/http2/Cargo.toml --all-targets --all-features
    cargo test --manifest-path vendor/http2/Cargo.toml --all-features client::tests
    cargo test --manifest-path vendor/http2/Cargo.toml --all-features --lib \
      -- --skip hpack::test::fixture
    ;;
  *)
    die "usage: $0 {wreq-proto|btls|http2} CANDIDATE [CHECKSUM]"
    ;;
esac

cargo tree -i "$dependency" --locked
workspace_gates
