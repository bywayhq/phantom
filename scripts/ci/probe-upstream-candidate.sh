#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_dir/../.." && git rev-parse --show-toplevel)
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
  count=$({ grep -F -o "$old" "$file" || true; } | wc -l | tr -d ' ')
  [[ "$count" == "$expected" ]] \
    || die "expected $expected occurrences of '$old' in $file, found $count"
  sed -i.bak "s|$old|$new|g" "$file"
  rm "$file.bak"
}

locked_git_source() {
  local package=$1
  awk -v package="$package" '
    /^\[\[package\]\]$/ { in_package = 1; name = ""; next }
    in_package && /^name = / {
      name = $0
      sub(/^[^"]*"/, "", name)
      sub(/".*/, "", name)
      next
    }
    in_package && name == package && /^source = / {
      source = $0
      sub(/^[^"]*"/, "", source)
      sub(/".*/, "", source)
      print source
      exit
    }
  ' Cargo.lock
}

installed_msrv=
ensure_msrv() {
  local requested=$1
  if [[ "$installed_msrv" != "$requested" ]]; then
    rustup toolchain install "$requested" --profile minimal
    installed_msrv=$requested
  fi
}

workspace_gates() {
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test -p phantom-net --all-features --locked alps
  cargo test -p phantom-net --all-features --locked \
    chromium_152_macos_matches_retained_client_hello
  cargo test -p phantom-testkit --all-features --locked \
    --test chrome_client_hello
  cargo test --workspace --all-targets --all-features --locked
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked

  local msrv
  msrv=$(sed -nE 's/^rust-version = "([^"]+)"/\1/p' Cargo.toml)
  [[ -n "$msrv" ]] || die "could not derive the workspace MSRV"
  ensure_msrv "$msrv"
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
    [[ -d vendor/btls && -f vendor/btls/patches/alps-settings.patch ]] \
      || die "vendored btls and its canonical ALPS patch are required"
    btls_revs=$(sed -nE \
      's/^(btls|tokio-btls) = .*rev = "([0-9a-f]{40})".*/\2/p' Cargo.toml)
    [[ $(printf '%s\n' "$btls_revs" | sed '/^$/d' | wc -l | tr -d ' ') == 2 ]] \
      || die "btls and tokio-btls must each use an exact revision"
    [[ $(printf '%s\n' "$btls_revs" | sort -u | wc -l | tr -d ' ') == 1 ]] \
      || die "btls and tokio-btls must use the same revision"
    btls_current=$(printf '%s\n' "$btls_revs" | head -1)

    staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-btls-candidate.XXXXXX")
    candidate_dir="$staging/btls"
    "$script_dir/stage-btls-candidate.sh" "$candidate" "$candidate_dir"

    # Retain provenance material only for the disposable checkout. The wrapper
    # source and manifest came from the exact candidate staged above.
    cp vendor/btls/PHANTOM.md "$candidate_dir/PHANTOM.md"
    mkdir -p "$candidate_dir/patches"
    cp vendor/btls/patches/alps-settings.patch "$candidate_dir/patches/"

    replace_exact Cargo.toml "rev = \"$btls_current\"" "rev = \"$candidate\"" 2
    mv vendor/btls "$staging/btls.previous"
    mv "$candidate_dir" vendor/btls
    cargo update -p btls-sys -p tokio-btls

    expected_source="git+https://github.com/0x676e67/btls?rev=$candidate#$candidate"
    for package in btls-sys tokio-btls; do
      actual_source=$(locked_git_source "$package")
      [[ "$actual_source" == "$expected_source" ]] \
        || die "$package lock source is '$actual_source', expected exact candidate $candidate"
    done

    cargo fmt --manifest-path vendor/btls/Cargo.toml --all --check
    if [[ $(uname -s) == Darwin ]]; then
      # Upstream does not rewrite prefixed archive symbols on Apple platforms;
      # match Phantom's target-specific dependency selection there.
      cargo clippy --manifest-path vendor/btls/Cargo.toml \
        --all-targets -- -D warnings
      cargo test --manifest-path vendor/btls/Cargo.toml ssl::test::alps
    else
      cargo clippy --manifest-path vendor/btls/Cargo.toml \
        --all-targets --features prefix-symbols -- -D warnings
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols ssl::test::alps
    fi

    msrv=$(sed -nE 's/^rust-version = "([^"]+)"/\1/p' Cargo.toml)
    [[ -n "$msrv" ]] || die "could not derive the workspace MSRV"
    ensure_msrv "$msrv"
    if [[ $(uname -s) == Darwin ]]; then
      cargo "+$msrv" check --manifest-path vendor/btls/Cargo.toml --all-targets
    else
      cargo "+$msrv" check --manifest-path vendor/btls/Cargo.toml \
        --all-targets --features prefix-symbols
    fi
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
