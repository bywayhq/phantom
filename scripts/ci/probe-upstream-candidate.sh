#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_dir/../.." && git rev-parse --show-toplevel)
cd "$repo_root"
dependency=${1:-}
candidate=${2:-}
checksum=${3:-}
probe_staging=

die() {
  echo "probe-upstream-candidate: $*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$probe_staging" && -d "$probe_staging" ]]; then
    rm -rf "$probe_staging"
  fi
}

trap cleanup EXIT

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

replace_exact_line() {
  local file=$1 old=$2 new=$3 expected=$4
  local count
  count=$(awk -v old="$old" '$0 == old { count++ } END { print count + 0 }' "$file")
  [[ "$count" == "$expected" ]] \
    || die "expected $expected lines equal to '$old' in $file, found $count"
  awk -v old="$old" -v replacement="$new" \
    '{ print ($0 == old ? replacement : $0) }' "$file" \
    > "$file.next"
  mv "$file.next" "$file"
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
  cargo test -p phantom-net --all-features --locked exact_ech_grease_payload
  cargo test -p phantom-net --all-features --locked \
    chromium_152_macos_matches_retained_client_hello
  cargo test -p phantom-testkit --all-features --locked \
    --test browser_client_hello_fixtures
  cargo test --workspace --all-targets --all-features --locked
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked

  local msrv
  msrv=$(sed -nE 's/^rust-version = "([^"]+)"/\1/p' Cargo.toml)
  [[ -n "$msrv" ]] || die "could not derive the workspace MSRV"
  ensure_msrv "$msrv"
  cargo "+$msrv" check --workspace --all-targets --locked
}

[[ "${PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT:-}" == 1 ]] \
  || die "refusing to mutate this checkout; set PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 only in a disposable checkout"
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
    [[ -d vendor/btls \
      && -f vendor/btls/patches/alps-settings.patch \
      && -f vendor/btls/patches/ech-grease-payload-length.patch \
      && -f vendor/btls/patches/record-size-limit.patch \
      && -f vendor/btls/patches/delegated-credentials.patch ]] \
      || die "vendored btls and all canonical wrapper patches are required"
    btls_sources=$(sed -nE \
      's/^(btls|tokio-btls) = .*git = "([^"]+)".*rev = "([0-9a-f]{40})".*/\2\t\3/p' \
      Cargo.toml)
    btls_revs=$(printf '%s\n' "$btls_sources" | cut -f2)
    [[ $(printf '%s\n' "$btls_revs" | sed '/^$/d' | wc -l | tr -d ' ') == 2 ]] \
      || die "btls and tokio-btls must each use an exact revision"
    [[ $(printf '%s\n' "$btls_revs" | sort -u | wc -l | tr -d ' ') == 1 ]] \
      || die "btls and tokio-btls must use the same revision"
    btls_current=$(printf '%s\n' "$btls_revs" | head -1)
    btls_current_repository=$(printf '%s\n' "$btls_sources" | cut -f1 | sort -u)
    [[ $(printf '%s\n' "$btls_current_repository" | sed '/^$/d' | wc -l | tr -d ' ') == 1 ]] \
      || die "btls and tokio-btls must use the same git repository"
    candidate_repository=${PHANTOM_BTLS_REPOSITORY:-https://github.com/0x676e67/btls.git}
    candidate_cargo_repository=${candidate_repository%.git}
    btls_sys_repository=${PHANTOM_BTLS_SYS_REPOSITORY:-https://github.com/0xARYA/btls}
    btls_sys_revision=${PHANTOM_BTLS_SYS_REVISION:-78b8c24a3388973d1d33c523995d311d766a1026}
    [[ "$btls_sys_revision" =~ ^[0-9a-f]{40}$ ]] \
      || die "PHANTOM_BTLS_SYS_REVISION must be an exact git revision"

    probe_staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-btls-candidate.XXXXXX")
    candidate_dir="$probe_staging/btls"
    "$script_dir/stage-btls-candidate.sh" "$candidate" "$candidate_dir"

    # Retain provenance material only for the disposable checkout. The wrapper
    # source and manifest came from the exact candidate staged above.
    cp vendor/btls/PHANTOM.md "$candidate_dir/PHANTOM.md"
    mkdir -p "$candidate_dir/patches"
    cp vendor/btls/patches/alps-settings.patch \
      vendor/btls/patches/ech-grease-payload-length.patch \
      vendor/btls/patches/record-size-limit.patch \
      vendor/btls/patches/delegated-credentials.patch \
      "$candidate_dir/patches/"

    replace_exact Cargo.toml \
      "git = \"$btls_current_repository\", rev = \"$btls_current\"" \
      "git = \"$candidate_cargo_repository\", rev = \"$candidate\"" 2
    replace_exact_line Cargo.toml \
      "[patch.\"$btls_current_repository\"]" \
      "[patch.\"$candidate_cargo_repository\"]" 1
    mv vendor/btls "$probe_staging/btls.previous"
    mv "$candidate_dir" vendor/btls
    cargo update -p btls-sys -p tokio-btls

    expected_source="git+$candidate_cargo_repository?rev=$candidate#$candidate"
    actual_source=$(locked_git_source tokio-btls)
    [[ "$actual_source" == "$expected_source" ]] \
      || die "tokio-btls lock source is '$actual_source', expected exact candidate $candidate"
    expected_source="git+$btls_sys_repository?rev=$btls_sys_revision#$btls_sys_revision"
    actual_source=$(locked_git_source btls-sys)
    [[ "$actual_source" == "$expected_source" ]] \
      || die "btls-sys lock source is '$actual_source', expected reviewed native patch $btls_sys_revision"

    cargo fmt --manifest-path vendor/btls/Cargo.toml --all --check
    btls_prefix_symbols=true
    case $(uname -s) in
      Darwin | MINGW* | MSYS* | CYGWIN*) btls_prefix_symbols=false ;;
    esac
    if [[ "$btls_prefix_symbols" == false ]]; then
      # Upstream does not rewrite prefixed archive symbols on Apple or Windows;
      # match Phantom's target-specific dependency selection there.
      cargo clippy --manifest-path vendor/btls/Cargo.toml \
        --all-targets -- -D warnings
      cargo test --manifest-path vendor/btls/Cargo.toml ssl::test::alps
      cargo test --manifest-path vendor/btls/Cargo.toml ssl::test::ech
      cargo test --manifest-path vendor/btls/Cargo.toml record_size_limit
      cargo test --manifest-path vendor/btls/Cargo.toml delegated_credentials
    else
      cargo clippy --manifest-path vendor/btls/Cargo.toml \
        --all-targets --features prefix-symbols -- -D warnings
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols ssl::test::alps
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols ssl::test::ech
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols record_size_limit
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols delegated_credentials
    fi

    msrv=$(sed -nE 's/^rust-version = "([^"]+)"/\1/p' Cargo.toml)
    [[ -n "$msrv" ]] || die "could not derive the workspace MSRV"
    ensure_msrv "$msrv"
    if [[ "$btls_prefix_symbols" == false ]]; then
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

    probe_staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-http2-candidate.XXXXXX")
    archive="$probe_staging/http2-$candidate.crate"
    fetch "https://static.crates.io/crates/http2/http2-$candidate.crate" > "$archive"
    actual=$(sha256 "$archive")
    [[ "$actual" == "$checksum" ]] \
      || die "http2 $candidate checksum mismatch: expected $checksum, found $actual"
    tar -xzf "$archive" -C "$probe_staging"
    candidate_dir="$probe_staging/http2-$candidate"

    # Apply while the canonical patch is still in the checked-out vendor tree.
    patch_file="$repo_root/vendor/http2/patches/ordered-headers.patch"
    git -C "$candidate_dir" apply --check "$patch_file"
    git -C "$candidate_dir" apply "$patch_file"
    mv vendor/http2 "$probe_staging/http2.previous"
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
