#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_dir/../.." && git rev-parse --show-toplevel)
cd "$repo_root"
dependency=${1:-}
candidate=${2:-}
checksum=${3:-}
probe_staging=
run_workspace_gates=true

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
    [[ -d vendor/btls && -f vendor/btls/patches/series ]] \
      || die "vendored btls and its canonical wrapper patch series are required"
    listed_patches=$(LC_ALL=C sort vendor/btls/patches/series)
    stored_patches=$(find vendor/btls/patches -maxdepth 1 -type f \
      -name '*.patch' -exec basename {} \; | LC_ALL=C sort)
    [[ "$listed_patches" == "$stored_patches" ]] \
      || die "btls patch series does not list every canonical patch exactly once"
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
    btls_sys_revision=${PHANTOM_BTLS_SYS_REVISION:-50e72407ac1f89cea14003004429ecf579541b6f}
    [[ "$btls_sys_revision" =~ ^[0-9a-f]{40}$ ]] \
      || die "PHANTOM_BTLS_SYS_REVISION must be an exact git revision"

    probe_staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-btls-candidate.XXXXXX")
    candidate_dir="$probe_staging/btls"
    "$script_dir/stage-btls-candidate.sh" "$candidate" "$candidate_dir"

    # Retain provenance material only for the disposable checkout. The wrapper
    # source and manifest came from the exact candidate staged above.
    cp vendor/btls/PHANTOM.md "$candidate_dir/PHANTOM.md"
    mkdir -p "$candidate_dir/patches"
    while IFS= read -r patch_name; do
      cp "vendor/btls/patches/$patch_name" "$candidate_dir/patches/"
    done < vendor/btls/patches/series
    cp vendor/btls/patches/series "$candidate_dir/patches/series"

    replace_exact_line Cargo.toml \
      "btls = { git = \"$btls_current_repository\", rev = \"$btls_current\", default-features = false }" \
      "btls = { git = \"$candidate_cargo_repository\", rev = \"$candidate\", default-features = false }" 1
    replace_exact_line Cargo.toml \
      "tokio-btls = { git = \"$btls_current_repository\", rev = \"$btls_current\", default-features = false }" \
      "tokio-btls = { git = \"$candidate_cargo_repository\", rev = \"$candidate\", default-features = false }" 1
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
      cargo test --manifest-path vendor/btls/Cargo.toml ssl::test::key_update
      cargo test --manifest-path vendor/btls/Cargo.toml ssl::test::ech
      cargo test --manifest-path vendor/btls/Cargo.toml record_size_limit
      cargo test --manifest-path vendor/btls/Cargo.toml delegated_credentials
      cargo test --manifest-path vendor/btls/Cargo.toml \
        aead::tests::shared_generic_context_seals_and_opens_concurrently
    else
      cargo clippy --manifest-path vendor/btls/Cargo.toml \
        --all-targets --features prefix-symbols -- -D warnings
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols ssl::test::alps
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols ssl::test::key_update
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols ssl::test::ech
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols record_size_limit
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols delegated_credentials
      cargo test --manifest-path vendor/btls/Cargo.toml \
        --features prefix-symbols \
        aead::tests::shared_generic_context_seals_and_opens_concurrently
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
    [[ -f vendor/http2/PHANTOM.md ]] \
      || die "vendored http2 provenance is required"
    [[ -f vendor/http2/patches/series ]] \
      || die "vendored http2 patch series is required"
    http2_patches=()
    while IFS= read -r patch; do
      [[ -n "$patch" ]] || die "vendored http2 patch series contains an empty entry"
      http2_patches+=("$patch")
    done < vendor/http2/patches/series
    [[ ${#http2_patches[@]} -gt 0 ]] || die "vendored http2 patch series is empty"
    for patch in "${http2_patches[@]}"; do
      [[ -f "vendor/http2/patches/$patch" ]] \
        || die "vendored http2 canonical patch $patch is required"
    done
    listed_http2_patches=$(printf '%s\n' "${http2_patches[@]}" | LC_ALL=C sort)
    stored_http2_patches=$(find vendor/http2/patches -maxdepth 1 -type f \
      -name '*.patch' -exec basename {} \; | LC_ALL=C sort)
    [[ "$listed_http2_patches" == "$stored_http2_patches" ]] \
      || die "vendored http2 patch series does not list every canonical patch exactly once"

    probe_staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-http2-candidate.XXXXXX")
    archive="$probe_staging/http2-$candidate.crate"
    fetch "https://static.crates.io/crates/http2/http2-$candidate.crate" > "$archive"
    actual=$(sha256 "$archive")
    [[ "$actual" == "$checksum" ]] \
      || die "http2 $candidate checksum mismatch: expected $checksum, found $actual"
    tar -xzf "$archive" -C "$probe_staging"
    candidate_dir="$probe_staging/http2-$candidate"

    # Apply while the canonical patches are still in the checked-out vendor tree.
    for patch in "${http2_patches[@]}"; do
      patch_file="$repo_root/vendor/http2/patches/$patch"
      if [[ "$patch" == ordered-headers.patch ]]; then
        git -C "$candidate_dir" apply --check --unidiff-zero "$patch_file"
        git -C "$candidate_dir" apply --unidiff-zero "$patch_file"
      else
        git -C "$candidate_dir" apply --check "$patch_file"
        git -C "$candidate_dir" apply "$patch_file"
      fi
    done
    mv vendor/http2 "$probe_staging/http2.previous"
    mv "$candidate_dir" vendor/http2
    cargo update -p http2 --precise "$candidate"

    cargo fmt --manifest-path vendor/http2/Cargo.toml --all --check
    cargo check --manifest-path vendor/http2/Cargo.toml --all-targets --all-features
    cargo test --manifest-path vendor/http2/Cargo.toml --all-features client::tests
    cargo test --manifest-path vendor/http2/Cargo.toml --all-features --lib \
      -- --skip hpack::test::fixture
    ;;
  h3)
    [[ "$candidate" =~ ^[0-9a-f]{40}$ ]] || die "invalid h3 revision '$candidate'"
    [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || die "invalid h3 archive checksum"
    [[ -f vendor/h3/PHANTOM.md ]] \
      || die "vendored h3 provenance is required"
    [[ -f vendor/h3/patches/series ]] \
      || die "vendored h3 patch series is required"
    h3_patches=()
    while IFS= read -r patch; do
      [[ -n "$patch" ]] || die "vendored h3 patch series contains an empty entry"
      h3_patches+=("$patch")
    done < vendor/h3/patches/series
    [[ ${#h3_patches[@]} -gt 0 ]] || die "vendored h3 patch series is empty"
    for patch in "${h3_patches[@]}"; do
      [[ -f "vendor/h3/patches/$patch" ]] \
        || die "vendored h3 canonical patch $patch is required"
    done
    listed_h3_patches=$(printf '%s\n' "${h3_patches[@]}" | LC_ALL=C sort)
    stored_h3_patches=$(find vendor/h3/patches -maxdepth 1 -type f \
      -name '*.patch' -exec basename {} \; | LC_ALL=C sort)
    [[ "$listed_h3_patches" == "$stored_h3_patches" ]] \
      || die "vendored h3 patch series does not list every canonical patch exactly once"

    probe_staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-h3-candidate.XXXXXX")
    archive="$probe_staging/h3-$candidate.tar.gz"
    fetch "https://codeload.github.com/hyperium/h3/tar.gz/$candidate" > "$archive"
    actual=$(sha256 "$archive")
    [[ "$actual" == "$checksum" ]] \
      || die "h3 $candidate checksum mismatch: expected $checksum, found $actual"
    tar -xzf "$archive" -C "$probe_staging"
    candidate_dir="$probe_staging/h3-$candidate"
    [[ -f "$candidate_dir/h3/Cargo.toml" \
      && -f "$candidate_dir/h3-quinn/Cargo.toml" ]] \
      || die "h3 candidate archive has an unexpected layout"

    for patch in "${h3_patches[@]}"; do
      patch_file="$repo_root/vendor/h3/patches/$patch"
      if [[ "$patch" == ordered-response-headers.patch ]]; then
        if ! git -C "$candidate_dir" apply --check --unidiff-zero "$patch_file"; then
          die "h3 patch $patch does not apply to candidate $candidate"
        fi
        git -C "$candidate_dir" apply --unidiff-zero "$patch_file"
      else
        if ! git -C "$candidate_dir" apply --check "$patch_file"; then
          die "h3 patch $patch does not apply to candidate $candidate"
        fi
        git -C "$candidate_dir" apply "$patch_file"
      fi
    done

    cp vendor/h3/PHANTOM.md "$candidate_dir/PHANTOM.md"
    mkdir -p "$candidate_dir/patches"
    cp vendor/h3/patches/series "$candidate_dir/patches/series"
    for patch in "${h3_patches[@]}"; do
      cp "$repo_root/vendor/h3/patches/$patch" "$candidate_dir/patches/"
    done
    mv vendor/h3 "$probe_staging/h3.previous"
    mv "$candidate_dir" vendor/h3

    cargo fmt --manifest-path vendor/h3/Cargo.toml --all --check
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 \
      config::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 \
      client::builder::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 \
      proto::frame::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p h3 qpack
    cargo clippy --manifest-path vendor/h3/Cargo.toml -p h3 \
      --lib --all-features -- -D warnings
    cargo check --manifest-path vendor/h3/Cargo.toml -p h3-quinn \
      --all-features

    # Candidate validation stays isolated from unrelated workspace packages.
    run_workspace_gates=false
    ;;
  *)
    die "usage: $0 {wreq-proto|btls|http2|h3} CANDIDATE [CHECKSUM]"
    ;;
esac

if [[ "$run_workspace_gates" == true ]]; then
  cargo tree -i "$dependency" --locked
  workspace_gates
fi
