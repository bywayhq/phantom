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

package_version() {
  awk '
    /^\[package\]$/ { package = 1; next }
    package && /^\[/ { exit }
    package && /^version = / {
      sub(/^[^"]*"/, "")
      sub(/".*/, "")
      print
      exit
    }
  ' "$1"
}

upstream_version() {
  awk '
    /^\[package\.metadata\.phantom\]$/ { metadata = 1; next }
    metadata && /^\[/ { exit }
    metadata && /^upstream-version = / {
      sub(/^[^"]*"/, "")
      sub(/".*/, "")
      print
      exit
    }
  ' "$1"
}

# Print the publish-identity patch rewritten from the current upstream version
# to a candidate version. The fork suffix restarts at 1 for a new upstream.
retarget_identity_patch() {
  local patch=$1 current=$2 candidate=$3 current_pattern
  current_pattern=${current//./\\.}
  sed -E \
    -e "s/\"(=?)$current_pattern-phantom\.[0-9]+\"/\"\1$candidate-phantom.1\"/g" \
    -e "s/\"$current_pattern\"/\"$candidate\"/g" \
    -e "s/ $current_pattern; / $candidate; /g" \
    -e "s/-$current_pattern\.crate/-$candidate.crate/g" \
    "$patch"
}

# Point every exact pin on a renamed fork at its new version.
repin_fork() {
  local current_pin=$1 candidate_pin=$2 manifest
  [[ "$current_pin" != "$candidate_pin" ]] || return 0
  while IFS= read -r manifest; do
    replace_exact "$manifest" "\"=$current_pin\"" "\"=$candidate_pin\"" 1
  done < <(grep -F -l "\"=$current_pin\"" Cargo.toml vendor/*/Cargo.toml \
    vendor/h3/*/Cargo.toml 2>/dev/null || true)
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
  cargo test -p phantom-net --all-features --locked ech_grease_aead
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
    [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] \
      || die "invalid wreq-proto archive checksum"
    [[ -f vendor/wreq-proto/PHANTOM.md ]] \
      || die "vendored wreq-proto provenance is required"
    [[ -f vendor/wreq-proto/patches/series ]] \
      || die "vendored wreq-proto patch series is required"
    wreq_patches=()
    while IFS= read -r patch; do
      [[ -n "$patch" ]] || die "vendored wreq-proto patch series contains an empty entry"
      wreq_patches+=("$patch")
    done < vendor/wreq-proto/patches/series
    [[ ${#wreq_patches[@]} -gt 0 ]] \
      || die "vendored wreq-proto patch series is empty"
    for patch in "${wreq_patches[@]}"; do
      [[ -f "vendor/wreq-proto/patches/$patch" ]] \
        || die "vendored wreq-proto canonical patch $patch is required"
    done
    listed_wreq_patches=$(printf '%s\n' "${wreq_patches[@]}" | LC_ALL=C sort)
    stored_wreq_patches=$(find vendor/wreq-proto/patches -maxdepth 1 -type f \
      -name '*.patch' -exec basename {} \; | LC_ALL=C sort)
    [[ "$listed_wreq_patches" == "$stored_wreq_patches" ]] \
      || die "vendored wreq-proto patch series does not list every canonical patch exactly once"

    wreq_current=$(upstream_version vendor/wreq-proto/Cargo.toml)
    [[ -n "$wreq_current" ]] || die "vendored wreq-proto has no upstream version"
    wreq_current_pin=$(package_version vendor/wreq-proto/Cargo.toml)

    probe_staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-wreq-proto-candidate.XXXXXX")
    archive="$probe_staging/wreq-proto-$candidate.crate"
    fetch "https://static.crates.io/crates/wreq-proto/wreq-proto-$candidate.crate" > "$archive"
    actual=$(sha256 "$archive")
    [[ "$actual" == "$checksum" ]] \
      || die "wreq-proto $candidate checksum mismatch: expected $checksum, found $actual"
    tar -xzf "$archive" -C "$probe_staging"
    candidate_dir="$probe_staging/wreq-proto-$candidate"
    [[ -f "$candidate_dir/Cargo.toml" ]] \
      || die "wreq-proto candidate archive has an unexpected layout"

    # The reviewed 0.2.5 archive stores these sources with CRLF. Normalize
    # before replay so the canonical patch is independent of archive line endings.
    for source in \
      src/error.rs \
      src/proto/http1.rs \
      src/conn/http1.rs \
      src/proto/http1/conn.rs \
      src/proto/http1/decode.rs
    do
      sed $'s/\r$//' "$candidate_dir/$source" > "$candidate_dir/$source.lf"
      mv "$candidate_dir/$source.lf" "$candidate_dir/$source"
    done

    for patch in "${wreq_patches[@]}"; do
      patch_file="$repo_root/vendor/wreq-proto/patches/$patch"
      if [[ "$patch" == publish-identity.patch ]]; then
        retarget_identity_patch "$patch_file" "$wreq_current" "$candidate" \
          > "$probe_staging/$patch"
        patch_file="$probe_staging/$patch"
      fi
      if ! git -C "$candidate_dir" apply --check "$patch_file"; then
        die "wreq-proto patch $patch does not apply to candidate $candidate"
      fi
      git -C "$candidate_dir" apply "$patch_file"
    done
    cp vendor/wreq-proto/PHANTOM.md "$candidate_dir/PHANTOM.md"
    mkdir -p "$candidate_dir/patches"
    cp vendor/wreq-proto/patches/series "$candidate_dir/patches/series"
    for patch in "${wreq_patches[@]}"; do
      cp "$repo_root/vendor/wreq-proto/patches/$patch" "$candidate_dir/patches/"
    done
    mv vendor/wreq-proto "$probe_staging/wreq-proto.previous"
    mv "$candidate_dir" vendor/wreq-proto

    repin_fork "$wreq_current_pin" "$(package_version vendor/wreq-proto/Cargo.toml)"
    cargo update -p phantom-wreq-proto

    cargo fmt --manifest-path vendor/wreq-proto/Cargo.toml --all --check
    cargo clippy --manifest-path vendor/wreq-proto/Cargo.toml \
      --all-targets --all-features -- \
      -D warnings \
      -A clippy::question_mark \
      -A clippy::result_large_err \
      -A clippy::useless_borrows_in_formatting
    cargo test --manifest-path vendor/wreq-proto/Cargo.toml \
      --lib --all-features
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
    btls_sys_repository=${PHANTOM_BTLS_SYS_REPOSITORY:-https://github.com/0xARYA/btls}
    btls_sys_revision=${PHANTOM_BTLS_SYS_REVISION:-ce81167653e2d8878f2e9b2218a15b9bc8351a53}
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

    btls_current_pin=$(package_version vendor/btls/Cargo.toml)
    mv vendor/btls "$probe_staging/btls.previous"
    mv "$candidate_dir" vendor/btls
    repin_fork "$btls_current_pin" "$(package_version vendor/btls/Cargo.toml)"
    cargo update -p phantom-btls

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
    http2_current=$(upstream_version vendor/http2/Cargo.toml)
    [[ -n "$http2_current" ]] || die "vendored http2 has no upstream version"
    http2_current_pin=$(package_version vendor/http2/Cargo.toml)

    # Apply while the canonical patches are still in the checked-out vendor tree.
    for patch in "${http2_patches[@]}"; do
      patch_file="$repo_root/vendor/http2/patches/$patch"
      if [[ "$patch" == publish-identity.patch ]]; then
        retarget_identity_patch "$patch_file" "$http2_current" "$candidate" \
          > "$probe_staging/$patch"
        patch_file="$probe_staging/$patch"
      fi
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
    repin_fork "$http2_current_pin" "$(package_version vendor/http2/Cargo.toml)"
    cargo update -p phantom-http2

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

    cargo fmt --manifest-path vendor/h3/Cargo.toml -p phantom-h3 -p phantom-h3-datagram -p phantom-h3-quinn -p h3-webtransport -p examples --check
    cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 \
      config::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 \
      client::builder::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 \
      proto::frame::tests
    cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 qpack
    cargo clippy --manifest-path vendor/h3/Cargo.toml -p phantom-h3 \
      --lib --all-features -- -D warnings
    cargo check --manifest-path vendor/h3/Cargo.toml -p phantom-h3-quinn \
      --all-features

    # Candidate validation stays isolated from unrelated workspace packages.
    run_workspace_gates=false
    ;;
  *)
    die "usage: $0 {wreq-proto|btls|http2|h3} CANDIDATE [CHECKSUM]"
    ;;
esac

if [[ "$run_workspace_gates" == true ]]; then
  cargo tree -i "phantom-$dependency" --locked
  workspace_gates
fi
