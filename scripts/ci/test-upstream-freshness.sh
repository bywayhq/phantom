#!/usr/bin/env bash

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

selected=$(
  scripts/ci/report-upstream-freshness.sh --select-latest <<'EOF'
{"vers":"0.9.99","cksum":"older","yanked":false,"rust_version":"1.70"}
{"vers":"0.10.0-rc.1","cksum":"prerelease","yanked":false,"rust_version":"1.80"}
{"vers":"0.10.0+build.7","cksum":"latest","yanked":false,"rust_version":"1.85"}
{"vers":"1.0.0","cksum":"yanked","yanked":true,"rust_version":"1.90"}
{"vers":"01.2.3","cksum":"invalid","yanked":false,"rust_version":"1.60"}
EOF
)
jq -e '
  (.vers | split("+")[0]) == "0.10.0"
  and .cksum == "latest"
  and .rust_version == "1.85"
' <<<"$selected" >/dev/null

only_prereleases=$(
  scripts/ci/report-upstream-freshness.sh --select-latest <<'EOF'
{"vers":"2.0.0-alpha.1","cksum":"alpha","yanked":false}
{"vers":"1.9.0","cksum":"yanked","yanked":true}
EOF
)
[[ "$only_prereleases" == null ]]

# Chrome drift follows the major-version profile policy.
chrome_drift() {
  scripts/ci/report-upstream-freshness.sh --chrome-drift "$1" "$2"
}
[[ $(chrome_drift 152.0.7977.83 152.0.7977.83) == false ]]
[[ $(chrome_drift 152.0.7977.83 152.0.7977.64) == false ]]
[[ $(chrome_drift 152.0.7977.83 152.1.8000.10) == false ]]
[[ $(chrome_drift 152.0.7977.83 153.0.7990.5) == true ]]
[[ $(chrome_drift 152.0.7977.83 99.0.1.1) == true ]]
if chrome_drift 152.0.7977.83 153 >/dev/null 2>&1; then
  echo "malformed Chrome version was accepted" >&2
  exit 1
fi

replace_fixture_line() {
  local file=$1 old=$2 new=$3
  grep -F -x -q "$old" "$file" \
    || { echo "fixture line missing from $file: $old" >&2; exit 1; }
  sed -i.bak "s|^$old$|$new|" "$file"
  rm "$file.bak"
}

assert_non_fips_item() {
  local file=$1 item=$2
  awk -v item="$item" '
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line)
    }
    line == "#[cfg(not(feature = \"fips\"))]" { guarded = 1; next }
    guarded && line ~ /^#\[/ { next }
    line == item { found = 1; if (!guarded) { invalid = 1 } }
    line != "" { guarded = 0 }
    END { exit !(found && !invalid) }
  ' "$file" || {
    echo "item is not excluded from FIPS selection in $file: $item" >&2
    exit 1
  }
}

copy_vendor_fixture() {
  local source=$1 destination=$2
  [[ ! -e "$destination" ]]
  mkdir -p "$destination"
  tar --exclude='./target' -cf - -C "$source" . \
    | tar -xf - -C "$destination"
  [[ ! -e "$destination/target" ]]
}

make_btls_candidate() {
  local destination=$1 drift=${2:-none} patch_name index
  local patches=()
  mkdir -p "$destination"
  copy_vendor_fixture vendor/btls "$destination/btls"
  cp vendor/btls/README.md "$destination/README.md"
  while IFS= read -r patch_name; do
    patches+=("$patch_name")
  done < "$repo_root/vendor/btls/patches/series"
  for ((index=${#patches[@]} - 1; index >= 0; index--)); do
    git -C "$destination/btls" apply --reverse \
      "$repo_root/vendor/btls/patches/${patches[index]}"
  done
  rm -rf "$destination/btls/patches"
  rm "$destination/btls/PHANTOM.md" "$destination/btls/README.md"
  ln -s ../README.md "$destination/btls/README.md"

  replace_fixture_line "$destination/btls/Cargo.toml" \
    'rust-version = "1.85"' 'rust-version = { workspace = true }'
  replace_fixture_line "$destination/btls/Cargo.toml" \
    'version = "0.5.6"' 'version = { workspace = true }'
  replace_fixture_line "$destination/btls/Cargo.toml" \
    'repository = "https://github.com/0x676e67/btls"' \
    'repository = { workspace = true }'
  replace_fixture_line "$destination/btls/Cargo.toml" \
    'edition = "2021"' 'edition = { workspace = true }'
  for dependency in \
    'bitflags = "2.11.1"' \
    'foreign-types = "0.5"' \
    'openssl-macros = "0.1.1"' \
    'libc = "0.2.185"' \
    'hex = "0.4"' \
    'brotli = "8.0.2"'; do
    replace_fixture_line "$destination/btls/Cargo.toml" "$dependency" \
      "${dependency%% = *} = { workspace = true }"
  done
  replace_fixture_line "$destination/btls/Cargo.toml" \
    'btls-sys = { version = "0.5.6", git = "https://github.com/0xARYA/btls", rev = "50e72407ac1f89cea14003004429ecf579541b6f" }' \
    'btls-sys = { workspace = true }'

  cat > "$destination/Cargo.toml" <<'EOF'
[workspace]
members = ["btls"]
resolver = "2"

[workspace.package]
version = "0.5.6"
repository = "https://github.com/0x676e67/btls"
edition = "2021"
rust-version = "1.85"

[workspace.dependencies]
btls-sys = { version = "0.5.6", path = "btls-sys" }
bitflags = "2.11.1"
foreign-types = "0.5"
openssl-macros = "0.1.1"
libc = "0.2.185"
hex = "0.4"
brotli = "8.0.2"
EOF

  git -C "$destination" init --quiet
  git -C "$destination" config user.name 'Phantom CI'
  git -C "$destination" config user.email 'ci@invalid.example'
  git -C "$destination" add .
  git -C "$destination" commit --quiet -m upstream

  case "$drift" in
    none) ;;
    alps)
      sed -i.bak 's/pub fn set_tlsext_use_srtp/pub fn drifted_set_tlsext_use_srtp/' \
        "$destination/btls/src/ssl/mod.rs"
      rm "$destination/btls/src/ssl/mod.rs.bak"
      ;;
    ech)
      sed -i.bak \
        's/assert!(!ssl_stream.ssl().ech_accepted());/assert_eq!(ssl_stream.ssl().ech_accepted(), false);/' \
        "$destination/btls/src/ssl/test/ech.rs"
      rm "$destination/btls/src/ssl/test/ech.rs.bak"
      ;;
    record_size_limit)
      sed -i.bak \
        's/pub fn set_record_size_limit/pub fn drifted_set_record_size_limit/' \
        "$destination/btls/src/ssl/mod.rs"
      rm "$destination/btls/src/ssl/mod.rs.bak"
      ;;
    delegated_credentials)
      sed -i.bak \
        's/pub fn set_delegated_credentials/pub fn drifted_set_delegated_credentials/' \
        "$destination/btls/src/ssl/mod.rs"
      rm "$destination/btls/src/ssl/mod.rs.bak"
      ;;
    *)
      echo "unsupported btls drift fixture: $drift" >&2
      exit 1
      ;;
  esac
  if [[ "$drift" != none ]]; then
    git -C "$destination" add btls
    git -C "$destination" commit --quiet -m "$drift drift"
  fi
}

test_root=$(mktemp -d "${TMPDIR:-/tmp}/phantom-freshness-tests.XXXXXX")
trap 'rm -rf "$test_root"' EXIT

candidate_repo="$test_root/candidate"
make_btls_candidate "$candidate_repo"
candidate_revision=$(git -C "$candidate_repo" rev-parse HEAD)
candidate_status_before=$(git -C "$candidate_repo" status --porcelain)

staged_wrapper="$test_root/staged/btls"
stage_tmp="$test_root/stage-tmp"
mkdir -p "$stage_tmp"
TMPDIR="$stage_tmp" PHANTOM_BTLS_REPOSITORY="$candidate_repo" \
  scripts/ci/stage-btls-candidate.sh "$candidate_revision" "$staged_wrapper"
grep -F -q 'rev = "50e72407ac1f89cea14003004429ecf579541b6f"' \
  "$staged_wrapper/Cargo.toml"
grep -F -q 'pub fn peer_application_settings' "$staged_wrapper/src/ssl/mod.rs"
grep -F -q 'pub fn set_ech_grease_payload_length' \
  "$staged_wrapper/src/ssl/mod.rs"
grep -F -q 'pub fn set_record_size_limit' "$staged_wrapper/src/ssl/mod.rs"
grep -F -q 'pub fn set_delegated_credentials' \
  "$staged_wrapper/src/ssl/mod.rs"
assert_non_fips_item "$staged_wrapper/src/ssl/mod.rs" \
  'pub fn set_record_size_limit(&mut self, limit: u16) -> Result<(), ErrorStack> {'
assert_non_fips_item "$staged_wrapper/src/ssl/mod.rs" \
  'pub fn set_ech_grease_payload_length('
assert_non_fips_item "$staged_wrapper/src/ssl/test/ech.rs" \
  'use std::sync::{Arc, Mutex};'
assert_non_fips_item "$staged_wrapper/src/ssl/test/ech.rs" \
  'use crate::ssl::{ExtensionType, Ssl, SslContext, SslMethod};'
assert_non_fips_item "$staged_wrapper/src/ssl/test/ech.rs" \
  'fn ech_grease_payload_length() {'
assert_non_fips_item "$staged_wrapper/src/ssl/test/ech.rs" \
  'fn ech_grease_default_payload_length_remains_randomized() {'
assert_non_fips_item "$staged_wrapper/src/ssl/test/ech.rs" \
  'fn ech_grease_payload_must_be_nonempty_and_fit_the_extension_body() {'
assert_non_fips_item "$staged_wrapper/src/ssl/test/ech.rs" \
  'fn capture_ech_grease_extension(payload_length: Option<usize>) -> Vec<u8> {'
[[ ! -L "$staged_wrapper/README.md" ]]
[[ $(git -C "$candidate_repo" status --porcelain) == "$candidate_status_before" ]]
[[ -z $(find "$stage_tmp" -mindepth 1 -print -quit) ]]

dc_drift_repo="$test_root/dc-drift"
make_btls_candidate "$dc_drift_repo" delegated_credentials
dc_drift_revision=$(git -C "$dc_drift_repo" rev-parse HEAD)
if TMPDIR="$stage_tmp" PHANTOM_BTLS_REPOSITORY="$dc_drift_repo" \
  scripts/ci/stage-btls-candidate.sh \
    "$dc_drift_revision" "$test_root/dc-drifted-wrapper" \
    >"$test_root/dc-drift.stdout" 2>"$test_root/dc-drift.stderr"; then
  echo "DC-drifted btls candidate unexpectedly accepted the canonical patch" >&2
  exit 1
fi
grep -F -q 'wrapper patch delegated-credentials.patch does not apply' \
  "$test_root/dc-drift.stderr"
[[ -z $(git -C "$dc_drift_repo" status --porcelain) ]]
[[ -z $(find "$stage_tmp" -mindepth 1 -print -quit) ]]

rsl_drift_repo="$test_root/rsl-drift"
make_btls_candidate "$rsl_drift_repo" record_size_limit
rsl_drift_revision=$(git -C "$rsl_drift_repo" rev-parse HEAD)
if TMPDIR="$stage_tmp" PHANTOM_BTLS_REPOSITORY="$rsl_drift_repo" \
  scripts/ci/stage-btls-candidate.sh \
    "$rsl_drift_revision" "$test_root/rsl-drifted-wrapper" \
    >"$test_root/rsl-drift.stdout" 2>"$test_root/rsl-drift.stderr"; then
  echo "RSL-drifted btls candidate unexpectedly accepted the canonical patch" >&2
  exit 1
fi
grep -F -q 'wrapper patch record-size-limit.patch does not apply' \
  "$test_root/rsl-drift.stderr"
[[ -z $(git -C "$rsl_drift_repo" status --porcelain) ]]
[[ -z $(find "$stage_tmp" -mindepth 1 -print -quit) ]]

drift_repo="$test_root/drift"
make_btls_candidate "$drift_repo" alps
drift_revision=$(git -C "$drift_repo" rev-parse HEAD)
if TMPDIR="$stage_tmp" PHANTOM_BTLS_REPOSITORY="$drift_repo" \
  scripts/ci/stage-btls-candidate.sh \
    "$drift_revision" "$test_root/drifted-wrapper" \
    >"$test_root/drift.stdout" 2>"$test_root/drift.stderr"; then
  echo "drifted btls candidate unexpectedly accepted the canonical patch" >&2
  exit 1
fi
grep -F -q 'wrapper patch alps-settings.patch does not apply' \
  "$test_root/drift.stderr"
[[ -z $(git -C "$drift_repo" status --porcelain) ]]
[[ -z $(find "$stage_tmp" -mindepth 1 -print -quit) ]]

ech_drift_repo="$test_root/ech-drift"
make_btls_candidate "$ech_drift_repo" ech
ech_drift_revision=$(git -C "$ech_drift_repo" rev-parse HEAD)
if TMPDIR="$stage_tmp" PHANTOM_BTLS_REPOSITORY="$ech_drift_repo" \
  scripts/ci/stage-btls-candidate.sh \
    "$ech_drift_revision" "$test_root/ech-drifted-wrapper" \
    >"$test_root/ech-drift.stdout" 2>"$test_root/ech-drift.stderr"; then
  echo "ECH-drifted btls candidate unexpectedly accepted the canonical patch" >&2
  exit 1
fi
grep -F -q \
  'wrapper patch ech-grease-payload-length.patch does not apply' \
  "$test_root/ech-drift.stderr"
[[ -z $(git -C "$ech_drift_repo" status --porcelain) ]]
[[ -z $(find "$stage_tmp" -mindepth 1 -print -quit) ]]

probe_checkout="$test_root/probe-checkout"
mkdir -p \
  "$probe_checkout/scripts/ci" \
  "$probe_checkout/vendor" \
  "$probe_checkout/crates/phantom-net"
cp Cargo.toml Cargo.lock "$probe_checkout/"
cp crates/phantom-net/Cargo.toml "$probe_checkout/crates/phantom-net/"
copy_vendor_fixture vendor/btls "$probe_checkout/vendor/btls"
cp scripts/ci/probe-upstream-candidate.sh \
  scripts/ci/stage-btls-candidate.sh "$probe_checkout/scripts/ci/"
git -C "$probe_checkout" init --quiet
git -C "$probe_checkout" config user.name 'Phantom CI'
git -C "$probe_checkout" config user.email 'ci@invalid.example'
git -C "$probe_checkout" add .
git -C "$probe_checkout" commit --quiet -m fixture

mock_bin="$test_root/mock-bin"
mkdir -p "$mock_bin"
cat > "$mock_bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'cargo %s\n' "$*" >> "$COMMAND_LOG"
EOF
cat > "$mock_bin/rustup" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'rustup %s\n' "$*" >> "$COMMAND_LOG"
EOF
cat > "$mock_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
url=
for argument in "$@"; do
  url=$argument
done
case "$url" in
  https://codeload.github.com/hyperium/h3/tar.gz/*)
    command cat "${MOCK_H3_ARCHIVE:?}"
    ;;
  https://static.crates.io/crates/wreq-proto/*)
    command cat "${MOCK_WREQ_ARCHIVE:?}"
    ;;
  https://static.crates.io/crates/http2/*)
    command cat "${MOCK_HTTP2_ARCHIVE:?}"
    ;;
  *)
    echo "unexpected mocked curl URL: $url" >&2
    exit 1
    ;;
esac
EOF
chmod +x "$mock_bin/cargo" "$mock_bin/rustup"
chmod +x "$mock_bin/curl"

linux_bin="$test_root/linux-bin"
darwin_bin="$test_root/darwin-bin"
cp -R "$mock_bin" "$linux_bin"
cp -R "$mock_bin" "$darwin_bin"
cat > "$linux_bin/uname" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && $1 == -s ]]
printf 'Linux\n'
EOF
cat > "$darwin_bin/uname" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && $1 == -s ]]
printf 'Darwin\n'
EOF
chmod +x "$linux_bin/uname" "$darwin_bin/uname"

command_log="$test_root/commands.log"
probe_tmp="$test_root/probe-tmp"
mkdir -p "$probe_tmp"
if (
  cd "$probe_checkout"
  TMPDIR="$probe_tmp" PHANTOM_BTLS_REPOSITORY="$candidate_repo" \
    scripts/ci/probe-upstream-candidate.sh btls "$candidate_revision"
) >"$test_root/refusal.stdout" 2>"$test_root/refusal.stderr"; then
  echo "btls probe unexpectedly mutated a checkout without disposable opt-in" >&2
  exit 1
fi
grep -F -q 'PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1' \
  "$test_root/refusal.stderr"
[[ -z $(git -C "$probe_checkout" status --porcelain) ]]
[[ -z $(find "$probe_tmp" -mindepth 1 -print -quit) ]]

if (
  cd "$probe_checkout"
  TMPDIR="$probe_tmp" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    PHANTOM_BTLS_REPOSITORY="$drift_repo" \
    scripts/ci/probe-upstream-candidate.sh btls "$drift_revision"
) >"$test_root/probe-drift.stdout" 2>"$test_root/probe-drift.stderr"; then
  echo "drifted btls probe unexpectedly succeeded" >&2
  exit 1
fi
grep -F -q 'wrapper patch alps-settings.patch does not apply' \
  "$test_root/probe-drift.stderr"
[[ -z $(git -C "$probe_checkout" status --porcelain) ]]
[[ -z $(find "$probe_tmp" -mindepth 1 -print -quit) ]]

darwin_checkout="$test_root/darwin-checkout"
cp -R "$probe_checkout" "$darwin_checkout"
darwin_command_log="$test_root/darwin-commands.log"
darwin_tmp="$test_root/darwin-tmp"
mkdir -p "$darwin_tmp"

(
  cd "$probe_checkout"
  PATH="$linux_bin:$PATH" \
    TMPDIR="$probe_tmp" \
    COMMAND_LOG="$command_log" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    PHANTOM_BTLS_REPOSITORY="$candidate_repo" \
    scripts/ci/probe-upstream-candidate.sh btls "$candidate_revision"
)
# The wrapper candidate replaces vendor/btls only; root dependency sources and
# the vendored tokio-btls fork stay pinned to the reviewed revision.
git -C "$probe_checkout" diff --quiet -- Cargo.toml
grep -F -q 'rev = "50e72407ac1f89cea14003004429ecf579541b6f"' \
  "$probe_checkout/vendor/btls/Cargo.toml"
grep -F -x -q 'cargo update -p phantom-btls' "$command_log"
grep -F -x -q 'cargo tree -i phantom-btls --locked' "$command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols ssl::test::alps' \
  "$command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols ssl::test::ech' \
  "$command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols record_size_limit' \
  "$command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols delegated_credentials' \
  "$command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols aead::tests::shared_generic_context_seals_and_opens_concurrently' \
  "$command_log"
grep -F -q 'phantom-net --all-features --locked alps' "$command_log"
grep -F -q 'phantom-net --all-features --locked exact_ech_grease_payload' \
  "$command_log"
grep -F -q 'browser_client_hello_fixtures' "$command_log"
[[ -z $(git -C "$candidate_repo" status --porcelain) ]]
[[ -z $(find "$probe_tmp" -mindepth 1 -print -quit) ]]

(
  cd "$darwin_checkout"
  PATH="$darwin_bin:$PATH" \
    TMPDIR="$darwin_tmp" \
    COMMAND_LOG="$darwin_command_log" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    PHANTOM_BTLS_REPOSITORY="$candidate_repo" \
    scripts/ci/probe-upstream-candidate.sh btls "$candidate_revision"
)
grep -F -x -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml ssl::test::alps' \
  "$darwin_command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml ssl::test::ech' \
  "$darwin_command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml record_size_limit' \
  "$darwin_command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml delegated_credentials' \
  "$darwin_command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml aead::tests::shared_generic_context_seals_and_opens_concurrently' \
  "$darwin_command_log"
if grep -F -q \
  'cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols' \
  "$darwin_command_log"; then
  echo "Darwin btls wrapper gate unexpectedly enabled prefixed symbols" >&2
  exit 1
fi
[[ -z $(find "$darwin_tmp" -mindepth 1 -print -quit) ]]

wreq_version=$(awk '
  /^\[package\.metadata\.phantom\]$/ { metadata = 1; next }
  metadata && /^upstream-version = / {
    sub(/^[^"]*"/, "")
    sub(/".*/, "")
    print
    exit
  }
' vendor/wreq-proto/Cargo.toml)
[[ -n "$wreq_version" ]]
wreq_source_root="$test_root/wreq-source"
mkdir -p "$wreq_source_root"
copy_vendor_fixture vendor/wreq-proto \
  "$wreq_source_root/wreq-proto-$wreq_version"
wreq_patches=()
while IFS= read -r patch; do
  [[ -n "$patch" ]]
  wreq_patches+=("$patch")
done < vendor/wreq-proto/patches/series
for ((index = ${#wreq_patches[@]} - 1; index >= 0; index--)); do
  patch=${wreq_patches[$index]}
  git -C "$wreq_source_root/wreq-proto-$wreq_version" apply --reverse \
    "$repo_root/vendor/wreq-proto/patches/$patch"
done
rm -rf "$wreq_source_root/wreq-proto-$wreq_version/patches"
rm "$wreq_source_root/wreq-proto-$wreq_version/PHANTOM.md"
# Match the published crate's line endings so the mocked crates.io download
# exercises the probe's archive-normalization step before patch replay.
perl -0777 -Mopen=IO,:raw -pi -e 's/\r?\n/\r\n/g' \
  "$wreq_source_root/wreq-proto-$wreq_version/src/error.rs" \
  "$wreq_source_root/wreq-proto-$wreq_version/src/proto/http1.rs" \
  "$wreq_source_root/wreq-proto-$wreq_version/src/conn/http1.rs" \
  "$wreq_source_root/wreq-proto-$wreq_version/src/proto/http1/conn.rs" \
  "$wreq_source_root/wreq-proto-$wreq_version/src/proto/http1/decode.rs"
wreq_archive="$test_root/wreq-proto-$wreq_version.crate"
tar -czf "$wreq_archive" -C "$wreq_source_root" \
  "wreq-proto-$wreq_version"
wreq_checksum=$(shasum -a 256 "$wreq_archive" | awk '{print $1}')

wreq_drift_root="$test_root/wreq-drift-source"
mkdir -p "$wreq_drift_root"
cp -R "$wreq_source_root/wreq-proto-$wreq_version" \
  "$wreq_drift_root/wreq-proto-$wreq_version"
wreq_patch_target=$(sed -nE 's|^\+\+\+ b/(.+)$|\1|p' \
  vendor/wreq-proto/patches/chunk-size-line-limit.patch | head -1)
[[ -n "$wreq_patch_target" ]]
: > "$wreq_drift_root/wreq-proto-$wreq_version/$wreq_patch_target"
wreq_drift_archive="$test_root/wreq-proto-drift-$wreq_version.crate"
tar -czf "$wreq_drift_archive" -C "$wreq_drift_root" \
  "wreq-proto-$wreq_version"
wreq_drift_checksum=$(shasum -a 256 "$wreq_drift_archive" | awk '{print $1}')

wreq_checkout="$test_root/wreq-checkout"
mkdir -p \
  "$wreq_checkout/scripts/ci" \
  "$wreq_checkout/vendor" \
  "$wreq_checkout/crates/phantom-net"
cp Cargo.toml Cargo.lock "$wreq_checkout/"
cp crates/phantom-net/Cargo.toml "$wreq_checkout/crates/phantom-net/"
copy_vendor_fixture vendor/wreq-proto "$wreq_checkout/vendor/wreq-proto"
cp scripts/ci/probe-upstream-candidate.sh \
  "$wreq_checkout/scripts/ci/probe-upstream-candidate.sh"
git -C "$wreq_checkout" init --quiet
git -C "$wreq_checkout" config user.name 'Phantom CI'
git -C "$wreq_checkout" config user.email 'ci@invalid.example'
git -C "$wreq_checkout" add .
git -C "$wreq_checkout" commit --quiet -m fixture

wreq_tmp="$test_root/wreq-tmp"
mkdir -p "$wreq_tmp"
if (
  cd "$wreq_checkout"
  PATH="$mock_bin:$PATH" \
    TMPDIR="$wreq_tmp" \
    MOCK_WREQ_ARCHIVE="$wreq_archive" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh wreq-proto "$wreq_version" \
      0000000000000000000000000000000000000000000000000000000000000000
) >"$test_root/wreq-checksum.stdout" 2>"$test_root/wreq-checksum.stderr"; then
  echo "wreq-proto probe unexpectedly accepted the wrong archive checksum" >&2
  exit 1
fi
grep -F -q 'checksum mismatch' "$test_root/wreq-checksum.stderr"
[[ -z $(git -C "$wreq_checkout" status --porcelain) ]]
[[ -z $(find "$wreq_tmp" -mindepth 1 -print -quit) ]]

if (
  cd "$wreq_checkout"
  PATH="$mock_bin:$PATH" \
    TMPDIR="$wreq_tmp" \
    MOCK_WREQ_ARCHIVE="$wreq_drift_archive" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh wreq-proto "$wreq_version" \
      "$wreq_drift_checksum"
) >"$test_root/wreq-drift.stdout" 2>"$test_root/wreq-drift.stderr"; then
  echo "drifted wreq-proto probe unexpectedly accepted the canonical patch" >&2
  exit 1
fi
grep -F -q \
  "wreq-proto patch chunk-size-line-limit.patch does not apply to candidate $wreq_version" \
  "$test_root/wreq-drift.stderr"
[[ -z $(git -C "$wreq_checkout" status --porcelain) ]]
[[ -z $(find "$wreq_tmp" -mindepth 1 -print -quit) ]]

wreq_command_log="$test_root/wreq-commands.log"
(
  cd "$wreq_checkout"
  PATH="$mock_bin:$PATH" \
    TMPDIR="$wreq_tmp" \
    COMMAND_LOG="$wreq_command_log" \
    MOCK_WREQ_ARCHIVE="$wreq_archive" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh wreq-proto "$wreq_version" \
      "$wreq_checksum"
)
grep -F -x -q 'cargo update -p phantom-wreq-proto' "$wreq_command_log"
grep -F -x -q \
  'cargo fmt --manifest-path vendor/wreq-proto/Cargo.toml --all --check' \
  "$wreq_command_log"
grep -F -x -q \
  'cargo clippy --manifest-path vendor/wreq-proto/Cargo.toml --all-targets --all-features -- -D warnings -A clippy::question_mark -A clippy::result_large_err -A clippy::useless_borrows_in_formatting' \
  "$wreq_command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/wreq-proto/Cargo.toml --lib --all-features' \
  "$wreq_command_log"
grep -F -x -q 'cargo tree -i phantom-wreq-proto --locked' "$wreq_command_log"
git -C "$wreq_checkout/vendor/wreq-proto" apply --reverse --check \
  patches/chunk-size-line-limit.patch
[[ -f "$wreq_checkout/vendor/wreq-proto/PHANTOM.md" ]]
[[ -z $(find "$wreq_tmp" -mindepth 1 -print -quit) ]]

http2_source_root="$test_root/http2-source"
mkdir -p "$http2_source_root"
copy_vendor_fixture vendor/http2 "$http2_source_root/http2-0.5.20"
http2_patches=()
while IFS= read -r patch; do
  [[ -n "$patch" ]]
  http2_patches+=("$patch")
done < vendor/http2/patches/series
for ((index = ${#http2_patches[@]} - 1; index >= 0; index--)); do
  patch=${http2_patches[$index]}
  if [[ "$patch" == ordered-headers.patch ]]; then
    git -C "$http2_source_root/http2-0.5.20" apply --reverse --unidiff-zero \
      "$repo_root/vendor/http2/patches/$patch"
  else
    git -C "$http2_source_root/http2-0.5.20" apply --reverse \
      "$repo_root/vendor/http2/patches/$patch"
  fi
done
rm -rf "$http2_source_root/http2-0.5.20/patches"
rm "$http2_source_root/http2-0.5.20/PHANTOM.md"
[[ ! -e "$http2_source_root/http2-0.5.20/.cargo-ok" ]]
http2_archive="$test_root/http2-0.5.20.crate"
tar -czf "$http2_archive" -C "$http2_source_root" http2-0.5.20
http2_checksum=$(shasum -a 256 "$http2_archive" | awk '{print $1}')

http2_checkout="$test_root/http2-checkout"
mkdir -p \
  "$http2_checkout/scripts/ci" \
  "$http2_checkout/vendor" \
  "$http2_checkout/crates/phantom-net"
cp Cargo.toml Cargo.lock "$http2_checkout/"
cp crates/phantom-net/Cargo.toml "$http2_checkout/crates/phantom-net/"
copy_vendor_fixture vendor/http2 "$http2_checkout/vendor/http2"
cp scripts/ci/probe-upstream-candidate.sh \
  scripts/ci/stage-btls-candidate.sh "$http2_checkout/scripts/ci/"
git -C "$http2_checkout" init --quiet
git -C "$http2_checkout" config user.name 'Phantom CI'
git -C "$http2_checkout" config user.email 'ci@invalid.example'
git -C "$http2_checkout" add .
git -C "$http2_checkout" commit --quiet -m fixture

http2_tmp="$test_root/http2-tmp"
mkdir -p "$http2_tmp"
if (
  cd "$http2_checkout"
  PATH="$mock_bin:$PATH" \
    TMPDIR="$http2_tmp" \
    MOCK_HTTP2_ARCHIVE="$http2_archive" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh http2 0.5.20 \
      0000000000000000000000000000000000000000000000000000000000000000
) >"$test_root/http2-failure.stdout" 2>"$test_root/http2-failure.stderr"; then
  echo "HTTP/2 probe unexpectedly accepted the wrong archive checksum" >&2
  exit 1
fi
grep -F -q 'checksum mismatch' "$test_root/http2-failure.stderr"
[[ -z $(git -C "$http2_checkout" status --porcelain) ]]
[[ -z $(find "$http2_tmp" -mindepth 1 -print -quit) ]]

(
  cd "$http2_checkout"
  PATH="$mock_bin:$PATH" \
    TMPDIR="$http2_tmp" \
    COMMAND_LOG="$command_log" \
    MOCK_HTTP2_ARCHIVE="$http2_archive" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh http2 0.5.20 "$http2_checksum"
)
[[ -z $(find "$http2_tmp" -mindepth 1 -print -quit) ]]

# shellcheck disable=SC2016 # Backticks are literal Markdown in the pattern.
h3_revision=$(sed -nE \
  's/.*[Uu]pstream (revision|commit):? `?([0-9a-f]{40})`?.*/\2/p' \
  vendor/h3/PHANTOM.md)
[[ "$h3_revision" =~ ^[0-9a-f]{40}$ ]]
h3_source_root="$test_root/h3-source"
mkdir -p "$h3_source_root"
copy_vendor_fixture vendor/h3 "$h3_source_root/h3-$h3_revision"
h3_patches=()
while IFS= read -r patch; do
  [[ -n "$patch" ]]
  h3_patches+=("$patch")
done < vendor/h3/patches/series
for ((index = ${#h3_patches[@]} - 1; index >= 0; index--)); do
  patch=${h3_patches[$index]}
  if [[ "$patch" == ordered-response-headers.patch ]]; then
    git -C "$h3_source_root/h3-$h3_revision" apply --reverse --unidiff-zero \
      "$repo_root/vendor/h3/patches/$patch"
  else
    git -C "$h3_source_root/h3-$h3_revision" apply --reverse \
      "$repo_root/vendor/h3/patches/$patch"
  fi
done
rm -rf "$h3_source_root/h3-$h3_revision/patches"
rm "$h3_source_root/h3-$h3_revision/PHANTOM.md"
h3_archive="$test_root/h3-$h3_revision.tar.gz"
tar -czf "$h3_archive" -C "$h3_source_root" "h3-$h3_revision"
h3_checksum=$(shasum -a 256 "$h3_archive" | awk '{print $1}')

h3_drift_root="$test_root/h3-drift-source"
mkdir -p "$h3_drift_root"
cp -R "$h3_source_root/h3-$h3_revision" \
  "$h3_drift_root/h3-$h3_revision"
sed -i.bak \
  's/#\[derive(Debug, PartialEq)\]/#[derive(Debug, PartialEq, Eq)]/g' \
  "$h3_drift_root/h3-$h3_revision/h3/src/proto/frame.rs"
rm "$h3_drift_root/h3-$h3_revision/h3/src/proto/frame.rs.bak"
h3_drift_archive="$test_root/h3-drift-$h3_revision.tar.gz"
tar -czf "$h3_drift_archive" -C "$h3_drift_root" "h3-$h3_revision"
h3_drift_checksum=$(shasum -a 256 "$h3_drift_archive" | awk '{print $1}')

h3_qpack_drift_root="$test_root/h3-qpack-drift-source"
mkdir -p "$h3_qpack_drift_root"
cp -R "$h3_source_root/h3-$h3_revision" \
  "$h3_qpack_drift_root/h3-$h3_revision"
sed -i.bak \
  's/track_blocks: HashMap/drift_track_blocks: HashMap/' \
  "$h3_qpack_drift_root/h3-$h3_revision/h3/src/qpack/dynamic.rs"
rm "$h3_qpack_drift_root/h3-$h3_revision/h3/src/qpack/dynamic.rs.bak"
h3_qpack_drift_archive="$test_root/h3-qpack-drift-$h3_revision.tar.gz"
tar -czf "$h3_qpack_drift_archive" -C "$h3_qpack_drift_root" \
  "h3-$h3_revision"
h3_qpack_drift_checksum=$(shasum -a 256 "$h3_qpack_drift_archive" \
  | awk '{print $1}')

h3_checkout="$test_root/h3-checkout"
mkdir -p "$h3_checkout/scripts/ci" "$h3_checkout/vendor"
copy_vendor_fixture vendor/h3 "$h3_checkout/vendor/h3"
cp scripts/ci/probe-upstream-candidate.sh \
  "$h3_checkout/scripts/ci/probe-upstream-candidate.sh"
git -C "$h3_checkout" init --quiet
git -C "$h3_checkout" config user.name 'Phantom CI'
git -C "$h3_checkout" config user.email 'ci@invalid.example'
git -C "$h3_checkout" add .
git -C "$h3_checkout" commit --quiet -m fixture

h3_tmp="$test_root/h3-tmp"
mkdir -p "$h3_tmp"
if (
  cd "$h3_checkout"
  TMPDIR="$h3_tmp" \
    MOCK_H3_ARCHIVE="$h3_archive" \
    scripts/ci/probe-upstream-candidate.sh h3 "$h3_revision" "$h3_checksum"
) >"$test_root/h3-refusal.stdout" 2>"$test_root/h3-refusal.stderr"; then
  echo "h3 probe unexpectedly mutated a checkout without disposable opt-in" >&2
  exit 1
fi
grep -F -q 'PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1' \
  "$test_root/h3-refusal.stderr"
[[ -z $(git -C "$h3_checkout" status --porcelain) ]]
[[ -z $(find "$h3_tmp" -mindepth 1 -print -quit) ]]

h3_unlisted_checkout="$test_root/h3-unlisted-checkout"
cp -R "$h3_checkout" "$h3_unlisted_checkout"
cp "$h3_unlisted_checkout/vendor/h3/patches/ordered-settings.patch" \
  "$h3_unlisted_checkout/vendor/h3/patches/unlisted.patch"
git -C "$h3_unlisted_checkout" add vendor/h3/patches/unlisted.patch
git -C "$h3_unlisted_checkout" commit --quiet -m 'unlisted h3 patch'
if (
  cd "$h3_unlisted_checkout"
  TMPDIR="$h3_tmp" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh h3 "$h3_revision" "$h3_checksum"
) >"$test_root/h3-unlisted.stdout" 2>"$test_root/h3-unlisted.stderr"; then
  echo "h3 probe unexpectedly accepted an unlisted canonical patch" >&2
  exit 1
fi
grep -F -q \
  'vendored h3 patch series does not list every canonical patch exactly once' \
  "$test_root/h3-unlisted.stderr"
[[ -z $(git -C "$h3_unlisted_checkout" status --porcelain) ]]
[[ -z $(find "$h3_tmp" -mindepth 1 -print -quit) ]]

if (
  cd "$h3_checkout"
  PATH="$mock_bin:$PATH" \
    TMPDIR="$h3_tmp" \
    MOCK_H3_ARCHIVE="$h3_archive" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh h3 deadbeef "$h3_checksum"
) >"$test_root/h3-revision.stdout" 2>"$test_root/h3-revision.stderr"; then
  echo "h3 probe unexpectedly accepted a short revision" >&2
  exit 1
fi
grep -F -q "invalid h3 revision 'deadbeef'" "$test_root/h3-revision.stderr"
[[ -z $(git -C "$h3_checkout" status --porcelain) ]]
[[ -z $(find "$h3_tmp" -mindepth 1 -print -quit) ]]

if (
  cd "$h3_checkout"
  PATH="$mock_bin:$PATH" \
    TMPDIR="$h3_tmp" \
    MOCK_H3_ARCHIVE="$h3_archive" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh h3 "$h3_revision" \
      0000000000000000000000000000000000000000000000000000000000000000
) >"$test_root/h3-checksum.stdout" 2>"$test_root/h3-checksum.stderr"; then
  echo "h3 probe unexpectedly accepted the wrong archive checksum" >&2
  exit 1
fi
grep -F -q 'checksum mismatch' "$test_root/h3-checksum.stderr"
[[ -z $(git -C "$h3_checkout" status --porcelain) ]]
[[ -z $(find "$h3_tmp" -mindepth 1 -print -quit) ]]

if (
  cd "$h3_checkout"
  PATH="$mock_bin:$PATH" \
    TMPDIR="$h3_tmp" \
    MOCK_H3_ARCHIVE="$h3_drift_archive" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh h3 "$h3_revision" \
      "$h3_drift_checksum"
) >"$test_root/h3-drift.stdout" 2>"$test_root/h3-drift.stderr"; then
  echo "drifted h3 probe unexpectedly accepted the canonical patch" >&2
  exit 1
fi
grep -F -q 'h3 patch ordered-settings.patch does not apply' \
  "$test_root/h3-drift.stderr"
[[ -z $(git -C "$h3_checkout" status --porcelain) ]]
[[ -z $(find "$h3_tmp" -mindepth 1 -print -quit) ]]

if (
  cd "$h3_checkout"
  PATH="$mock_bin:$PATH" \
    TMPDIR="$h3_tmp" \
    MOCK_H3_ARCHIVE="$h3_qpack_drift_archive" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh h3 "$h3_revision" \
      "$h3_qpack_drift_checksum"
) >"$test_root/h3-qpack-drift.stdout" \
  2>"$test_root/h3-qpack-drift.stderr"; then
  echo "QPACK-drifted h3 probe unexpectedly accepted the canonical patches" >&2
  exit 1
fi
grep -F -q 'h3 patch qpack-codec.patch does not apply' \
  "$test_root/h3-qpack-drift.stderr"
[[ -z $(git -C "$h3_checkout" status --porcelain) ]]
[[ -z $(find "$h3_tmp" -mindepth 1 -print -quit) ]]

h3_command_log="$test_root/h3-commands.log"
(
  cd "$h3_checkout"
  PATH="$mock_bin:$PATH" \
    TMPDIR="$h3_tmp" \
    COMMAND_LOG="$h3_command_log" \
    MOCK_H3_ARCHIVE="$h3_archive" \
    PHANTOM_DISPOSABLE_CANDIDATE_CHECKOUT=1 \
    scripts/ci/probe-upstream-candidate.sh h3 "$h3_revision" "$h3_checksum"
)
grep -F -x -q \
  'cargo fmt --manifest-path vendor/h3/Cargo.toml -p phantom-h3 -p phantom-h3-datagram -p phantom-h3-quinn -p h3-webtransport -p examples --check' \
  "$h3_command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 config::tests' \
  "$h3_command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 client::builder::tests' \
  "$h3_command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 proto::frame::tests' \
  "$h3_command_log"
grep -F -x -q \
  'cargo test --manifest-path vendor/h3/Cargo.toml -p phantom-h3 qpack' \
  "$h3_command_log"
grep -F -x -q \
  'cargo clippy --manifest-path vendor/h3/Cargo.toml -p phantom-h3 --lib --all-features -- -D warnings' \
  "$h3_command_log"
grep -F -x -q \
  'cargo check --manifest-path vendor/h3/Cargo.toml -p phantom-h3-quinn --all-features' \
  "$h3_command_log"
if grep -F -q 'cargo tree -i h3' "$h3_command_log" \
  || grep -F -q 'cargo clippy --workspace' "$h3_command_log"; then
  echo "unselected h3 probe unexpectedly ran root workspace gates" >&2
  exit 1
fi
for ((index = ${#h3_patches[@]} - 1; index >= 0; index--)); do
  patch=${h3_patches[$index]}
  if [[ "$patch" == ordered-response-headers.patch ]]; then
    git -C "$h3_checkout/vendor/h3" apply --reverse --check --unidiff-zero \
      "patches/$patch"
    git -C "$h3_checkout/vendor/h3" apply --reverse --unidiff-zero \
      "patches/$patch"
  else
    git -C "$h3_checkout/vendor/h3" apply --reverse --check "patches/$patch"
    git -C "$h3_checkout/vendor/h3" apply --reverse "patches/$patch"
  fi
done
# shellcheck disable=SC2016 # GitHub expressions are matched literally.
grep -F -q 'h3_latest: ${{ steps.freshness.outputs.h3_latest }}' \
  .github/workflows/upstream-freshness.yml
# shellcheck disable=SC2016 # GitHub expressions are matched literally.
grep -F -q 'h3_checksum: ${{ steps.freshness.outputs.h3_checksum }}' \
  .github/workflows/upstream-freshness.yml
grep -F -q 'dependency: [wreq-proto, btls, http2, h3]' \
  .github/workflows/upstream-freshness.yml
[[ -z $(find "$h3_tmp" -mindepth 1 -print -quit) ]]
