#!/usr/bin/env bash

set -euo pipefail

candidate=${1:-}
destination=${2:-}
repository=${PHANTOM_BTLS_REPOSITORY:-https://github.com/0x676e67/btls.git}
btls_sys_repository=${PHANTOM_BTLS_SYS_REPOSITORY:-https://github.com/0xARYA/btls}
btls_sys_revision=${PHANTOM_BTLS_SYS_REVISION:-78b8c24a3388973d1d33c523995d311d766a1026}

die() {
  echo "stage-btls-candidate: $*" >&2
  exit 1
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

workspace_package_value() {
  local manifest=$1 key=$2
  awk -v key="$key" '
    /^\[workspace\.package\]$/ { in_section = 1; next }
    in_section && /^\[/ { exit }
    in_section && index($0, key " = ") == 1 {
      line = $0
      sub(/^[^"]*"/, "", line)
      sub(/".*/, "", line)
      print line
      exit
    }
  ' "$manifest"
}

workspace_dependency_version() {
  local manifest=$1 dependency=$2
  awk -v dependency="$dependency" '
    /^\[workspace\.dependencies\]$/ { in_section = 1; next }
    in_section && /^\[/ { exit }
    in_section && index($0, dependency " = ") == 1 {
      line = $0
      if (line ~ /version[[:space:]]*=[[:space:]]*"/) {
        sub(/^.*version[[:space:]]*=[[:space:]]*"/, "", line)
      } else {
        sub(/^[^"]*"/, "", line)
      }
      sub(/".*/, "", line)
      print line
      exit
    }
  ' "$manifest"
}

materialize_wrapper_manifest() {
  local upstream_manifest=$1 wrapper_manifest=$2
  local version repository_url edition rust_version dependency dependency_version

  version=$(workspace_package_value "$upstream_manifest" version)
  repository_url=$(workspace_package_value "$upstream_manifest" repository)
  edition=$(workspace_package_value "$upstream_manifest" edition)
  rust_version=$(workspace_package_value "$upstream_manifest" rust-version)
  [[ -n "$version" && -n "$repository_url" && -n "$edition" && -n "$rust_version" ]] \
    || die "candidate workspace package metadata cannot be materialized"

  # Replace rust-version first because its suffix contains the package-version
  # text as a fixed substring.
  replace_exact "$wrapper_manifest" 'rust-version = { workspace = true }' \
    "rust-version = \"$rust_version\"" 1
  replace_exact "$wrapper_manifest" 'version = { workspace = true }' \
    "version = \"$version\"" 1
  replace_exact "$wrapper_manifest" 'repository = { workspace = true }' \
    "repository = \"$repository_url\"" 1
  replace_exact "$wrapper_manifest" 'edition = { workspace = true }' \
    "edition = \"$edition\"" 1

  for dependency in bitflags foreign-types openssl-macros libc hex brotli; do
    dependency_version=$(workspace_dependency_version \
      "$upstream_manifest" "$dependency")
    [[ -n "$dependency_version" ]] \
      || die "candidate workspace dependency '$dependency' has no version"
    replace_exact "$wrapper_manifest" \
      "$dependency = { workspace = true }" \
      "$dependency = \"$dependency_version\"" 1
  done

  dependency_version=$(workspace_dependency_version "$upstream_manifest" btls-sys)
  [[ -n "$dependency_version" ]] \
    || die "candidate workspace dependency 'btls-sys' has no version"
  replace_exact "$wrapper_manifest" 'btls-sys = { workspace = true }' \
    "btls-sys = { version = \"$dependency_version\", git = \"$btls_sys_repository\", rev = \"$btls_sys_revision\" }" 1

  if grep -F -q 'workspace = true' "$wrapper_manifest"; then
    die "candidate wrapper gained unsupported workspace-inherited packaging fields"
  fi
}

[[ "$candidate" =~ ^[0-9a-f]{40}$ ]] \
  || die "usage: $0 CANDIDATE_REVISION DESTINATION"
[[ "$btls_sys_revision" =~ ^[0-9a-f]{40}$ ]] \
  || die "PHANTOM_BTLS_SYS_REVISION must be an exact git revision"
[[ -n "$destination" ]] || die "usage: $0 CANDIDATE_REVISION DESTINATION"
[[ ! -e "$destination" ]] || die "destination already exists: $destination"

staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-btls-source.XXXXXX")
trap 'rm -rf "$staging"' EXIT

git -C "$staging" init --quiet
git -C "$staging" remote add origin "$repository"
git -C "$staging" fetch --quiet --depth=1 origin "$candidate" \
  || die "could not fetch exact btls revision $candidate from $repository"
git -C "$staging" checkout --quiet --detach FETCH_HEAD
actual=$(git -C "$staging" rev-parse HEAD)
[[ "$actual" == "$candidate" ]] \
  || die "fetched btls revision $actual instead of requested $candidate"

[[ -f "$staging/Cargo.toml" && -d "$staging/btls" ]] \
  || die "candidate revision does not contain the expected btls workspace"
mkdir -p "$(dirname "$destination")"
cp -R "$staging/btls" "$destination"

# Upstream's wrapper README is a workspace-relative symlink. A vendored package
# must contain the referenced repository README as a regular file.
if [[ -L "$destination/README.md" ]]; then
  [[ $(readlink "$destination/README.md") == ../README.md ]] \
    || die "candidate wrapper README symlink target changed"
  rm "$destination/README.md"
  cp "$staging/README.md" "$destination/README.md"
fi

# Packaging materialization is intentionally separate from the source patch.
# It resolves workspace fields and pins btls-sys to the reviewed native-patch
# fork independently from the upstream wrapper candidate.
materialize_wrapper_manifest \
  "$staging/Cargo.toml" "$destination/Cargo.toml"

patch_dir=$(cd "$(dirname "$0")/../.." && pwd)/vendor/btls/patches
series_file="$patch_dir/series"
[[ -f "$series_file" ]] || die "canonical wrapper patch series is missing"
listed_patches=$(LC_ALL=C sort "$series_file")
stored_patches=$(find "$patch_dir" -maxdepth 1 -type f -name '*.patch' \
  -exec basename {} \; | LC_ALL=C sort)
[[ "$listed_patches" == "$stored_patches" ]] \
  || die "wrapper patch series does not list every canonical patch exactly once"
while IFS= read -r patch_name; do
  [[ -n "$patch_name" ]] || die "wrapper patch series contains an empty entry"
  patch_file="$patch_dir/$patch_name"
  [[ -f "$patch_file" ]] || die "canonical wrapper patch is missing: $patch_name"
  if ! git -C "$destination" apply --check "$patch_file"; then
    die "wrapper patch $patch_name does not apply to btls $candidate; review upstream drift"
  fi
  git -C "$destination" apply "$patch_file"
done < "$series_file"
