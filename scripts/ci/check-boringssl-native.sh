#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
native_target=$(mktemp -d "${TMPDIR:-/tmp}/phantom-boringssl-native.XXXXXX")
trap 'rm -rf "$native_target"' EXIT

for tool in cargo cmake git go; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool is unavailable: $tool" >&2
    exit 1
  fi
done

cd "$repo_root"

locked_btls_sys_source() {
  local lock_file=$1
  awk '
    $0 == "[[package]]" { in_package = 0 }
    $0 == "name = \"btls-sys\"" { in_package = 1 }
    in_package && /^source = / {
      sub(/^source = \"/, "")
      sub(/\"$/, "")
      print
      exit
    }
  ' "$lock_file"
}

workspace_source=$(locked_btls_sys_source Cargo.lock)
vendor_source=$(locked_btls_sys_source vendor/btls/Cargo.lock)
if [[ -z "$workspace_source" || "$workspace_source" != "$vendor_source" ]]; then
  echo "workspace and standalone btls-sys lock entries differ" >&2
  exit 1
fi

# The standalone wrapper manifest has no default features. In particular, this
# leaves symbol prefixing disabled so BoringSSL's native test shims can link.
CARGO_TARGET_DIR="$native_target" \
  cargo check --manifest-path vendor/btls/Cargo.toml --locked

caches=()
while IFS= read -r -d '' cache; do
  caches+=("$cache")
done < <(find "$native_target" -type f \
  -path '*/build/btls-sys-*/out/build/CMakeCache.txt' -print0)

if [[ ${#caches[@]} -ne 1 ]]; then
  echo "expected one btls-sys CMake cache, found ${#caches[@]}" >&2
  exit 1
fi

cache=${caches[0]}
build_dir=$(dirname "$cache")
out_dir=$(dirname "$build_dir")

cache_value() {
  local key=$1
  awk -F= -v key="$key" '
    index($0, key ":") == 1 {
      sub(/^[^=]*=/, "")
      print
    }
  ' "$cache"
}

if [[ $(cache_value BUILD_TESTING) != ON ]]; then
  echo "btls-sys configured BoringSSL without BUILD_TESTING=ON" >&2
  exit 1
fi

if [[ $(cache_value CMAKE_PROJECT_NAME) != BoringSSL ]]; then
  echo "unexpected native CMake project" >&2
  exit 1
fi

case $(cache_value LIBUNWIND_FOUND) in
  1 | ON | TRUE | YES) ;;
  *)
    echo "BoringSSL configured without libunwind test coverage" >&2
    exit 1
    ;;
esac

generator=$(cache_value CMAKE_GENERATOR)
if [[ -z "$generator" || "$generator" == "Visual Studio "* ]]; then
  echo "CMake generator does not provide BoringSSL's run_tests target: $generator" >&2
  exit 1
fi

source_dir=$(cache_value CMAKE_HOME_DIRECTORY)
expected_source="$out_dir/boringssl"
if [[ ! -d "$source_dir" || ! -d "$expected_source" ]]; then
  echo "btls-sys did not materialize the BoringSSL source tree" >&2
  exit 1
fi
if [[ $(cd "$source_dir" && pwd -P) != $(cd "$expected_source" && pwd -P) ]]; then
  echo "CMake source does not belong to the locked btls-sys build" >&2
  exit 1
fi

required_go=$(sed -nE 's/^go ([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' \
  "$source_dir/go.mod")
actual_go=$(go env GOVERSION)
if [[ -z "$required_go" || "$actual_go" != "go$required_go" ]]; then
  echo "BoringSSL requires Go $required_go, found $actual_go" >&2
  exit 1
fi

cmake --build "$build_dir" --target run_tests --parallel
