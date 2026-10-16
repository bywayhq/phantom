#!/usr/bin/env bash
# Check that unsafe code stays inside the audited FFI modules.
#
# The workspace forbids `unsafe_code`. phantom-quic-btls and phantom-net deny
# it instead and allow it on their audited private module declarations,
# described in docs/explanation/design.md#unsafe-code. This
# check fails when an `allow(unsafe_code` or `expect(unsafe_code` attribute
# appears anywhere else in tracked Rust code, when an audited declaration
# is missing, or when a manifest relaxes the `unsafe_code` lint further.
#
# The search covers tracked files outside vendor/, whose forks carry their
# upstream unsafe code and are audited through their patch series.
#
# Usage: check-unsafe-boundaries.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

failures=0
fail() {
  echo "$1" >&2
  failures=$((failures + 1))
}

# Runs git grep with the given arguments. No match is an empty result; any
# other failure stops the check rather than passing it.
search() {
  local status=0
  git grep "$@" || status=$?
  if [[ $status -gt 1 ]]; then
    echo "git grep failed with status $status" >&2
    exit 2
  fi
}

# path:count for each audited declaration.
expected=(
  "crates/phantom-quic-btls/src/lib.rs:1"
  "crates/phantom-net/src/lib.rs:4"
)

attributes=$(search -c -E '(allow|expect)\(([^)]*,[[:space:]]*)?unsafe_code' -- '*.rs' ':!vendor')

for entry in "${expected[@]}"; do
  if ! grep -qxF "$entry" <<<"$attributes"; then
    fail "expected ${entry##*:} unsafe_code allowance(s) in ${entry%:*}"
  fi
done

while IFS= read -r entry; do
  [[ -z $entry ]] && continue
  allowed=false
  for expected_entry in "${expected[@]}"; do
    if [[ ${entry%:*} == "${expected_entry%:*}" ]]; then
      allowed=true
    fi
  done
  if [[ $allowed == false ]]; then
    fail "unsafe_code is allowed outside the audited FFI modules: ${entry%:*}"
  fi
done <<<"$attributes"

# Count checks alone would permit an allowance moved onto another module.
check_modules() {
  local path=$1 names=$2
  if ! awk -v names="$names" '
    BEGIN {
      count = split(names, modules, "|")
      for (i = 1; i <= count; i++) expected[modules[i]] = 0
    }
    /(allow|expect)\(([^)]*,[[:space:]]*)?unsafe_code/ {
      if (getline <= 0) { invalid = 1; exit }
      sub(/\r$/, "")
      if ($0 !~ ("^mod (" names ");$")) { invalid = 1; exit }
      name = $0
      sub(/^mod /, "", name)
      sub(/;$/, "", name)
      expected[name]++
    }
    END {
      for (name in expected) if (expected[name] != 1) invalid = 1
      exit invalid
    }
  ' "$path"; then
    fail "unsafe_code allowance moved outside audited declarations in $path"
  fi
}
check_modules crates/phantom-quic-btls/src/lib.rs backend
check_modules crates/phantom-net/src/lib.rs 'socket_ffi|system_dns_ffi|linux_dns_ffi|macos_dns_ffi'

# Manifests may deny unsafe_code but never allow or warn on it.
manifests=$(search -n -E '^[[:space:]]*unsafe_code[[:space:]]*=.*"(allow|warn)"' -- '*Cargo.toml' ':!vendor')
while IFS= read -r match; do
  [[ -z $match ]] && continue
  fail "a manifest relaxes unsafe_code: $match"
done <<<"$manifests"

if [[ $failures -gt 0 ]]; then
  echo "$failures unsafe code boundary check(s) failed" >&2
  exit 1
fi
echo "unsafe code is allowed only in the audited FFI modules"
