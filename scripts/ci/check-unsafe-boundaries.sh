#!/usr/bin/env bash
# Check that unsafe code stays inside the two audited FFI modules.
#
# The workspace forbids `unsafe_code`. phantom-quic-btls and phantom-net deny
# it instead and allow it on exactly one module declaration each, the audited
# FFI boundaries that docs/explanation/design.md#unsafe-code describes. This
# check fails when an `allow(unsafe_code` or `expect(unsafe_code` attribute
# appears anywhere else in tracked Rust code, when either audited declaration
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

# path:count for each audited declaration.
expected=(
  "crates/phantom-quic-btls/src/lib.rs:1"
  "crates/phantom-net/src/tcp.rs:1"
)

attributes=$(git grep -c -E '(allow|expect)\(([^)]*,[[:space:]]*)?unsafe_code' -- '*.rs' ':!vendor' || true)

for entry in "${expected[@]}"; do
  if ! grep -qxF "$entry" <<<"$attributes"; then
    fail "expected exactly one unsafe_code allowance in ${entry%:*}"
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

# Manifests may deny unsafe_code but never allow or warn on it.
while IFS= read -r match; do
  [[ -z $match ]] && continue
  fail "a manifest relaxes unsafe_code: $match"
done < <(git grep -n -E '^[[:space:]]*unsafe_code[[:space:]]*=.*"(allow|warn)"' -- '*Cargo.toml' ':!vendor' || true)

if [[ $failures -gt 0 ]]; then
  echo "$failures unsafe code boundary check(s) failed" >&2
  exit 1
fi
echo "unsafe code is allowed only in the audited FFI modules"
