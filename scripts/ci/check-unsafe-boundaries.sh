#!/usr/bin/env bash
# Check that unsafe code stays inside the audited FFI modules.
#
# The workspace forbids `unsafe_code`. phantom-quic-btls and phantom-net deny
# it instead, as do the Go and Node adapters, and allow it on their audited private
# module declarations. The check fails when an unsafe_code allow/expect attribute
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

# Python checks balanced Rust attributes, ignoring comments and literal contents.
# Inspect every source branch without evaluating cfg or expanding macros.
status=0
python scripts/ci/check_unsafe_boundaries.py || status=$?
if [[ $status -gt 1 ]]; then
  exit "$status"
elif [[ $status -eq 1 ]]; then
  failures=$((failures + 1))
fi

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
