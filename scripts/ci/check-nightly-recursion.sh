#!/usr/bin/env bash
# Check the public client's Send proofs with the workflow's pinned nightly.
# Usage: check-nightly-recursion.sh TOOLCHAIN JOBS CARGO_LOG
set -euo pipefail

if [[ $# != 3 || ! $2 =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: $0 TOOLCHAIN JOBS CARGO_LOG" >&2
  exit 64
fi
toolchain=$1
jobs=$2
output=$3
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

status=0
"$root/scripts/dev/with-cargo-lock.sh" cargo "+$toolchain" check -j "$jobs" \
  -p phantom-http --all-targets --all-features --locked >"$output" 2>&1 || status=$?
if [[ ! -f $output ]]; then
  echo "error: could not write nightly Cargo log: $output" >&2
  exit 1
fi
if grep -qE 'recursion_depth_exceeding_limit|overflow evaluating the requirement' "$output"; then
  cat "$output"
  echo "error: $toolchain reports recursion_depth_exceeding_limit; see $output"
  exit 1
fi
if ((status != 0)); then
  cat "$output"
  echo "error: cargo +$toolchain check failed with status $status; see $output"
  exit "$status"
fi
echo "$toolchain reports no recursion_depth_exceeding_limit in phantom-http"
