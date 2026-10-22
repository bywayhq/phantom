#!/usr/bin/env bash
set -uo pipefail
scripts/dev/with-cargo-lock.sh wsl.exe -d Ubuntu-24.04 --cd 'C:\code\phantom-worktrees\safari-ios-peer' -e bash -lc '
  unset DOCS_RS BORING_BSSL_PATH BORING_BSSL_INCLUDE_PATH BORING_BSSL_ASSUME_PATCHED BORING_BSSL_SOURCE_PATH BORING_BSSL_FIPS_SOURCE_PATH
  export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never
  export CARGO_TARGET_DIR="$HOME/.cache/phantom-peer/safari-ios-peer"
  exec cargo build --locked --offline -j 2 --manifest-path target/tmp/safari-ios-peer-preparation/consumer/Cargo.toml
' > target/tmp/safari-ios-peer-preparation/build-linux.log 2>&1
result=$?
printf '%s\n' "$result" > target/tmp/safari-ios-peer-preparation/build-linux-exit.txt
exit "$result"
