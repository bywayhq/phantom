#!/usr/bin/env bash
# Build and exercise the native Node adapter using the caller's Cargo target.
# Run through with-cargo-lock.sh, as the integration gate does.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
node --version
cargo build --locked -p phantom-node
# Cargo resolves MSYS paths as well as ordinary host paths. Give the copy
# script that resolved path rather than interpreting the environment again.
CARGO_TARGET_DIR=$(cargo metadata --locked --no-deps --format-version 1 |
  node -e 'let text = ""; process.stdin.setEncoding("utf8"); process.stdin.on("data", value => { text += value; }); process.stdin.on("end", () => { console.log(JSON.parse(text).target_directory); });')
export CARGO_TARGET_DIR
npm --prefix bindings/node ci --ignore-scripts
npm --prefix bindings/node run copy-native
npm --prefix bindings/node test
npm --prefix bindings/node run check-types
