#!/usr/bin/env bash
# Package or publish Phantom's renamed dependency forks and its own crates in
# dependency order.
#
# Usage: publish-crates.sh [--list|--publish]
#   --list     (default) list each package's contents; publishes nothing
#   --publish  publish every package with `cargo publish --locked`; requires
#              CARGO_REGISTRY_TOKEN and is intended only for release.yml
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repository_root"
mode=${1:---list}

die() {
  echo "publish-crates: $*" >&2
  exit 1
}

# Bottom-up publication order: every package appears after its dependencies.
manifests=(
  vendor/btls/Cargo.toml
  vendor/tokio-btls/Cargo.toml
  vendor/quinn-proto/Cargo.toml
  vendor/quinn/Cargo.toml
  vendor/h3/h3/Cargo.toml
  vendor/h3/h3-datagram/Cargo.toml
  vendor/h3/h3-quinn/Cargo.toml
  vendor/http2/Cargo.toml
  vendor/wreq-proto/Cargo.toml
  vendor/tungstenite/Cargo.toml
  vendor/tokio-tungstenite/Cargo.toml
  crates/phantom-profile/Cargo.toml
  crates/phantom-quic-btls/Cargo.toml
  crates/phantom-net/Cargo.toml
  crates/phantom/Cargo.toml
)

case "$mode" in
  --list)
    for manifest in "${manifests[@]}"; do
      echo "== $manifest"
      cargo package --list --allow-dirty --manifest-path "$manifest"
    done
    ;;
  --publish)
    [[ -n "${CARGO_REGISTRY_TOKEN:-}" ]] || die "CARGO_REGISTRY_TOKEN is required"
    [[ -z $(git status --porcelain) ]] || die "refusing to publish from a dirty checkout"
    # crates.io rejects git dependencies. btls-sys still resolves from the
    # reviewed fork by git, so publication must stay blocked until it is
    # published under a Phantom name.
    if grep -F -q 'btls-sys = { git = ' Cargo.toml vendor/btls/Cargo.toml; then
      die "btls-sys is still a git dependency; publish it under a Phantom name first"
    fi
    for manifest in "${manifests[@]}"; do
      echo "== publishing $manifest"
      cargo publish --locked --manifest-path "$manifest"
    done
    ;;
  *)
    die "usage: $0 [--list|--publish]"
    ;;
esac
