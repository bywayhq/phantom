#!/usr/bin/env bash
# Package or publish Phantom's renamed dependency forks and its own crates in
# dependency order.
#
# Usage: publish-crates.sh [--list|--preflight|--verify|--publish] [arguments]
#   --list     (default) list each package's contents; publishes nothing
#   --publish  publish every package with `cargo publish --locked`; requires
#              CARGO_REGISTRY_TOKEN and is intended only for release.yml
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repository_root"
mode=${1:---list}
if [[ $# -gt 0 ]]; then shift; fi
lock="$repository_root/scripts/dev/with-cargo-lock.sh"

die() {
  echo "publish-crates: $*" >&2
  exit 1
}

# Bottom-up publication order: every package appears after its dependencies.
manifests=()
while IFS= read -r manifest; do manifests+=("$manifest"); done < scripts/release/packages.txt

case "$mode" in
  --list)
    for manifest in "${manifests[@]}"; do
      echo "== $manifest"
      "$lock" cargo package --list --allow-dirty --manifest-path "$manifest"
    done
    ;;
  --verify)
    exec "$lock" python3 scripts/release/verify-packages.py "$@"
    ;;
  --preflight)
    exec "$lock" python3 scripts/release/publish.py
    ;;
  --publish)
    [[ -n "${CARGO_REGISTRY_TOKEN:-}" ]] || die "CARGO_REGISTRY_TOKEN is required"
    [[ -z $(git status --porcelain) ]] || die "refusing to publish from a dirty checkout"
    if grep -F -q 'btls-sys = { git = ' Cargo.toml vendor/btls/Cargo.toml; then
      die "btls-sys is still a git dependency; publish it under a Phantom name first"
    fi
    exec "$lock" python3 scripts/release/publish.py --publish
    ;;
  *)
    die "usage: $0 [--list|--preflight|--verify|--publish] [arguments]"
    ;;
esac
