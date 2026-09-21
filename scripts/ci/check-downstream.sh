#!/usr/bin/env bash
# Build a throwaway downstream consumer that declares Phantom with one
# dependency line and no [patch] table, then prove that Cargo resolved every
# patched dependency to Phantom's renamed fork and none to the stock package.
#
# Usage: check-downstream.sh [path|git|registry VERSION]...
#   path      phantom = { path = ... }             (vendored checkout layout)
#   git       phantom = { git = ..., rev = ... }   (from a local commit)
#   registry  phantom = "=VERSION"                 (after publishing)
# With no arguments, the path and git modes run.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_root=$(mktemp -d "${TMPDIR:-/tmp}/phantom-downstream.XXXXXX")

cleanup() {
  if [[ -n "${work_root:-}" && -d "$work_root" ]]; then
    rm -rf -- "$work_root"
  fi
}
trap cleanup EXIT HUP INT TERM

# Third-party dependencies are shared between modes; Phantom's own packages get
# distinct package IDs per source and rebuild.
export CARGO_TARGET_DIR="$work_root/target"

file_url() {
  if command -v cygpath >/dev/null 2>&1; then
    printf 'file:///%s' "$(cygpath -m "$1")"
  else
    printf 'file://%s' "$1"
  fi
}

# Copy exactly the checkout's tracked and non-ignored files, without .git or
# local target trees.
copy_checkout() {
  mkdir -p "$1"
  git -C "$repository_root" ls-files --cached --others --exclude-standard -z |
    tar --create --directory="$repository_root" --null --files-from=- |
    tar --extract --directory="$1"
}

write_consumer() {
  local consumer=$1 dependency=$2
  mkdir -p "$consumer/src"
  cat >"$consumer/Cargo.toml" <<EOF
[package]
name = "phantom-downstream-check"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
$dependency
EOF
  cat >"$consumer/src/main.rs" <<'EOF'
use phantom as _;

fn main() {}
EOF
}

assert_fork_graph() {
  local metadata=$1 expected_source=$2
  python3 - "$metadata" "$expected_source" <<'PY'
import json
import sys

metadata_path, expected_source = sys.argv[1], sys.argv[2]

# Stock packages that Phantom patches, or that would pull a patched package
# transitively. None of them may appear in a consumer graph.
stock = {
    "btls",
    "h3",
    "h3-datagram",
    "h3-quinn",
    "http2",
    "quinn",
    "quinn-proto",
    "tokio-btls",
    "tokio-tungstenite",
    "tungstenite",
    "wreq-proto",
}
forks = {f"phantom-{name}" for name in stock}
btls_sys_source = (
    "git+https://github.com/0xARYA/btls"
    "?rev=50e72407ac1f89cea14003004429ecf579541b6f"
    "#50e72407ac1f89cea14003004429ecf579541b6f"
)

with open(metadata_path, encoding="utf-8") as metadata_file:
    packages = json.load(metadata_file)["packages"]

def source_kind(source):
    if source is None:
        return "path"
    if source.startswith("git+"):
        return "git"
    if source.startswith("registry+"):
        return "registry"
    return source

failures = []
by_name = {}
for package in packages:
    by_name.setdefault(package["name"], []).append(package)

for name in sorted(stock & by_name.keys()):
    for package in by_name[name]:
        failures.append(f"stock package {name} {package['version']} resolved from {package['source']}")

for name in sorted(forks):
    resolved = by_name.get(name, [])
    if len(resolved) != 1:
        failures.append(f"expected exactly one {name}, found {len(resolved)}")
        continue
    kind = source_kind(resolved[0]["source"])
    if kind != expected_source:
        failures.append(f"{name} resolved from {kind}, expected {expected_source}")

btls_sys = by_name.get("btls-sys", [])
if [package["source"] for package in btls_sys] != [btls_sys_source]:
    failures.append(f"btls-sys did not resolve only from the reviewed fork: {btls_sys}")

for failure in failures:
    print(failure, file=sys.stderr)
raise SystemExit(1 if failures else 0)
PY
}

check_consumer() {
  local consumer=$1 expected_source=$2
  cargo generate-lockfile --manifest-path "$consumer/Cargo.toml"
  cargo metadata \
    --manifest-path "$consumer/Cargo.toml" \
    --format-version 1 \
    --all-features \
    --locked >"$consumer/metadata.json"
  assert_fork_graph "$consumer/metadata.json" "$expected_source"
  cargo check \
    --manifest-path "$consumer/Cargo.toml" \
    --all-features \
    --locked
  echo "downstream $expected_source consumer resolved only Phantom forks"
}

check_path() {
  local consumer="$work_root/path"
  copy_checkout "$consumer/vendor/phantom"
  write_consumer "$consumer" \
    'phantom = { path = "vendor/phantom/crates/phantom", features = ["full"] }'
  check_consumer "$consumer" path
}

check_git() {
  local consumer="$work_root/git" source="$work_root/git-source" revision
  copy_checkout "$source"
  git -C "$source" init --quiet
  git -C "$source" add --all --force
  git -C "$source" -c user.name=phantom -c user.email=phantom@invalid \
    -c commit.gpgsign=false commit --quiet --message snapshot
  revision=$(git -C "$source" rev-parse HEAD)
  write_consumer "$consumer" \
    "phantom = { git = \"$(file_url "$source")\", rev = \"$revision\", features = [\"full\"] }"
  check_consumer "$consumer" git
}

check_registry() {
  local version=$1 consumer="$work_root/registry"
  write_consumer "$consumer" \
    "phantom = { version = \"=$version\", features = [\"full\"] }"
  check_consumer "$consumer" registry
}

if [[ $# -eq 0 ]]; then
  set -- path git
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    path) check_path; shift ;;
    git) check_git; shift ;;
    registry)
      [[ $# -ge 2 ]] || { echo "registry mode needs a version" >&2; exit 2; }
      check_registry "$2"
      shift 2
      ;;
    *)
      echo "usage: $0 [path|git|registry VERSION]..." >&2
      exit 2
      ;;
  esac
done
