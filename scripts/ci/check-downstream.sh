#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
consumer_root=$(mktemp -d "${TMPDIR:-/tmp}/phantom-downstream.XXXXXX")

cleanup() {
  if [[ -n "${consumer_root:-}" && -d "$consumer_root" ]]; then
    rm -rf -- "$consumer_root"
  fi
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$consumer_root/vendor/phantom" "$consumer_root/src"

# Copy exactly the checkout's tracked and non-ignored files. This models the
# documented vendored layout without pulling .git or any local target trees
# into the temporary consumer root.
git -C "$repository_root" ls-files --cached --others --exclude-standard -z |
  tar --null --files-from=- --create --directory="$repository_root" |
  tar --extract --directory="$consumer_root/vendor/phantom"

cat >"$consumer_root/Cargo.toml" <<'EOF'
[package]
name = "phantom-downstream-check"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
phantom = { path = "vendor/phantom/crates/phantom", features = ["full"] }

[patch.crates-io]
h3 = { path = "vendor/phantom/vendor/h3/h3" }
h3-datagram = { path = "vendor/phantom/vendor/h3/h3-datagram" }
h3-quinn = { path = "vendor/phantom/vendor/h3/h3-quinn" }
http2 = { path = "vendor/phantom/vendor/http2" }
quinn-proto = { path = "vendor/phantom/vendor/quinn-proto" }
tungstenite = { path = "vendor/phantom/vendor/tungstenite" }
wreq-proto = { path = "vendor/phantom/vendor/wreq-proto" }

[patch."https://github.com/0xARYA/btls"]
btls = { path = "vendor/phantom/vendor/btls" }
EOF

cat >"$consumer_root/src/main.rs" <<'EOF'
use phantom as _;

fn main() {}
EOF

cargo generate-lockfile --manifest-path "$consumer_root/Cargo.toml"
cargo metadata \
  --manifest-path "$consumer_root/Cargo.toml" \
  --format-version 1 \
  --all-features \
  --locked >"$consumer_root/metadata.json"

python3 - "$consumer_root/metadata.json" <<'PY'
import json
import sys

expected = {
    "phantom",
    "btls",
    "h3",
    "h3-datagram",
    "h3-quinn",
    "http2",
    "quinn-proto",
    "tungstenite",
    "wreq-proto",
}

with open(sys.argv[1], encoding="utf-8") as metadata_file:
    packages = json.load(metadata_file)["packages"]

resolved = {package["name"] for package in packages}
missing = sorted(expected - resolved)
non_path = sorted(
    (package["name"], package["source"])
    for package in packages
    if package["name"] in expected and package["source"] is not None
)

if missing or non_path:
    if missing:
        print(f"missing expected packages: {', '.join(missing)}", file=sys.stderr)
    for name, source in non_path:
        print(f"{name} did not resolve from a path: {source}", file=sys.stderr)
    raise SystemExit(1)
PY

cargo check \
  --manifest-path "$consumer_root/Cargo.toml" \
  --all-features \
  --locked
