#!/usr/bin/env bash

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

selected=$(
  scripts/ci/report-upstream-freshness.sh --select-latest <<'EOF'
{"vers":"0.9.99","cksum":"older","yanked":false,"rust_version":"1.70"}
{"vers":"0.10.0-rc.1","cksum":"prerelease","yanked":false,"rust_version":"1.80"}
{"vers":"0.10.0+build.7","cksum":"latest","yanked":false,"rust_version":"1.85"}
{"vers":"1.0.0","cksum":"yanked","yanked":true,"rust_version":"1.90"}
{"vers":"01.2.3","cksum":"invalid","yanked":false,"rust_version":"1.60"}
EOF
)
jq -e '
  (.vers | split("+")[0]) == "0.10.0"
  and .cksum == "latest"
  and .rust_version == "1.85"
' <<<"$selected" >/dev/null

only_prereleases=$(
  scripts/ci/report-upstream-freshness.sh --select-latest <<'EOF'
{"vers":"2.0.0-alpha.1","cksum":"alpha","yanked":false}
{"vers":"1.9.0","cksum":"yanked","yanked":true}
EOF
)
[[ "$only_prereleases" == null ]]
