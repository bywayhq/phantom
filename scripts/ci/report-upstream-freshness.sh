#!/usr/bin/env bash

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

die() {
  echo "report-upstream-freshness: $*" >&2
  exit 1
}

fetch() {
  curl --fail --location --silent --show-error --retry 3 \
    --user-agent "phantom-upstream-freshness/1" "$1"
}

package_version() {
  awk '
    /^\[package\]$/ { package = 1; next }
    package && /^version = / {
      sub(/^[^"]*"/, "")
      sub(/".*/, "")
      print
      exit
    }
  ' "$1"
}

fixture_field() {
  local file=$1 key=$2 values count
  values=$(awk -v prefix="$key=" \
    'index($0, prefix) == 1 { print substr($0, length(prefix) + 1) }' "$file")
  count=$(printf '%s\n' "$values" | sed '/^$/d' | wc -l | tr -d ' ')
  [[ "$count" == 1 ]] || die "$file must contain one nonempty $key field"
  printf '%s\n' "$values"
}

select_latest_registry_record() {
  jq -sc '
    map(
      select(
        (.yanked | not)
        and (.vers | test(
          "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$"
        ))
      )
      | . + {
          _precedence: (
            .vers
            | capture(
              "^(?<major>0|[1-9][0-9]*)\\.(?<minor>0|[1-9][0-9]*)\\.(?<patch>0|[1-9][0-9]*)"
            )
            | [.major, .minor, .patch]
            | map(tonumber)
          )
        }
    )
    | max_by(._precedence)
    | del(._precedence)
  '
}

latest_registry_record() {
  fetch "$1" | select_latest_registry_record
}

latest_chrome_recipe() {
  local protocol=$1 description
  case "$protocol" in
    tls) description="TLS settings captured" ;;
    http2) description="HTTP/2 settings observed" ;;
    *) die "unknown Chrome recipe protocol $protocol" ;;
  esac

  sed -nE \
    "s|^/// Returns $description from Chrome ([0-9]+(\\.[0-9]+){3}) on macOS ([0-9]+(\\.[0-9]+)+)\\.$|\\1\tmacos-\\3|p" \
    crates/phantom-profile/src/chromium.rs \
    | jq -Rrs '
        split("\n")
        | map(select(length > 0) | split("\t"))
        | map({
            version: .[0],
            platform: .[1],
            precedence: (.[0] | split(".") | map(tonumber))
          })
        | max_by(.precedence)
        | [.version, .platform]
        | @tsv
      '
}

write_output() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  fi
}

if [[ "${1:-}" == --select-latest ]]; then
  select_latest_registry_record
  exit
fi

output_dir=${1:-target/upstream-freshness}
mkdir -p "$output_dir"

wreq_current=$(sed -nE 's/.*wreq-proto = "=([^"]+)".*/\1/p' \
  crates/phantom-net/Cargo.toml)
if [[ -n "$wreq_current" ]]; then
  wreq_tracked=true
  wreq_display=$wreq_current
else
  wreq_tracked=false
  wreq_display=untracked
fi

http2_current=$(package_version vendor/http2/Cargo.toml)
[[ -n "$http2_current" ]] || die "could not derive the vendored http2 version"

if [[ -d vendor/btls ]]; then
  [[ -f vendor/btls/PHANTOM.md ]] \
    || die "vendored btls is missing PHANTOM.md provenance"
  btls_revs=$(sed -nE \
    's/.*[Uu]pstream (revision|commit):? `?([0-9a-f]{40})`?.*/\2/p' \
    vendor/btls/PHANTOM.md | sort -u)
  [[ $(printf '%s\n' "$btls_revs" | sed '/^$/d' | wc -l | tr -d ' ') == 1 ]] \
    || die "vendored btls PHANTOM.md must name one exact upstream revision"
  btls_current=$btls_revs
  btls_provenance=vendored
  btls_probe_supported=true
  btls_probe_note="enabled from an exact upstream revision using canonical wrapper patches and the reviewed native-patch fork"
else
  btls_revs=$(sed -nE \
    's/^(btls|tokio-btls) = .*rev = "([0-9a-f]{40})".*/\2/p' Cargo.toml)
  [[ $(printf '%s\n' "$btls_revs" | sed '/^$/d' | wc -l | tr -d ' ') == 2 ]] \
    || die "btls and tokio-btls must each use an exact revision"
  [[ $(printf '%s\n' "$btls_revs" | sort -u | wc -l | tr -d ' ') == 1 ]] \
    || die "btls and tokio-btls must use the same revision"
  btls_current=$(printf '%s\n' "$btls_revs" | head -1)
  btls_provenance=git
  btls_probe_supported=true
  btls_probe_note="enabled for exact git revision"
fi

http2_record=$(latest_registry_record https://index.crates.io/ht/tp/http2)
[[ "$http2_record" != null ]] || die "the http2 index contains no stable release"
if [[ "$wreq_tracked" == true ]]; then
  wreq_record=$(latest_registry_record https://index.crates.io/wr/eq/wreq-proto)
  [[ "$wreq_record" != null ]] || die "the wreq-proto index contains no stable release"
  wreq_latest=$(jq -r .vers <<<"$wreq_record")
  wreq_checksum=$(jq -r .cksum <<<"$wreq_record")
  wreq_rust_version=$(jq -r '.rust_version // ""' <<<"$wreq_record")
  wreq_source=https://index.crates.io/wr/eq/wreq-proto
  wreq_upstream_display="\`$wreq_latest\` (MSRV \`${wreq_rust_version:-unspecified}\`)"
else
  wreq_latest=
  wreq_checksum=
  wreq_rust_version=
  wreq_source=
  wreq_upstream_display="not queried"
fi
http2_latest=$(jq -r .vers <<<"$http2_record")
http2_checksum=$(jq -r .cksum <<<"$http2_record")
http2_rust_version=$(jq -r '.rust_version // ""' <<<"$http2_record")

btls_latest=$(git ls-remote https://github.com/0x676e67/btls.git HEAD \
  | awk '$2 == "HEAD" { print $1 }')
[[ "$btls_latest" =~ ^[0-9a-f]{40}$ ]] || die "could not resolve the btls HEAD"

chrome_record=$(fetch \
  https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json)
chrome_latest=$(jq -r .channels.Stable.version <<<"$chrome_record")
chrome_revision=$(jq -r .channels.Stable.revision <<<"$chrome_record")
[[ "$chrome_latest" =~ ^[0-9]+(\.[0-9]+){3}$ ]] \
  || die "the official Chrome stable feed returned an invalid version"

tls_recipe=$(latest_chrome_recipe tls)
http2_recipe=$(latest_chrome_recipe http2)
[[ -n "$tls_recipe" && "$tls_recipe" == "$http2_recipe" ]] \
  || die "latest built-in Chrome TLS and HTTP/2 recipes must name one version/platform"
IFS=$'\t' read -r chrome_recipe_version chrome_platform <<<"$tls_recipe"
chrome_major=${chrome_recipe_version%%.*}
grep -F -q "pub fn v${chrome_major}_macos_tls()" \
  crates/phantom-profile/src/chromium.rs \
  || die "missing TLS function for the latest Chrome recipe"
grep -F -q "pub fn v${chrome_major}_macos_http2()" \
  crates/phantom-profile/src/chromium.rs \
  || die "missing HTTP/2 function for the latest Chrome recipe"

tls_fixture="fixtures/tls/chrome/$chrome_recipe_version/$chrome_platform/client-hello.txt"
http2_fixture="fixtures/http2/chrome/$chrome_recipe_version/$chrome_platform/pingly-api-all.txt"
[[ -f "$tls_fixture" ]] || die "missing exact Chrome TLS fixture $tls_fixture"
[[ -f "$http2_fixture" ]] || die "missing exact Chrome HTTP/2 fixture $http2_fixture"

chrome_os_version=${chrome_platform#macos-}
[[ $(fixture_field "$tls_fixture" format) == phantom-client-hello-v2 ]] \
  || die "$tls_fixture has an unexpected format"
[[ $(fixture_field "$tls_fixture" browser_version) == "$chrome_recipe_version" ]] \
  || die "$tls_fixture does not match the built-in Chrome version"
tls_os=$(fixture_field "$tls_fixture" operating_system)
[[ "${tls_os%% (*}" == "macOS $chrome_os_version" ]] \
  || die "$tls_fixture does not match the built-in Chrome platform"
[[ $(fixture_field "$http2_fixture" format) == phantom-pingly-http2-v1 ]] \
  || die "$http2_fixture has an unexpected format"
[[ $(fixture_field "$http2_fixture" browser) == "Google Chrome $chrome_recipe_version" ]] \
  || die "$http2_fixture does not match the built-in Chrome version"
http2_os=$(fixture_field "$http2_fixture" os)
[[ "${http2_os%% (*}" == "macOS $chrome_os_version" ]] \
  || die "$http2_fixture does not match the built-in Chrome platform"

if [[ "$wreq_tracked" == true && "$wreq_current" != "$wreq_latest" ]]; then
  wreq_drift=true
else
  wreq_drift=false
fi
[[ "$http2_current" == "$http2_latest" ]] && http2_drift=false || http2_drift=true
[[ "$btls_current" == "$btls_latest" ]] && btls_drift=false || btls_drift=true
if [[ "$chrome_recipe_version" == "$chrome_latest" ]]; then
  chrome_drift=false
else
  chrome_drift=true
fi
if [[ "$wreq_drift" == true || "$http2_drift" == true \
  || "$btls_drift" == true || "$chrome_drift" == true ]]; then
  any_drift=true
else
  any_drift=false
fi

checked_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -n \
  --arg checked_at "$checked_at" \
  --arg wreq_current "$wreq_current" \
  --arg wreq_latest "$wreq_latest" \
  --arg wreq_checksum "$wreq_checksum" \
  --arg wreq_rust_version "$wreq_rust_version" \
  --arg wreq_source "$wreq_source" \
  --argjson wreq_tracked "$wreq_tracked" \
  --argjson wreq_drift "$wreq_drift" \
  --arg http2_current "$http2_current" \
  --arg http2_latest "$http2_latest" \
  --arg http2_checksum "$http2_checksum" \
  --arg http2_rust_version "$http2_rust_version" \
  --argjson http2_drift "$http2_drift" \
  --arg btls_current "$btls_current" \
  --arg btls_latest "$btls_latest" \
  --arg btls_provenance "$btls_provenance" \
  --arg btls_probe_note "$btls_probe_note" \
  --argjson btls_probe_supported "$btls_probe_supported" \
  --argjson btls_drift "$btls_drift" \
  --arg chrome_latest "$chrome_latest" \
  --arg chrome_revision "$chrome_revision" \
  --argjson chrome_drift "$chrome_drift" \
  --arg chrome_recipe_version "$chrome_recipe_version" \
  --arg chrome_platform "$chrome_platform" \
  --arg tls_fixture "$tls_fixture" \
  --arg http2_fixture "$http2_fixture" \
  --argjson any_drift "$any_drift" \
  '{
    checked_at: $checked_at,
    dependencies: {
      "wreq-proto": {
        tracked: $wreq_tracked,
        current: ($wreq_current | if length == 0 then null else . end),
        latest_non_yanked: ($wreq_latest | if length == 0 then null else . end),
        checksum: ($wreq_checksum | if length == 0 then null else . end),
        rust_version: ($wreq_rust_version | if length == 0 then null else . end),
        drift: $wreq_drift,
        source: ($wreq_source | if length == 0 then null else . end)
      },
      http2: {
        current: $http2_current,
        latest_non_yanked: $http2_latest,
        checksum: $http2_checksum,
        rust_version: ($http2_rust_version | if length == 0 then null else . end),
        drift: $http2_drift,
        source: "https://index.crates.io/ht/tp/http2"
      },
      btls: {
        current: $btls_current,
        upstream_head: $btls_latest,
        provenance: $btls_provenance,
        candidate_probe_supported: $btls_probe_supported,
        candidate_probe_note: $btls_probe_note,
        drift: $btls_drift,
        source: "https://github.com/0x676e67/btls"
      }
    },
    browser_fixtures: {
      chrome: {
        recipe_version: $chrome_recipe_version,
        platform: $chrome_platform,
        tls_fixture: $tls_fixture,
        http2_fixture: $http2_fixture,
        fixture_metadata_matches_recipe: true,
        official_stable: $chrome_latest,
        official_revision: $chrome_revision,
        drift: $chrome_drift,
        source: "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
      }
    },
    drift: $any_drift
  }' > "$output_dir/report.json"

cat > "$output_dir/summary.md" <<EOF
# Upstream freshness

Checked at \`$checked_at\`. A drift signal is a review prompt, not approval to
change a dependency or browser fingerprint.

| Source | Repository state | Upstream state | Drift |
| --- | --- | --- | --- |
| wreq-proto | \`$wreq_display\` | $wreq_upstream_display | $wreq_drift |
| vendored http2 | \`$http2_current\` | \`$http2_latest\` (MSRV \`${http2_rust_version:-unspecified}\`) | $http2_drift |
| btls ($btls_provenance) | \`$btls_current\` | \`$btls_latest\` | $btls_drift |
| Chrome $chrome_platform | recipe + exact TLS/H2 fixtures \`$chrome_recipe_version\` | stable \`$chrome_latest\` (revision \`$chrome_revision\`) | $chrome_drift |

Registry checksums and exact fixture paths are in \`report.json\`.
Browser drift requires a reviewed browser capture and packet differential; this
workflow never rewrites profiles or fixtures.

btls candidate probe: $btls_probe_note.
EOF

write_output wreq_latest "$wreq_latest"
write_output wreq_checksum "$wreq_checksum"
write_output wreq_drift "$wreq_drift"
write_output http2_latest "$http2_latest"
write_output http2_checksum "$http2_checksum"
write_output http2_drift "$http2_drift"
write_output btls_latest "$btls_latest"
write_output btls_drift "$btls_drift"
write_output btls_probe_supported "$btls_probe_supported"
write_output chrome_drift "$chrome_drift"
write_output any_drift "$any_drift"

cat "$output_dir/summary.md"
