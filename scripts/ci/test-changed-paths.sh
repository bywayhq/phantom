#!/usr/bin/env bash
# Check the CI path classification in changed-paths.sh.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
classifier="$repo_root/scripts/ci/changed-paths.sh"

failures=0

expect() {
  local expected=$1 actual
  shift
  actual=$("$classifier" --classify "$@" | paste -sd ' ' -)
  if [[ $actual != "$expected" ]]; then
    printf 'FAILED: %s -> %s, expected %s\n' "${*:-<no paths>}" "$actual" "$expected" >&2
    failures=$((failures + 1))
  fi
}

doc='code=false doctests=false core=false'
doctest='code=false doctests=true core=false'
binding='code=true doctests=true core=false'
code='code=true doctests=true core=true'

# Documentation only.
expect "$doc" CONTRIBUTING.md
expect "$doc" AGENTS.md CLAUDE.md SECURITY.md
expect "$doc" docs/README.md docs/reference/coverage.md docs/explanation/design.md
expect "$doc" 'docs/reference/a file with spaces.md'
expect "$doc" docs/images/diagram.svg
expect "$doc" scripts/capture/README.md scripts/dev/README.md
expect "$doc" .github/pull_request_template.md .github/CODEOWNERS
expect "$doc" .github/ISSUE_TEMPLATE/bug_report.yml .github/ISSUE_TEMPLATE/config.yml
expect "$doc" .claude/skills/lane/SKILL.md
expect "$doc" LICENSE-APACHE LICENSE-MIT

# Markdown compiled as doctests by crates/phantom/src/lib.rs.
expect "$doctest" README.md
expect "$doctest" docs/getting-started.md
expect "$doctest" docs/guides/client.md
expect "$doctest" docs/guides/new-guide.md
expect "$doctest" docs/reference/fingerprint-import.md
expect "$doctest" docs/reference/limits.md docs/reference/fingerprint-import.md
expect "$doctest" CONTRIBUTING.md README.md docs/reference/limits.md

# Code, including Markdown inside package, fixture, fuzz, and vendored trees.
expect "$code"
expect "$code" crates/phantom/src/lib.rs
expect "$code" crates/phantom-net/README.md
expect "$code" vendor/h3/PHANTOM.md
expect "$code" vendor/tungstenite/CHANGELOG.md
expect "$code" fixtures/http3/README.md
expect "$code" fuzz/README.md
expect "$code" Cargo.toml Cargo.lock rust-toolchain.toml deny.toml
expect "$code" .github/workflows/ci.yml .github/dependabot.yml .gitattributes
expect "$code" scripts/ci/changed-paths.sh scripts/requirements.txt
expect "$code" LICENSE-MIT.rs
expect "$code" docs/README.md crates/phantom/src/lib.rs README.md
expect "$code" README.md docs/guides/client.md Cargo.lock

# Only known binding sources skip core Features and Vendor. Manifests,
# builders, new file kinds and other verification tools remain full code.
for path in bindings/node/src/ffi.rs bindings/node/src/profile/tests.rs \
  bindings/node/index.cjs bindings/node/index.mjs bindings/node/index.d.ts \
  bindings/node/index.d.cts bindings/node/index.d.mts \
  bindings/node/tests/client.test.cjs bindings/node/tests/types.cts \
  bindings/node/tests/types.mts bindings/python/src/response.rs \
  bindings/python/python/phantom_http/__init__.py \
  bindings/python/python/phantom_http/_native.pyi \
  bindings/python/python/phantom_http/py.typed \
  bindings/python/tests/typing/client_usage.py \
  bindings/go/client.go bindings/go/client_test.go \
  bindings/go/native/src/operations/tests.rs; do
  expect "$binding" "$path"
done
for path in bindings/node/Cargo.toml bindings/python/Cargo.toml \
  bindings/go/native/Cargo.toml bindings/go/native/Cargo.lock \
  bindings/node/build.rs bindings/node/src/build.rs \
  bindings/node/package.json bindings/node/package-lock.json \
  bindings/python/pyproject.toml bindings/go/go.mod bindings/go/go.sum \
  bindings/node/scripts/copy-native.cjs bindings/node/new-file.ts \
  bindings/node/tests/configuration.json bindings/python/new-helper.py \
  bindings/go/new-format.json scripts/dev/check-node-binding.sh \
  scripts/release/node_artifact.py scripts/dev/gate.sh \
  bindings/node/src/../Cargo.toml /bindings/node/src/client.rs; do
  expect "$code" "$path"
done
expect "$binding" bindings/node/index.cjs bindings/python/src/client.rs CHANGELOG.md
expect "$code" bindings/node/index.cjs crates/phantom/src/client.rs
expect "$code" crates/phantom/src/client.rs bindings/node/index.cjs
expect "$code" bindings/node/index.cjs Cargo.lock
expect "$code" Cargo.lock bindings/node/index.cjs

# Every file that crates/ or fuzz/ compile in with include_str! or
# include_bytes! must be classified as code or as a doctest source; a
# documentation-only change to it would otherwise skip the jobs that build
# it. The scanner prints one tab-separated line per include:
#   file <path> <location>      a fully resolved repository path
#   prefix <path> <location>    the literal prefix before a macro argument
#   unresolved <location>       a form this scanner cannot resolve
# shellcheck disable=SC2016 # Perl source, not shell.
include_scanner='
use strict;
use warnings;

local $/ = "\0";
my $string = qr/"(?:[^"\\]|\\.)*"/s;

sub parent {
  my ($path) = @_;
  return $path =~ m{^(.*)/[^/]*$} ? $1 : "";
}

# Collapses . and .. segments; undef when the path leaves the repository.
sub normalize {
  my ($path) = @_;
  my @parts;
  for my $part (split m{/}, $path) {
    next if $part eq "" || $part eq ".";
    if ($part eq "..") {
      return undef unless @parts;
      pop @parts;
    } else {
      push @parts, $part;
    }
  }
  return join "/", @parts;
}

sub manifest_dir {
  my ($dir) = @_;
  while ($dir ne "") {
    return $dir if -f "$dir/Cargo.toml";
    $dir = parent($dir);
  }
  return undef;
}

sub literal {
  my ($quoted) = @_;
  my $value = substr $quoted, 1, -1;
  return $value =~ /\\/ ? undef : $value;
}

while (my $file = <STDIN>) {
  chomp $file;
  open my $handle, "<", $file or die "$file: $!\n";
  my $source = do { local $/; <$handle> };
  close $handle;
  $source =~ s/\r\n/\n/g;

  while ($source =~ /\binclude_(?:str|bytes)!\s*(\((?:[^()"]++|$string|(?1))*+\))/g) {
    my $arguments = substr $1, 1, -1;
    my $line = 1 + (substr($source, 0, $-[0]) =~ tr/\n//);
    my $location = "$file:$line";
    $arguments =~ s/^\s+|[\s,]+$//g;

    my ($base, $relative, $variable);
    if ($arguments =~ /^$string$/) {
      $base = parent($file);
      $relative = literal($arguments);
    } elsif ($arguments =~ /^concat!\s*\((.*)\)$/s) {
      my $items = $1;
      $items =~ s/[\s,]+$//;
      $base = parent($file);
      $relative = "";
      my $first = 1;
      while ($items =~ /\G\s*(env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)|$string|\$[A-Za-z_]\w*|\$\((?s:.*))\s*(?:,|$)/gc) {
        my $item = $1;
        if ($item =~ /^env!/) {
          $base = $first ? manifest_dir(parent($file)) : undef;
          $relative = "";
        } elsif ($item =~ /^\$/) {
          $variable = 1;
          last;
        } else {
          my $value = literal($item);
          $relative = defined $value && defined $relative ? $relative . $value : undef;
        }
        $first = 0;
      }
      $relative = undef unless $variable || (pos($items) // 0) == length $items;
    }

    my $path = defined $base && defined $relative ? normalize("$base/$relative") : undef;
    if (!defined $path) {
      print "unresolved\t$location\t\n";
    } elsif ($variable) {
      $path .= "/" if $relative =~ m{/$} || $relative eq "";
      print "prefix\t$path\t$location\n";
    } else {
      print "file\t$path\t$location\n";
    }
  }
}
'
includes=$(git ls-files -z --cached --others --exclude-standard -- 'crates/*.rs' 'fuzz/*.rs' |
  perl -e "$include_scanner")
include_count=0
readme_included=false
while IFS=$'\t' read -r kind target location; do
  [[ -n $kind ]] || continue
  include_count=$((include_count + 1))
  candidates=()
  case $kind in
    file)
      if [[ ! -f $target ]]; then
        printf 'FAILED: %s includes missing file %s\n' "$location" "$target" >&2
        failures=$((failures + 1))
      fi
      [[ $target != README.md ]] || readme_included=true
      candidates=("$target")
      ;;
    prefix)
      candidates=("${target}placeholder" "${target}placeholder.md")
      ;;
    *)
      printf 'FAILED: cannot resolve the include at %s\n' "$target" >&2
      failures=$((failures + 1))
      ;;
  esac
  for candidate in ${candidates[@]+"${candidates[@]}"}; do
    class=$("$classifier" --classify "$candidate" | paste -sd ' ' -)
    if [[ $class != "$code" && $class != "$doctest" ]]; then
      printf 'FAILED: %s includes %s, which skips core and doctest coverage\n' \
        "${location:-$target}" "$candidate" >&2
      failures=$((failures + 1))
    fi
  done
done <<<"$includes"
# Each textual mention must be an include the scanner parsed, so a form it
# does not recognize fails here instead of going unchecked.
include_mentions=$(git ls-files -z --cached --others --exclude-standard -- 'crates/*.rs' 'fuzz/*.rs' |
  xargs -0 grep -ho 'include_\(str\|bytes\)!' | wc -l)
if ((include_mentions != include_count)); then
  printf 'FAILED: found %d include macros but parsed %d\n' "$include_mentions" "$include_count" >&2
  failures=$((failures + 1))
fi
if ((include_count == 0)) || [[ $readme_included != true ]]; then
  echo "FAILED: the include scan did not find the README.md rustdoc hook" >&2
  failures=$((failures + 1))
fi

# The git mode lists both sides of a rename and does not quote paths.
work_root=$(mktemp -d "${TMPDIR:-/tmp}/phantom-changed-paths.XXXXXX")
trap 'rm -rf -- "$work_root"' EXIT
git_test() {
  git -C "$work_root" -c user.name=test -c user.email=test@invalid \
    -c commit.gpgsign=false -c core.autocrlf=false "$@"
}
git_test init --quiet
mkdir -p "$work_root/crates/example" "$work_root/docs/guides"
printf 'fn main() {}\n' >"$work_root/crates/example/main.rs"
printf '# Notes\n' >"$work_root/docs/notes.md"
git_test add --all
git_test commit --quiet --message base
base=$(git_test rev-parse HEAD)

expect_diff() {
  local expected=$1 from=$2 to=$3 actual
  actual=$(cd "$work_root" && "$classifier" "$from" "$to" | paste -sd ' ' -)
  if [[ $actual != "$expected" ]]; then
    printf 'FAILED: git diff %s -> %s, expected %s\n' "$4" "$actual" "$expected" >&2
    failures=$((failures + 1))
  fi
}

printf '# Notes\n\nMore.\n' >"$work_root/docs/notes.md"
printf '# Notes\n' >"$work_root/docs/"$'caf\xc3\xa9.md'
git_test add --all
git_test commit --quiet --message docs
expect_diff "$doc" "$base" HEAD 'docs edit with a non-ASCII name'

printf '# Guide\n' >"$work_root/docs/guides/new.md"
git_test add --all
git_test commit --quiet --message guide
expect_diff "$doctest" HEAD~1 HEAD 'new guide'

git_test mv crates/example/main.rs docs/main.md
git_test commit --quiet --message move
expect_diff "$code" HEAD~1 HEAD 'code moved into docs'

mkdir -p "$work_root/bindings/node/src"
git_test mv docs/main.md bindings/node/src/client.rs
git_test commit --quiet --message 'move documentation into binding'
expect_diff "$binding" HEAD~1 HEAD 'binding added from documentation'
git_test mv bindings/node/src/client.rs crates/example/main.rs
git_test commit --quiet --message 'move binding into core'
expect_diff "$code" HEAD~1 HEAD 'binding moved into core'
git_test mv crates/example/main.rs bindings/node/src/client.rs
git_test commit --quiet --message 'move core into binding'
expect_diff "$code" HEAD~1 HEAD 'core moved into binding'
git_test rm --quiet bindings/node/src/client.rs
git_test commit --quiet --message 'remove binding'
expect_diff "$binding" HEAD~1 HEAD 'binding removed'

git_test commit --quiet --allow-empty --message empty
expect_diff "$code" HEAD~1 HEAD 'empty change set'

if (cd "$work_root" && "$classifier" "$base" not-a-revision) >/dev/null 2>&1; then
  echo "FAILED: an unknown revision was accepted" >&2
  failures=$((failures + 1))
fi
if "$classifier" >/dev/null 2>&1; then
  echo "FAILED: missing arguments were accepted" >&2
  failures=$((failures + 1))
fi

# Exercise the actual required-job guard, not a second policy implementation.
# A changed command layout fails extraction instead of silently skipping it.
workflow="$repo_root/.github/workflows/ci.yml"
required_filter=$(awk '
  /jq --exit-status --raw-output --arg event/ { inside = 1; count++; next }
  inside && / <<<"\$NEEDS"/ { inside = 0; next }
  inside { print }
  END { if (count != 1 || inside) exit 1 }
' "$workflow")
[[ -n $required_filter ]] || { echo 'FAILED: missing required-job guard' >&2; exit 1; }
everything=$(sed -n "s/^          everything=//p" "$workflow")
[[ -n $everything ]] || { echo 'FAILED: missing full-run fallback' >&2; exit 1; }
fallback=$(bash -c "printf '%s\\n' $everything" | paste -sd ' ' -)
if [[ $fallback != "$code" ]]; then
  echo 'FAILED: schedule/manual/missing-push fallback must enable every class' >&2
  failures=$((failures + 1))
fi

full_needs=$(jq -n '{
  changes: {result: "success", outputs: {code: "true", doctests: "true", core: "true"}},
  docs: {result: "success"}, quality: {result: "success"},
  features: {result: "success"}, downstream: {result: "success"},
  vendor: {result: "success"}, platform: {result: "success"}, msrv: {result: "success"}
}')
binding_needs=$(jq '.changes.outputs.core = "false" | .features.result = "skipped" |
  .vendor.result = "skipped"' <<<"$full_needs")
doc_needs=$(jq '.changes.outputs = {code: "false", doctests: "false", core: "false"} |
  .quality.result = "skipped" | .features.result = "skipped" |
  .downstream.result = "skipped" | .vendor.result = "skipped" |
  .platform.result = "skipped" | .msrv.result = "skipped"' <<<"$full_needs")
expect_required() {
  local expected=$1 input=$2 event=${3:-pull_request} actual=fail
  if jq --exit-status --raw-output --arg event "$event" "$required_filter" \
    <<<"$input" >/dev/null 2>&1; then actual=pass; fi
  if [[ $actual != "$expected" ]]; then
    echo "FAILED: required-job guard expected $expected for $event: $input" >&2
    failures=$((failures + 1))
  fi
}
expect_required pass "$full_needs"
expect_required pass "$binding_needs"
expect_required pass "$doc_needs"
for event in schedule workflow_dispatch; do
  expect_required pass "$full_needs" "$event"
  expect_required fail "$binding_needs" "$event"
done
for job in quality downstream platform msrv; do
  for result in skipped failure cancelled; do
    expect_required fail "$(jq --arg job "$job" --arg result "$result" \
      '.[$job].result = $result' <<<"$binding_needs")"
  done
done
for field in code doctests core; do
  expect_required fail "$(jq --arg field "$field" 'del(.changes.outputs[$field])' <<<"$doc_needs")"
  expect_required fail "$(jq --arg field "$field" '.changes.outputs[$field] = "invalid"' <<<"$doc_needs")"
done
expect_required fail "$(jq '.changes.outputs.code = "false" | .downstream.result = "skipped" |
  .platform.result = "skipped" | .msrv.result = "skipped"' <<<"$full_needs")"
expect_required fail "$(jq '.changes.outputs.doctests = "false" |
  .quality.result = "skipped"' <<<"$binding_needs")"
expect_required fail "$(jq 'del(.platform)' <<<"$binding_needs")"
expect_required fail "$(jq '.unexpected = {result: "success"}' <<<"$binding_needs")"
expect_required fail "$(jq '.features.result = "skipped"' <<<"$full_needs")"
expect_required fail "$(jq '.vendor.result = "success"' <<<"$binding_needs")"

if ((failures > 0)); then
  printf '%d path classification checks failed\n' "$failures" >&2
  exit 1
fi
echo "path classification checks passed"
