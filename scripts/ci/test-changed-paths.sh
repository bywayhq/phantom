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

doc='code=false doctests=false'
doctest='code=false doctests=true'
code='code=true doctests=true'

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

# Every Markdown file rustdoc includes must at least run the doctest job.
# Prints the repository path for a path relative to crates/phantom/src.
hook_path() {
  local part
  local -a parts=() resolved=(crates phantom src)
  IFS=/ read -ra parts <<<"$1"
  for part in "${parts[@]}"; do
    case $part in
      '' | .) ;;
      ..)
        ((${#resolved[@]} > 0)) || return 1
        unset 'resolved[-1]'
        ;;
      *) resolved+=("$part") ;;
    esac
  done
  (IFS=/ && printf '%s\n' "${resolved[*]}")
}
hooks=0
while IFS= read -r relative; do
  path=$(hook_path "$relative")
  hooks=$((hooks + 1))
  if [[ $("$classifier" --classify "$path" | sed -n 's/^doctests=//p') != true ]]; then
    printf 'FAILED: rustdoc hook %s is not classified as a doctest source\n' "$path" >&2
    failures=$((failures + 1))
  fi
done < <(sed -nE 's/^#\[doc = include_str!\("([^"]+\.md)"\)\][[:space:]]*$/\1/p' crates/phantom/src/lib.rs)
if ((hooks == 0)); then
  echo "FAILED: found no rustdoc Markdown hooks in crates/phantom/src/lib.rs" >&2
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

if ((failures > 0)); then
  printf '%d path classification checks failed\n' "$failures" >&2
  exit 1
fi
echo "path classification checks passed"
