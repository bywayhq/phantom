#!/usr/bin/env bash
# Classify the repository paths a change touches so CI can skip jobs that the
# change cannot affect. Prints GitHub Actions step outputs:
#
#   code=true|false      true when any changed path is outside the
#                        documentation set; every CI job then runs.
#   doctests=true|false  true when code changed or when a Markdown file that
#                        rustdoc compiles as doctests changed; the job that
#                        runs `cargo test` and `cargo doc` then runs.
#
# Usage:
#   changed-paths.sh BASE HEAD           classify `git diff BASE HEAD`
#   changed-paths.sh --classify [PATH]...  classify the given paths
#
# An empty change set counts as code, so an unexpected diff never skips a job.
set -euo pipefail

usage() {
  echo "usage: $0 BASE HEAD | --classify [PATH]..." >&2
  exit 2
}

# Sets path_class to doctest, doc, or code for one repository-relative path.
# Anything not listed as documentation is code. The doctest entries must cover
# every `#[doc = include_str!(...)]` hook in crates/phantom/src/lib.rs;
# test-changed-paths.sh enforces that.
classify_path() {
  case $1 in
    README.md | docs/getting-started.md | docs/guides/*)
      path_class=doctest
      ;;
    # Markdown in these trees is package content, fixture provenance, or
    # vendored provenance read by the vendor checks.
    crates/* | fixtures/* | fuzz/* | vendor/*)
      path_class=code
      ;;
    *.md | docs/* | LICENSE-APACHE | LICENSE-MIT | \
      .github/CODEOWNERS | .github/ISSUE_TEMPLATE/*)
      path_class=doc
      ;;
    *)
      path_class=code
      ;;
  esac
}

classify() {
  local code=false doctests=false path path_class
  if (($# == 0)); then
    code=true
  fi
  for path in "$@"; do
    classify_path "$path"
    case $path_class in
      code)
        code=true
        break
        ;;
      doctest)
        doctests=true
        ;;
    esac
  done
  if [[ $code == true ]]; then
    doctests=true
  fi
  printf 'code=%s\ndoctests=%s\n' "$code" "$doctests"
}

classify_diff() {
  local base head path
  local -a paths=()
  base=$(git rev-parse --verify --quiet --end-of-options "$1^{commit}") ||
    { echo "error: not a commit: $1" >&2; exit 1; }
  head=$(git rev-parse --verify --quiet --end-of-options "$2^{commit}") ||
    { echo "error: not a commit: $2" >&2; exit 1; }

  diff_file=$(mktemp)
  trap 'rm -f -- "$diff_file"' EXIT
  # Without rename detection a moved file lists both its old and new path, so
  # moving code into docs/ still counts as a code change.
  git diff --name-only --no-renames -z "$base" "$head" -- >"$diff_file"
  while IFS= read -r -d '' path; do
    paths+=("$path")
  done <"$diff_file"
  classify ${paths[@]+"${paths[@]}"}
}

if (($# >= 1)) && [[ $1 == --classify ]]; then
  shift
  classify "$@"
elif (($# == 2)); then
  classify_diff "$1" "$2"
else
  usage
fi
