#!/usr/bin/env bash
# Classify the repository paths a change touches so CI can skip jobs that the
# change cannot affect. Prints GitHub Actions step outputs:
#
#   code=true|false      true when any changed path is outside the
#                        documentation set; binding and workspace jobs run.
#   doctests=true|false  true when code changed or when a Markdown file that
#                        rustdoc compiles as doctests changed; the job that
#                        runs `cargo test` and `cargo doc` then runs.
#   core=true|false      true unless only documentation or known binding
#                        implementation/test sources changed; runs Features
#                        and Vendor in addition to the other code jobs.
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

# Sets path_class to doctest, doc, binding, or code for one relative path.
# Anything not listed as documentation is code. The doctest entries must cover
# every `#[doc = include_str!(...)]` hook in crates/phantom/src/lib.rs;
# test-changed-paths.sh enforces that.
classify_path() {
  case $1 in
    # Unknown files, build inputs and noncanonical paths must not acquire the
    # binding-only exception through a broader source or test glob below.
    /* | ./* | ../* | */../* | */./* | *\\* | \
      */Cargo.toml | */Cargo.lock | */build.rs | */package.json | \
      */package-lock.json | */go.mod | */go.sum | */pyproject.toml)
      path_class=code
      ;;
    bindings/node/src/*.rs | bindings/node/tests/*.cjs | \
      bindings/node/tests/*.cts | bindings/node/tests/*.mts | \
      bindings/node/index.cjs | bindings/node/index.mjs | \
      bindings/node/index.d.ts | bindings/node/index.d.cts | bindings/node/index.d.mts | \
      bindings/python/src/*.rs | bindings/python/tests/*.py | \
      bindings/python/python/phantom_http/*.py | bindings/python/python/phantom_http/*.pyi | \
      bindings/python/python/phantom_http/py.typed | \
      bindings/go/*.go | bindings/go/native/src/*.rs)
      path_class=binding
      ;;
    README.md | docs/getting-started.md | docs/guides/* | \
      docs/reference/fingerprint-import.md)
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
  local code=false doctests=false core=false path path_class
  if (($# == 0)); then
    code=true core=true
  fi
  for path in "$@"; do
    classify_path "$path"
    case $path_class in
      code)
        code=true core=true
        break
        ;;
      binding)
        code=true
        ;;
      doctest)
        doctests=true
        ;;
    esac
  done
  if [[ $code == true ]]; then
    doctests=true
  fi
  printf 'code=%s\ndoctests=%s\ncore=%s\n' "$code" "$doctests" "$core"
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
