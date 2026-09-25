#!/usr/bin/env bash
# Check that tool versions pinned in more than one file agree. Dependabot
# updates only scripts/requirements.in and scripts/requirements.txt; the other
# copies are edited by hand, and this check fails when one of them drifts:
#
#   - scripts/requirements.txt pins every package in scripts/requirements.in
#     at the same version, so the lock was regenerated after an edit.
#   - The ruff `required-version` in pyproject.toml, every `ruff@VERSION`, and
#     every `--with NAME==VERSION` match the pin in scripts/requirements.txt.
#   - Every `nightly-YYYY-MM-DD` names the same toolchain.
#   - Every `ShellCheck X.Y.Z` in Markdown matches SHELLCHECK_VERSION in the
#     CI workflow.
#
# The search covers tracked files outside vendor/ and fixtures/.
#
# Usage: check-tool-pins.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

failures=0
fail() {
  echo "$1" >&2
  failures=$((failures + 1))
}

# Prints `path:line:match` for each match of an extended regular expression in
# tracked text files outside vendor/ and fixtures/, limited to the optional
# pathspecs that follow the pattern.
search() {
  local pattern=$1
  shift
  git grep -n -o -I -E -e "$pattern" -- "$@" ':!vendor' ':!fixtures' || true
}

requirements_in=scripts/requirements.in
requirements_txt=scripts/requirements.txt

# The resolved pins, keyed by lowercase package name.
declare -A pinned=()
while IFS= read -r line; do
  line=${line%$'\r'}
  if [[ $line =~ ^([A-Za-z0-9._-]+)==([^[:space:]\;\\]+) ]]; then
    pinned[${BASH_REMATCH[1],,}]=${BASH_REMATCH[2]}
  fi
done <"$requirements_txt"

lineno=0
while IFS= read -r line; do
  lineno=$((lineno + 1))
  line=${line%$'\r'}
  if [[ $line =~ ^([A-Za-z0-9._-]+)==([^[:space:]]+) ]]; then
    name=${BASH_REMATCH[1],,}
    version=${BASH_REMATCH[2]}
    if [[ ${pinned[$name]:-} != "$version" ]]; then
      fail "$requirements_in:$lineno: $name==$version, but $requirements_txt pins ${pinned[$name]:-nothing}; regenerate it with the command in its header"
    fi
  fi
done <"$requirements_in"

ruff=${pinned[ruff]:-}
if [[ -z $ruff ]]; then
  fail "$requirements_txt: no ruff pin"
fi

required=$(sed -nE 's/^required-version = "==([^"]+)".*/\1/p' pyproject.toml)
if [[ -z $required ]]; then
  fail "pyproject.toml: no exact ruff required-version"
elif [[ $required != "$ruff" ]]; then
  fail "pyproject.toml: ruff required-version $required, but $requirements_txt pins $ruff"
fi

copies=0
while IFS=: read -r path line match; do
  copies=$((copies + 1))
  if [[ ${match#ruff@} != "$ruff" ]]; then
    fail "$path:$line: $match, but $requirements_txt pins ruff==$ruff"
  fi
done < <(search 'ruff@[0-9][0-9A-Za-z.]*')
if ((copies == 0)); then
  fail "no ruff@VERSION command found; the gate in AGENTS.md should have one"
fi

copies=0
while IFS=: read -r path line match; do
  copies=$((copies + 1))
  spec=${match#--with }
  name=${spec%%==*}
  name=${name,,}
  version=${spec#*==}
  if [[ -z ${pinned[$name]:-} ]]; then
    fail "$path:$line: $spec is not pinned in $requirements_txt"
  elif [[ ${pinned[$name]} != "$version" ]]; then
    fail "$path:$line: $spec, but $requirements_txt pins $name==${pinned[$name]}"
  fi
done < <(search '--with [A-Za-z0-9._-]+==[0-9][0-9A-Za-z.]*')
if ((copies == 0)); then
  fail "no --with NAME==VERSION found; the gate in AGENTS.md should have one"
fi

nightlies=$(search 'nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}')
nightly=$(cut -d: -f3 <<<"$nightlies" | sort -u)
if [[ $nightly == *$'\n'* ]]; then
  fail "the pinned nightly toolchain differs between files:"$'\n'"$nightlies"
fi

shellcheck=$(sed -nE 's/^ *SHELLCHECK_VERSION: v([0-9.]+)\r?$/\1/p' .github/workflows/ci.yml)
if [[ -z $shellcheck ]]; then
  fail ".github/workflows/ci.yml: no SHELLCHECK_VERSION"
fi
while IFS=: read -r path line match; do
  if [[ ${match#ShellCheck } != "$shellcheck" ]]; then
    fail "$path:$line: $match, but CI installs ShellCheck $shellcheck"
  fi
done < <(search 'ShellCheck [0-9]+\.[0-9]+\.[0-9]+' '*.md')

if ((failures > 0)); then
  echo "check-tool-pins: $failures mismatched pin(s)" >&2
  exit 1
fi
echo "check-tool-pins: ruff $ruff, ${nightly:-no nightly toolchain}, and ShellCheck $shellcheck agree"
