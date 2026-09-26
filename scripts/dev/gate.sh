#!/usr/bin/env bash
# Run the integration gate from AGENTS.md with independent steps in parallel.
#
# `cargo fmt --check` runs first and stops the gate on failure. The other
# steps run as concurrent chains. Each Cargo chain has its own target
# directory under target/gate/, so chains never wait on one another's build
# lock, and each Cargo command takes one slot through with-cargo-lock.sh, so
# the gate shares PHANTOM_CARGO_SLOTS with other worktrees. Every step writes
# target/gate/logs/<step>.log. A step fails when it exits non-zero, or when
# its log shows a failure or warning that the command did not report through
# its exit status.
#
# Usage: scripts/dev/gate.sh [options]
#
#   --quick           Lane check: formatting, Clippy, nextest on the changed
#                     crates and their dependents, and the docs checker.
#   -p, --package P   With --quick, test package P instead of the changed
#                     crates. Repeat for more.
#   --base REF        With --quick, find changed crates against the merge base
#                     with REF (default: main).
#   -j, --jobs N      Cargo build jobs per command (default: 2 x CPUs / slots).
#   --test-threads N  Tests nextest runs at once (default: nextest's).
#   --slots N         Cargo commands at once across worktrees, when
#                     PHANTOM_CARGO_SLOTS is unset (default: 4).
#   -h, --help        Show this help.
set -uo pipefail

usage() {
  sed -n '/^# Usage:/,/^# *-h, --help/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}"
}

quick=false
packages=()
base=main
jobs=""
test_threads=""
slots=4
while [[ $# -gt 0 ]]; do
  case $1 in
    --quick) quick=true ;;
    -p | --package) packages+=("${2:?$1 needs a package}"); shift ;;
    --base) base=${2:?$1 needs a ref}; shift ;;
    -j | --jobs) jobs=${2:?$1 needs a count}; shift ;;
    --test-threads) test_threads=${2:?$1 needs a count}; shift ;;
    --slots) slots=${2:?$1 needs a count}; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "gate: unknown option $1" >&2; usage >&2; exit 64 ;;
  esac
  shift
done
for value in "$slots" ${jobs:+"$jobs"} ${test_threads:+"$test_threads"}; do
  if ! [[ $value =~ ^[1-9][0-9]*$ ]]; then
    echo "gate: counts must be positive integers, not '$value'" >&2
    exit 64
  fi
done
if [[ $quick == false && ${#packages[@]} -gt 0 ]]; then
  echo "gate: --package applies only to --quick" >&2
  exit 64
fi

root=$(git rev-parse --show-toplevel) || exit 1
cd "$root" || exit 1
lock="$root/scripts/dev/with-cargo-lock.sh"
export PHANTOM_CARGO_SLOTS=${PHANTOM_CARGO_SLOTS:-$slots}
if [[ -z $jobs ]]; then
  cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)
  # Twice the fair share: a build spends much of its time compiling one crate
  # on one core, so the other chains' commands fill the idle cores.
  jobs=$((2 * cpus / PHANTOM_CARGO_SLOTS))
  ((jobs >= 2)) || jobs=2
fi
threads=()
[[ -z $test_threads ]] || threads=(--test-threads "$test_threads")
msrv=$(sed -nE 's/^rust-version = "([^"]+)".*/\1/p' Cargo.toml)
[[ $msrv == *.*.* ]] || msrv="$msrv.0"

gate_dir="$root/target/gate"
logs="$gate_dir/logs"
rm -rf -- "$logs"
mkdir -p -- "$logs"

# A Cargo diagnostic, a failed Rust or Python test, a nextest failure line, or
# a docs checker finding. Each is a failure even when the command exits 0.
failure_pattern='^(error|warning)(\[[^]]*\])?:|FAILED|^ +(FAIL|SIGSEGV|SIGABRT|TIMEOUT|ABORT) \[|^[1-9][0-9]* error\(s\)|, [1-9][0-9]* warning\(s\)'

# run_step NAME TARGET COMMAND...: runs COMMAND with its output in NAME's log
# and records its exit status, duration, and first suspicious log lines.
# TARGET is a directory under target/gate for a Cargo command, or - for a
# command that does not build Rust.
run_step() {
  local name=$1 target=$2
  shift 2
  local log="$logs/$name.log" start status
  start=$(date +%s)
  {
    printf '$ %s\n' "$*"
    if [[ $target == - ]]; then
      "$@"
    else
      CARGO_TARGET_DIR="$gate_dir/$target" "$lock" "$@"
    fi
  } >"$log" 2>&1
  status=$?
  grep -E -m 5 -- "$failure_pattern" "$log" >"$logs/$name.flags"
  printf '%s %s\n' "$status" "$(($(date +%s) - start))" >"$logs/$name.status"
}

# feature_rows JOB TARGET: checks each optional feature row of the CI job JOB
# (features or msrv) in target/gate/TARGET. The rows are read from the
# workflow, so the gate and CI cannot drift apart. Every row runs; the status
# is 1 when any row fails. The rows take one Cargo slot for the whole batch:
# each is a check of a few seconds, and queueing for a slot before every row
# spent several minutes behind the other chains' long builds.
feature_rows() {
  local job=$1 target=$2 pattern rows toolchain=""
  # shellcheck disable=SC2016 # $MSRV is literal workflow text.
  case $job in
    features) pattern='s/^ +cargo check (-p .* --locked)\r?$/\1/p' ;;
    msrv) pattern='s/^ +cargo "\+\$MSRV" check (-p .* --locked)\r?$/\1/p'; toolchain="+$msrv" ;;
  esac
  mapfile -t rows < <(sed -nE "$pattern" .github/workflows/ci.yml)
  if [[ ${#rows[@]} -eq 0 ]]; then
    echo "gate: no $job feature rows found in .github/workflows/ci.yml"
    return 1
  fi
  # shellcheck disable=SC2016 # The script expands its own arguments.
  CARGO_TARGET_DIR="$gate_dir/$target" "$lock" bash -c '
    toolchain=$1 jobs=$2 status=0
    shift 2
    for row in "$@"; do
      read -ra args <<<"$row"
      printf "\n\$ cargo %scheck -j %s %s\n" "${toolchain:+$toolchain }" "$jobs" "$row"
      cargo ${toolchain:+"$toolchain"} check -j "$jobs" "${args[@]}" || status=1
    done
    exit "$status"' _ "$toolchain" "$jobs" "${rows[@]}"
}

# changed_packages: prints the workspace packages whose files differ from the
# merge base with $base (committed, staged, unstaged, or untracked), or `*`
# when a change outside crates/ can affect every package.
changed_packages() {
  local merge_base path dir name
  merge_base=$(git merge-base HEAD "$base") || return 1
  {
    git -c core.safecrlf=false diff --name-only "$merge_base"
    git ls-files --others --exclude-standard
  } | sort -u | while IFS= read -r path; do
    case $path in
      crates/*/*)
        dir=${path#crates/}
        dir=${dir%%/*}
        name=$(sed -nE 's/^name = "([^"]+)"/\1/p' "crates/$dir/Cargo.toml" 2>/dev/null | head -n 1)
        [[ -z $name ]] || echo "$name"
        ;;
      Cargo.toml | Cargo.lock | rust-toolchain.toml | .cargo/* | .config/* | vendor/* | fixtures/*)
        echo '*'
        ;;
    esac
  done | sort -u
}

# Each chain runs in a process group of its own, so an interrupted gate stops
# the whole chain, Cargo and the lock helper included, and no orphaned build
# keeps a lock slot.
set -m
pids=()
launch() {
  "$@" &
  pids+=($!)
}
stop_chains() {
  local pid
  for pid in "${pids[@]}"; do
    kill -TERM -- "-$pid" 2>/dev/null
  done
  exit 130
}
trap stop_chains INT TERM

gate_start=$(date +%s)
steps=(fmt)
run_step fmt - cargo fmt --check
if [[ $quick == false ]]; then
  steps+=(fmt-fuzz)
  run_step fmt-fuzz - cargo fmt --manifest-path fuzz/Cargo.toml --check
fi
if grep -qv '^0 ' "$logs"/fmt*.status; then
  echo "gate: formatting failed; see $logs/fmt*.log" >&2
  cat "$logs"/fmt*.log >&2
  exit 1
fi

# Test selection, without the package scope: --workspace, -p, or a filter.
tests=(--all-targets --all-features --locked --no-fail-fast)
if cargo nextest --version >/dev/null 2>&1; then
  runner=(cargo nextest run --build-jobs "$jobs" "${threads[@]}")
else
  echo "gate: cargo-nextest is not installed; running cargo test instead" >&2
  runner=(cargo test -j "$jobs")
fi
scope=(--workspace)
if [[ $quick == true ]]; then
  if [[ ${#packages[@]} -gt 0 ]]; then
    scope=()
    for package in "${packages[@]}"; do scope+=(-p "$package"); done
  else
    mapfile -t packages < <(changed_packages)
    if [[ ${#packages[@]} -eq 0 ]]; then
      scope=()
    elif [[ " ${packages[*]} " != *' * '* ]]; then
      if [[ ${runner[1]} == nextest ]]; then
        # Dependents too: a change to phantom-net can break phantom-http.
        filter=$(printf 'rdeps(%s) | ' "${packages[@]}")
        scope=(--workspace -E "${filter% | }")
      else
        scope=()
        for package in "${packages[@]}"; do scope+=(-p "$package"); done
      fi
    fi
  fi
fi
clippy=(cargo clippy -j "$jobs" --workspace --all-targets --all-features --locked -- -D warnings)
python=(uv run --no-project --python 3.10)

# Each chain runs in the background, its steps in order. The full gate has
# four Cargo chains, one per default slot, so it does not queue behind itself.
#
# Only Clippy runs in target/gate/lint. The btls-sys build script declares
# RUSTC_WORKSPACE_WRAPPER, which Clippy sets and other Cargo commands do not,
# as a rerun trigger, so a directory shared by Clippy and any other command
# rebuilds BoringSSL on every switch between them.
chain_tests() {
  if [[ ${#scope[@]} -eq 0 ]]; then
    echo "no Rust package changed since $base" >"$logs/nextest.log"
    : >"$logs/nextest.flags"
    printf '0 0\n' >"$logs/nextest.status"
    return
  fi
  run_step nextest test "${runner[@]}" "${scope[@]}" "${tests[@]}"
  [[ $quick == true ]] && return
  run_step doctest test cargo test --doc -j "$jobs" --workspace --all-features --locked
  run_step fuzz-test test cargo test -j "$jobs" --manifest-path fuzz/Cargo.toml --locked
}
chain_lint() {
  run_step clippy lint "${clippy[@]}"
  [[ $quick == true ]] && return
  run_step fuzz-clippy lint cargo clippy -j "$jobs" --manifest-path fuzz/Cargo.toml \
    --all-targets --locked -- -D warnings
  RUSTDOCFLAGS="-D warnings" run_step rustdoc doc \
    cargo doc -j "$jobs" --workspace --all-features --no-deps --locked
}
chain_msrv() {
  run_step msrv-workspace msrv cargo "+$msrv" check -j "$jobs" --workspace --all-targets --locked
  run_step msrv-rows - feature_rows msrv msrv
}
chain_python() {
  local ruff=(uvx ruff@0.16.8) paths=(scripts/capture scripts/conformance scripts/docs)
  run_step ruff-check - "${ruff[@]}" check "${paths[@]}"
  run_step ruff-format - "${ruff[@]}" format --check "${paths[@]}"
  run_step capture-tests - "${python[@]}" --with aioquic==1.3.0 --with h2==4.4.1 \
    --with hpack==4.2.0 python -m unittest discover -s scripts/capture/tests -p 'test_*.py'
  run_step conformance-tests - "${python[@]}" --with aioquic==1.3.0 \
    python -m unittest discover -s scripts/conformance/tests -p 'test_*.py'
  run_step docs-tests - "${python[@]}" \
    python -m unittest discover -s scripts/docs/tests -p 'test_*.py'
  run_step docs-check - "${python[@]}" python scripts/docs/check_docs.py
  run_step tool-pins - bash scripts/ci/check-tool-pins.sh
}

if [[ $quick == true ]]; then
  steps+=(nextest clippy docs-check)
  launch chain_tests
  launch chain_lint
  launch run_step docs-check - "${python[@]}" python scripts/docs/check_docs.py
else
  steps+=(nextest doctest fuzz-test clippy fuzz-clippy rustdoc msrv-workspace msrv-rows
    feature-rows ruff-check ruff-format capture-tests conformance-tests docs-tests docs-check
    tool-pins)
  launch chain_tests
  launch chain_lint
  launch chain_msrv
  launch run_step feature-rows - feature_rows features features
  launch chain_python
fi
wait "${pids[@]}"

failed=0
printf '\n%-18s %-6s %5s %8s\n' step result exit seconds
for step in "${steps[@]}"; do
  if [[ -f $logs/$step.status ]]; then
    read -r status seconds <"$logs/$step.status"
  else
    status=skipped seconds=-
  fi
  if [[ $status != 0 ]]; then
    result=FAIL
  elif [[ -s $logs/$step.flags ]]; then
    result=FLAG
  else
    result=ok
  fi
  [[ $result == ok ]] || failed=$((failed + 1))
  printf '%-18s %-6s %5s %8s\n' "$step" "$result" "$status" "$seconds"
done
printf '%-18s %-6s %5s %8s\n' total "" "" "$(($(date +%s) - gate_start))"
echo "logs: $logs"
if ((failed > 0)); then
  echo
  for step in "${steps[@]}"; do
    if [[ -s $logs/$step.flags ]]; then
      echo "$step.log:"
      sed 's/^/  /' "$logs/$step.flags"
    fi
  done
  echo "gate: $failed step(s) failed or flagged; read their logs" >&2
  exit 1
fi
echo "gate: all steps passed"
