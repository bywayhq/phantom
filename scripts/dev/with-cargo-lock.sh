#!/usr/bin/env bash
# Run one command while holding one of this repository's Cargo lock slots.
#
# Every worktree of a repository shares one Git common directory, so lock
# directories there bound how many Cargo commands run at once across sibling
# worktrees. PHANTOM_CARGO_SLOTS sets the number of slots (default 1, which
# serializes Cargo). mkdir is the atomic test-and-set; the owner file only
# helps a waiting caller or a human identify a stale lock.
#
# Usage: scripts/dev/with-cargo-lock.sh cargo test -p phantom --locked
#        PHANTOM_CARGO_SLOTS=4 scripts/dev/with-cargo-lock.sh cargo test ...
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command> [arguments...]" >&2
  exit 64
fi

# Incremental caches grow by tens of gigabytes per worktree and have filled the
# disk with several lanes active. CI sets the same value.
export CARGO_INCREMENTAL=0

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
common_dir=$(git -C "$script_dir" rev-parse --path-format=absolute --git-common-dir)
slots=${PHANTOM_CARGO_SLOTS:-1}
if ! [[ $slots =~ ^[1-9][0-9]*$ ]]; then
  echo "with-cargo-lock: PHANTOM_CARGO_SLOTS must be a positive integer" >&2
  exit 64
fi
# Slot 0 keeps the historical name so older copies of this script share it.
slot_dir() {
  if [[ $1 -eq 0 ]]; then
    printf '%s' "$common_dir/phantom-cargo-lock"
  else
    printf '%s' "$common_dir/phantom-cargo-lock.$1"
  fi
}
lock_dir=""

# A holder that died without running its trap (kill -9, crash) leaves the
# directory behind. Reclaim it only when its recorded PID is gone; renaming it
# first makes the reclaim atomic, so two waiters cannot both take it.
reclaim_stale_lock() {
  local pid
  pid=$(cat "$lock_dir/pid" 2>/dev/null) || return 0
  [[ $pid =~ ^[0-9]+$ ]] || return 0
  kill -0 "$pid" 2>/dev/null && return 0
  local stale="$lock_dir.stale.$$"
  mv -- "$lock_dir" "$stale" 2>/dev/null || return 0
  if [[ $(cat "$stale/pid" 2>/dev/null) == "$pid" ]]; then
    echo "with-cargo-lock: removed stale lock held by dead pid $pid" >&2
    rm -rf -- "$stale"
  else
    # A new holder took the lock between the check and the rename.
    mv -- "$stale" "$lock_dir" 2>/dev/null || rm -rf -- "$stale"
  fi
}

try_acquire() {
  local slot
  for ((slot = 0; slot < slots; slot++)); do
    lock_dir=$(slot_dir "$slot")
    if mkdir "$lock_dir" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

announced=false
until try_acquire; do
  if [[ $announced == false ]]; then
    owner=$(cat "$(slot_dir 0)/owner" 2>/dev/null || echo "unknown")
    echo "with-cargo-lock: waiting for one of $slots slot(s) (slot 0 held by: $owner)" >&2
    announced=true
  fi
  for ((slot = 0; slot < slots; slot++)); do
    lock_dir=$(slot_dir "$slot")
    reclaim_stale_lock
  done
  sleep 5
done
trap 'rm -rf -- "$lock_dir"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
printf '%s\n' "$$" >"$lock_dir/pid"
printf 'pid %s in %s :: %s\n' "$$" "$PWD" "$*" >"$lock_dir/owner"

"$@"
