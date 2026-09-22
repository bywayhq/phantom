#!/usr/bin/env bash
# Run one command while holding this repository's Cargo lock.
#
# Every worktree of a repository shares one Git common directory, so a lock
# directory there serializes Cargo across sibling worktrees. mkdir is the
# atomic test-and-set; the owner file only helps a waiting caller or a human
# identify a stale lock.
#
# Usage: scripts/dev/with-cargo-lock.sh cargo test -p phantom --locked
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
lock_dir="$common_dir/phantom-cargo-lock"

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

announced=false
until mkdir "$lock_dir" 2>/dev/null; do
  if [[ $announced == false ]]; then
    owner=$(cat "$lock_dir/owner" 2>/dev/null || echo "unknown")
    echo "with-cargo-lock: waiting for $lock_dir (held by: $owner)" >&2
    announced=true
  fi
  reclaim_stale_lock
  sleep 5
done
trap 'rm -rf -- "$lock_dir"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
printf '%s\n' "$$" >"$lock_dir/pid"
printf 'pid %s in %s :: %s\n' "$$" "$PWD" "$*" >"$lock_dir/owner"

"$@"
