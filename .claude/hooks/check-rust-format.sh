#!/usr/bin/env bash
# Claude Code PostToolUse hook for Edit, MultiEdit, and Write.
#
# After an edit to a workspace or fuzz Rust file (edition 2024), runs
# `rustfmt --check` on it and reports unformatted output back to Claude. It
# never rewrites the file. Vendored forks keep their upstream editions and
# formatting, so vendor/ is skipped. Missing tools skip the check (fail open).
set -uo pipefail

payload=$(cat)
if ! command -v jq >/dev/null 2>&1; then
  echo "check-rust-format: jq is not installed; format check skipped" >&2
  exit 0
fi
file=$(jq -r '.tool_input.file_path // empty' <<<"$payload" 2>/dev/null) || exit 0
[[ $file == *.rs ]] || exit 0
# Windows delivers native paths with backslashes; Git Bash tools accept "/".
file=$(tr "\\\\" / <<<"$file")
[[ -f $file ]] || exit 0

prefix=$(git -C "$(dirname "$file")" rev-parse --show-prefix 2>/dev/null) || exit 0
relative="$prefix$(basename "$file")"
case $relative in
  crates/* | fuzz/*) ;;
  *) exit 0 ;;
esac

if ! command -v rustfmt >/dev/null 2>&1; then
  echo "check-rust-format: rustfmt is not installed; format check skipped" >&2
  exit 0
fi

# rustfmt also checks out-of-line child modules of the file it is given.
if output=$(rustfmt --edition 2024 --check --color never -- "$file" 2>&1); then
  exit 0
fi
report=$(head -n 60 <<<"$output")
jq -n --arg reason "rustfmt --edition 2024 --check failed after editing $relative. Run \`rustfmt --edition 2024 $relative\` (or \`cargo fmt\` for workspace crates, never with --all), then re-check. First lines of output:
$report" '{decision: "block", reason: $reason}'
exit 0
