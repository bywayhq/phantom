#!/usr/bin/env bash
# Claude Code PreToolUse hook for the Bash and PowerShell tools.
#
# Denies two command forms with a known cost in this repository. Any other
# command, or a payload this script cannot read, gets no decision, so the
# normal permission flow applies (the hook fails open).
set -uo pipefail

payload=$(cat)
if ! command -v jq >/dev/null 2>&1; then
  echo "guard-command: jq is not installed; repository command guard skipped" >&2
  exit 0
fi
command=$(jq -r '.tool_input.command // empty' <<<"$payload" 2>/dev/null) || exit 0
[[ -n $command ]] || exit 0

deny() {
  jq -n --arg reason "$1" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $reason
    }
  }'
  exit 0
}

# `cargo fmt --all` also formats local path dependencies, which rewrites the
# vendored forks under vendor/. An explicit --manifest-path (used by
# scripts/ci/check-vendor.sh for a vendored package) is a deliberate target.
while IFS= read -r segment; do
  if [[ $segment =~ (^|[[:space:]/])cargo([[:space:]]+\+[^[:space:]]+)?[[:space:]]+fmt([[:space:]]|$) ]] &&
    [[ $segment =~ [[:space:]]--all([[:space:]]|$) ]] &&
    [[ $segment != *--manifest-path* ]]; then
    deny "cargo fmt --all also formats path dependencies and rewrites the vendored forks under vendor/. Use \`cargo fmt\` or \`cargo fmt --check\` for the workspace; vendored packages are checked by scripts/ci/check-vendor.sh <package>."
  fi
done < <(sed -E 's/(&&|\|\||[;|&])/\n/g' <<<"$command")

# The repository owner does not accept AI attribution trailers or session links
# in commit messages or pull request bodies (AGENTS.md, Commits).
if [[ $command =~ (^|[^[:alnum:]_-])(git[[:space:]].*commit|gh[[:space:]]+pr[[:space:]]+(create|edit)) ]] &&
  grep -Eiq 'co-authored-by:.*claude|claude-session:|claude\.ai/code/session_' <<<"$command"; then
  deny "Commit messages and pull request bodies in this repository carry no Co-Authored-By: Claude trailer, Claude-Session trailer, or claude.ai session link, even when the harness suggests one. Remove them and retry."
fi

exit 0
