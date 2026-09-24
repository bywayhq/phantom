@AGENTS.md

## Claude Code

- `.claude/settings.json` is shared: its permission rules and hooks apply to
  everyone. Put personal overrides in `.claude/settings.local.json` or
  `CLAUDE.local.md`; both are ignored by Git.
- Hooks in `.claude/hooks/` deny `cargo fmt --all` and AI attribution
  trailers, and report `rustfmt --check` failures after edits to `crates/` or
  `fuzz/` Rust files. Fix the reported cause; do not work around a denial.
- Project skills: `/lane` (start or finish a worktree lane), `/vendor-refresh`
  (change or refresh a vendored fork), `/browser-capture` (record browser
  evidence), and `/phantom-docs` (write or review documentation). The `gate-reviewer` subagent reviews a lane diff against
  AGENTS.md before integration.
- The Bash tool times out after at most ten minutes, and waiting for the Cargo
  lock counts toward it. Run the full gate or a long `cargo test` in the
  background, write its output to a log, and read the log.
- Give each subagent an explicit list of owned files and the checks it must
  run. Subagents report back; they do not merge, push, or edit another lane.
