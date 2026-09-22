---
name: lane
description: Start, work in, or finish a Phantom worktree lane (../phantom-worktrees/<lane> on branch lane/<lane>). Use when splitting work into parallel lanes, when working inside a lane, or when integrating a finished lane into main with the full gate.
argument-hint: "start <lane> | finish <lane>"
---

# Worktree lanes

The rules are in the "Lanes and worktrees" section of `AGENTS.md`; the
commands and lock details are in `scripts/dev/README.md`. Read both before
acting. Arguments: `$ARGUMENTS`.

## start <lane> (integration owner)

1. Confirm the integration checkout is on an up-to-date, clean `main`.
2. `git worktree add -b lane/<lane> ../phantom-worktrees/<lane> main`.
3. Write the lane brief: acceptance criteria, non-goals, owned files, and the
   checks the lane runs. Owned files must not overlap another active lane.
   Shared manifests (`Cargo.toml`, `Cargo.lock`) and central public APIs stay
   with the integration owner unless the brief delegates them.

## Inside a lane

- Work only in the lane's worktree and owned files.
- Wrap every Cargo command:
  `scripts/dev/with-cargo-lock.sh cargo <subcommand> ... --locked`.
- Stop at source and static checks unless the brief assigns a focused build.
- Commit in logical steps with Conventional Commit subjects and no AI
  attribution trailers. Do not rebase onto, merge into, or push `main`.
- Hand off the exact commands run, their results, and open uncertainty.

## finish <lane> (integration owner)

1. `git -C ../phantom-worktrees/<lane> status` must be clean.
2. Rebase the lane onto `main` and resolve conflicts in the lane worktree.
3. Review `git log main..lane/<lane>` and `git diff main...lane/<lane>`
   against `AGENTS.md`; the `gate-reviewer` subagent can do a first pass.
4. Run the full gate from `AGENTS.md` on the rebased branch, each Cargo
   command through the lock, with output written to a log.
5. Read the log. Search it for `error`, `FAILED`, and `warning`. Never chain
   the merge onto the gate command or trust a piped exit status.
6. Only when the gate is clean and the human integrator has authorized it:
   `git merge --ff-only lane/<lane>`, then
   `git worktree remove ../phantom-worktrees/<lane>` and
   `git branch -d lane/<lane>`.
