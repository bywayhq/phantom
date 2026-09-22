# Development helpers

Local tools for maintainers and coding agents. CI does not run them.

## Parallel lanes

Independent changes can run concurrently in sibling Git worktrees, one branch
and one agent per worktree. [AGENTS.md](../../AGENTS.md#lanes-and-worktrees)
states the rules; this section records the commands.

Start a lane from the integration checkout:

```sh
git worktree add -b lane/<name> ../phantom-worktrees/<name> main
```

Finish it from the integration checkout once the lane has handed off:

```sh
git -C ../phantom-worktrees/<name> rebase main    # the lane must be clean
git log --oneline main..lane/<name>               # review every commit
git diff main...lane/<name>
# Run the full gate from AGENTS.md on the rebased branch, serialized through
# the lock below, and read its output before merging.
git merge --ff-only lane/<name>
git worktree remove ../phantom-worktrees/<name>
git branch -d lane/<name>
```

Semantic conflicts between lanes, such as a new enum variant from one lane
meeting an exhaustive `match` from another, appear only in the post-rebase
gate. A command list joined with `;` or piped through `tail` or `grep` exits
with the status of its last command, so never chain the merge onto the gate
or trust its exit status alone: search the output for `error`, `FAILED`, and
`warning` first.

## Cargo lock

`with-cargo-lock.sh` runs one command while holding a lock shared by every
worktree of this repository:

```sh
scripts/dev/with-cargo-lock.sh cargo test -p phantom --test http3_retries --locked
RUSTDOCFLAGS="-D warnings" scripts/dev/with-cargo-lock.sh \
  cargo doc --workspace --all-features --no-deps --locked
```

Wrap each Cargo invocation separately so other lanes can interleave between
them. The script:

- creates the lock directory `phantom-cargo-lock` inside the Git common
  directory (`git rev-parse --git-common-dir`), which all worktrees share, and
  polls every five seconds while another command holds it;
- writes the holder's PID, working directory, and command to `owner`, and
  prints it once while waiting;
- removes the lock when the command exits or the script receives `HUP`,
  `INT`, or `TERM`, and exits with the command's status;
- exports `CARGO_INCREMENTAL=0`. Incremental caches grew by tens of gigabytes
  per worktree and filled the disk with several lanes active; CI sets the same
  value.

Each worktree keeps its own `target/`. Never point divergent worktrees at one
`CARGO_TARGET_DIR`.

A lock left by a killed shell (for example after `kill -9`) is not removed
automatically. Confirm that the PID in `owner` is gone, then delete the
directory:

```sh
cat "$(git rev-parse --path-format=absolute --git-common-dir)/phantom-cargo-lock/owner"
rm -r "$(git rev-parse --path-format=absolute --git-common-dir)/phantom-cargo-lock"
```
