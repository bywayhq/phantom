# Development helpers

Local tools for maintainers and coding agents who run several changes at once.
CI does not use them.

## Parallel lanes

A lane is one independent change in its own sibling Git worktree, with one
branch and one agent. The rules are in
[AGENTS.md](../../AGENTS.md#lanes-and-worktrees); this section has the
commands.

Start a lane from the integration checkout:

```sh
git worktree add -b lane/<name> ../phantom-worktrees/<name> main
```

When the lane has handed off, finish it from the integration checkout:

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

Run the full gate after the rebase, not before. Two lanes can each pass alone
and still break together: for example, one adds an enum variant and the other
adds an exhaustive `match` on that enum.

Never chain the merge onto the gate. A command list joined with `;` or piped
through `tail` or `grep` exits with the status of its last command, so a
green exit status does not prove that Cargo passed. Search the gate output for
`error`, `FAILED`, and `warning` first.

## Cargo lock

When more than one worktree is active, run each Cargo command through
`with-cargo-lock.sh`. It runs one command while holding a lock that every
worktree of this repository shares:

```sh
scripts/dev/with-cargo-lock.sh cargo test -p phantom --test http3_retries --locked
RUSTDOCFLAGS="-D warnings" scripts/dev/with-cargo-lock.sh \
  cargo doc --workspace --all-features --no-deps --locked
```

Wrap each Cargo command separately, so other lanes can run between them.

By default one Cargo command runs at a time. On a machine with cores and disk
to spare, allow more with `PHANTOM_CARGO_SLOTS`; each slot is one more lock
directory, so four lanes with `-j 4` use about 16 cores:

```sh
PHANTOM_CARGO_SLOTS=4 scripts/dev/with-cargo-lock.sh cargo test --workspace --locked -j 4
```

The script:

- takes the first free lock directory among `phantom-cargo-lock`,
  `phantom-cargo-lock.1`, and so on up to the slot count, in the Git common
  directory (`git rev-parse --git-common-dir`), which all worktrees share;
- records the holder's PID in `pid`, and its PID, working directory, and
  command in `owner`;
- while another command holds the lock, prints the `owner` line once and
  retries every five seconds;
- removes the lock when the command exits or the script receives `HUP`,
  `INT`, or `TERM`, and exits with the command's status;
- exports `CARGO_INCREMENTAL=0`, as CI does. With several lanes active,
  incremental caches grew by tens of gigabytes per worktree and filled the
  disk.

Each worktree keeps its own `target/`. Never point divergent worktrees at one
`CARGO_TARGET_DIR`.

A holder killed without cleanup (for example by `kill -9`) leaves the lock
directory behind. A waiting script reclaims it once the PID in `pid` no longer
runs. If a lock still blocks you, confirm that its holder is gone, then delete
the directory:

```sh
cat "$(git rev-parse --path-format=absolute --git-common-dir)/phantom-cargo-lock/owner"
rm -r "$(git rev-parse --path-format=absolute --git-common-dir)/phantom-cargo-lock"
```
