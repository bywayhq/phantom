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
# Run the full gate on the rebased branch and read its output before merging.
scripts/dev/gate.sh
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

## Integration gate

`gate.sh` runs the gate from
[AGENTS.md](../../AGENTS.md#verification-and-handoff). It needs bash 4.4 or
later; macOS ships bash 3.2, so install a newer one (`brew install bash`).
`cargo fmt --check` runs first and stops the gate when it fails. The other steps run as
concurrent chains:

| Chain | Target directory | Steps |
| --- | --- | --- |
| Tests | `target/gate/test` | `cargo nextest run`, `cargo test --doc`, then the tests of the `fuzz/` crate |
| Lint | `target/gate/lint`, then `target/gate/doc` | Clippy on the workspace and the `fuzz/` crate, then rustdoc |
| MSRV | `target/gate/msrv` | `cargo +1.88.0 check --workspace`, then the MSRV job's feature rows |
| Features | `target/gate/features` | The Features job's rows, `cargo check` or `cargo clippy` as the job writes them |
| Python | none | ruff, the four unittest suites, the docs checker, and the tool-pin check |

The feature rows are read from `.github/workflows/ci.yml`, so the gate checks
the rows CI checks. The gate fails if either job has a `cargo check` or
`cargo clippy` command it cannot parse as a row. No two chains share a target
directory, so chains do not wait on one another's Cargo build lock. The first
run builds each directory from scratch, and later runs reuse what is already
built there; `with-cargo-lock.sh` turns off incremental compilation, so a
changed crate is rebuilt whole. Only Clippy builds in
`target/gate/lint`: the `btls-sys` build script reruns whenever
`RUSTC_WORKSPACE_WRAPPER` changes, and Clippy sets it while other Cargo
commands do not, so sharing a directory rebuilds BoringSSL on each switch.
The four Cargo chains match the default of four slots, so the gate does not
queue behind itself.

```sh
scripts/dev/gate.sh                  # the full gate
scripts/dev/gate.sh --quick          # a lane: the crates changed since main
scripts/dev/gate.sh --quick -p phantom-net
```

`--quick` runs formatting, Clippy, the docs checker, and nextest on the
crates changed since the merge base with `main` (`--base REF` for another
branch) and the crates that depend on them. It stops with an error when that
merge base cannot be found. A change to a manifest, the lock
file, `vendor/`, `fixtures/`, or `.config/` tests the whole workspace. A `-p`
list tests exactly those packages.

Each step writes `target/gate/logs/<step>.log`. The script then prints the
step, result, exit status, and duration of every step, and exits non-zero if
any step failed. A step whose command exits 0 but whose log contains a Cargo
`error:` or `warning:` line, `FAILED`, a nextest failure line, or a docs
checker finding is marked `FLAG` and also fails the gate; the table is
followed by the matching lines.

Every Cargo command in the gate takes one slot through `with-cargo-lock.sh`,
so the gate shares the machine with other worktrees under the rules below.
The feature rows are the exception: each chain of rows holds one slot for the
whole batch, because each row is a check of a few seconds and queueing before
every row cost minutes. When `PHANTOM_CARGO_SLOTS` is unset, the gate sets it
to `--slots` (default 4). Each Cargo command gets `-j` jobs
(default: twice the CPUs divided by slots, since a build often waits on one
crate and leaves cores idle); `--test-threads` sets how many tests
nextest runs at once. Without `cargo-nextest`, the tests step runs
`cargo test` instead.

Each chain runs in a process group of its own. When the gate receives `HUP`,
`INT`, or `TERM`, it stops every chain, and each lock helper releases its
slot. A gate killed without that chance, by `SIGKILL` or by a timeout that
kills only the gate's own process group, leaves its chains running and
holding slots. Stop them with the group IDs the gate recorded:

```sh
while read -r group; do kill -TERM -- "-$group"; done < target/gate/logs/chains.pids
```

A lock whose holder died without releasing it is reclaimed by the next
waiting command, as [below](#cargo-lock) describes.

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
