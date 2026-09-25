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
scripts/dev/with-cargo-lock.sh \n  cargo test -p phantom-http --test http3 --locked http3_retries::
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

## Integration test binaries

`phantom-http` builds its integration tests as five test binaries, one
directory each under `crates/phantom/tests/`:

| Binary | Covers |
| --- | --- |
| `requests` | One request through the public client: fields, bodies, redirects, retries, and timeouts |
| `sessions` | Name resolution, connection reuse, pooling, and negotiation across requests |
| `http3` | HTTP/3, Alt-Svc upgrades, HTTPS records, and CONNECT-UDP |
| `proxies` | HTTP CONNECT, forwarding, and SOCKS5 proxy routes |
| `streams` | WebSocket and server-sent event streams |

`phantom-profile` has one, `public_api`. Each `main.rs` declares one module
per test area, and `crates/phantom/tests/support/` holds the loopback servers
and helpers that every binary loads.

Add a test area as a module of the binary it belongs to, with a `mod` line in
that binary's `main.rs`, gated with `#[cfg(feature = "...")]` when it needs a
feature. Do not add a top-level `tests/*.rs` file: it links a binary of its
own, with its own copy of the dependency graph and its own PDB on Windows.

Run one module by its path:

```sh
scripts/dev/with-cargo-lock.sh \
  cargo test -p phantom-http --all-features --test http3 --locked http3_retries::
```

`consolidate_integration_tests.py` moved the tests into this layout, and its
`GROUPS` table assigns each module to a binary. A branch that started before
the move and adds or edits a top-level test file can run it again from the
repository root; it moves only the files still at the top level:

```sh
python scripts/dev/consolidate_integration_tests.py
git diff -M --stat HEAD
```

The script:

- moves each top-level `tests/*.rs` file, and each directory it includes,
  into its binary's directory with `git mv`;
- turns each `#[path = "support/<file>.rs"] mod <name>;` into
  `use crate::support::<file> as <name>;`, drops the imports that only served
  another support file, and rewrites `crate::` paths for the new module;
- moves a file-level `#![cfg(feature = ...)]` onto the module's `mod` line
  and regenerates each `main.rs` and `tests/support/mod.rs`;
- removes the file's `[[test]]` table from the crate's `Cargo.toml`, turning
  its `required-features` into a `cfg` on the `mod` line, and stops on any
  other setting, such as `harness = false`, that a module cannot keep;
- rewrites `crates/<crate>/tests/<name>.rs` paths in tracked files and lists
  each `--test <name>` use, which needs a `--test <binary> <name>::` filter
  by hand.

A new file needs an entry in `GROUPS` first. Build the tests with
`--all-features` and with no features afterwards: a merged file can leave an
import unused or a support module ungated. The script's own tests run with
`python -m unittest discover -s scripts/dev/tests -p 'test_*.py'`; one of
them fails while a grouped crate has a top-level test file.

## Disk space

Measured on Windows with the dev profile, which keeps line tables for the
workspace crates and no debug information for dependencies:

| After | `target/` size |
| --- | --- |
| A clean `cargo test --workspace --all-targets --all-features --no-run` | 2.3 GB |
| A full `scripts/dev/gate.sh` from a clean checkout, in `target/gate/` | 8.9 GB |

Cargo never deletes old artifacts. Each toolchain, profile, and feature set
keeps its own build of the dependencies, BoringSSL alone taking 300 MB per
build, so a long-lived checkout grows with every dependency update and
toolchain change.

IDEs run their own `cargo check` with incremental compilation on, because
`CARGO_INCREMENTAL=0` applies only to commands run through the lock helper.
Their incremental data lives in `target/debug/incremental`.

To reclaim space:

- Delete `target/debug/incremental` at any time. The IDE rebuilds it on its
  next check.
- Remove one package's artifacts, for example after many changes to it, with
  `cargo clean -p <package>`, such as `cargo clean -p phantom-http`.
- Delete a lane's `target/` when the lane hands off. `git worktree remove`
  deletes it with the rest of the worktree.
- Delete the whole `target/` of a long-lived checkout. The next build starts
  from scratch.
