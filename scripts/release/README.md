# Release Phantom

Use these steps to verify and publish Rust packages, or prepare native CLI
archives. Package metadata points to Byway's repository. Registry ownership
is checked separately.

## CLI archives

The **CLI artifacts** workflow prepares candidates for these native targets:

| Target | Verification runner |
| --- | --- |
| `x86_64-pc-windows-msvc` | Windows Server 2022, x64 |
| `x86_64-unknown-linux-gnu` | Ubuntu 24.04, x64 |
| `aarch64-apple-darwin` | macOS 15, arm64 |

To prepare one on a matching host, use a clean checkout and its native build
tools. The command uses the pinned Rust toolchain and locked dependencies:

```sh
scripts/dev/with-cargo-lock.sh python scripts/release/cli_artifact.py \
  --target x86_64-unknown-linux-gnu --output target/cli-artifact
```

`CARGO_BUILD_JOBS` sets a positive build-job count; the default is two.

The archive contains the executable, project licenses, dependency/native
notices and `artifact.json`. That receipt records the source revision, lockfile
and binary hashes, compiler versions, actual runtime and native dependency
inspection. Build-tool and procedural-macro notices are included conservatively.
The archive's SHA256 and installation results accompany it in `verified/`.
Build and command logs remain in `logs/`, including failed checks.

Verification extracts outside the checkout and runs version/profile checks,
an HTTP/1 request with ordered headers, file upload, chunked download and a
stalled-body deadline that must disconnect. These are installation checks,
not browser captures, throughput measurements or Control-C signal tests.

Only successful candidates are uploaded. This workflow does not publish a
GitHub Release or upload packages to any registry. No older runtime floor,
fully static binary, cross-compilation or code-signing support is claimed.
Inspect each receipt's actual runtime and dependency output before deployment.

## Prepare and verify

Use Python 3.12 or later for these scripts. Run from a clean release commit
on `main`, after the full integration gate and all PR checks pass.

```sh
scripts/release/publish-crates.sh --preflight
scripts/release/publish-crates.sh --verify --output target/release-current
scripts/release/publish-crates.sh --verify --toolchain 1.88.0 \
  --output target/release-msrv
scripts/dev/with-cargo-lock.sh python3 scripts/release/check-advisories.py \
  --output target/release-advisories
```

The package check creates the eight archives in `packages.txt`: five workspace
libraries, the CLI and the changed `btls` and `tokio-btls` forks. Unchanged forks
keep their exact published versions and resolve from crates.io. The check serves
the new archives from a temporary loopback registry with no publishing
endpoint. The downstream
consumer fetches those archives, builds minimal and full features, and
checks the resolved sources. It also runs the existing public-client peers
over TLS HTTP/1, HTTP/2, and HTTP/3, with Chrome and Firefox settings and
cold and reused clients. These short runs check operation, not performance.

The release workflow repeats archive installation on Windows, macOS, and
Linux with the current compiler and Rust 1.88. Keep its logs, archive
checksums, registry index, consumer lockfile, and protocol results.
`--allow-dirty` is available for local preparation. Its archives are not
the final release artifacts.

The advisory check maps all renamed forks back to their upstream names and
versions. It retains the complete audit report. A backport exception must
name the exact upstream version and its retained patch. Review audit
warnings and new native-library advisories as well as reported vulnerabilities.

Before the first release, retain a public API listing with `cargo public-api`.
Later releases compare against the previous published version with
`cargo semver-checks`. Finalize the version and changelog before making the
clean release commit. Tag that exact commit after the registry smoke check.

## Byway ownership

Every package must have the team owner `github:bywayhq:staff`. The publishing
maintainer must belong to that team and authorize crates.io to read GitHub
organization memberships. Keep a named maintainer owner: team owners cannot
manage other owners. See [Cargo's ownership rules](https://doc.rust-lang.org/cargo/reference/publishing.html#cargo-owner).

The publisher checks all names before uploading anything. After each package,
it adds the Byway team and verifies the registry owner list before continuing.
An ownership failure stops the release. Setting a repository URL or authors
field does not give Byway registry ownership.

## Publish after approval

Obtain the human integrator's approval before publishing. Configure a
crates.io token with publication and owner-management permissions in the
protected `crates-io` environment. Do not put the token in command arguments
or logs. Configure required reviewers on that environment before use.

Dispatch the Release workflow on `main` with its dry run disabled. It waits
for all six packaged-install jobs. `packages.txt` defines dependency order.
Each package gets a real registry dry run immediately before its upload,
once its dependencies are available. A final registry-only consumer check
must pass before the release is complete.

If publication stops, rerun from the same clean commit. Existing versions
must contain that exact commit in their checked registry archive. The script
repairs missing team ownership before moving on. A version from a different
commit stops the run; do not overwrite it or silently skip it.

After a successful publish and install check, create the `v0.2.0` tag at the
release commit and retain the workflow evidence. A failed partial release
remains partial until every planned version and owner is verified.
