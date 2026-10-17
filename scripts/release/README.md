# Release Phantom

Use these steps to publish the Rust libraries. There is no supported CLI
binary in this release. Package metadata points to Byway's repository.
Registry ownership is checked separately.

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

The package check creates all seventeen archives. It serves them from a
temporary loopback registry with no publishing endpoint. The downstream
consumer fetches those archives, builds minimal and full features, and
checks the resolved sources. It also runs the existing public-client peers
over TLS HTTP/1, HTTP/2, and HTTP/3, with Chrome and Firefox settings and
cold and reused clients. These short runs check operation, not performance.

The release workflow repeats archive installation on Windows, macOS, and
Linux with the current compiler and Rust 1.88. Keep its logs, archive
checksums, registry index, consumer lockfile, and protocol results.
`--allow-dirty` is available for local preparation. Its archives are not
the final release artifacts.

The advisory check maps renamed forks back to their upstream names and
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

After a successful publish and install check, create the `v0.1.0` tag at the
release commit and retain the workflow evidence. A failed partial release
remains partial until every planned version and owner is verified.
