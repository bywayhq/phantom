# Adding Phantom to a project

Phantom is not yet published to crates.io. The supported ways to depend on it
are a pinned git revision or a pinned path checkout. The package is named
`phantom-http` because `phantom` is taken on crates.io; the library crate is
still `phantom`, so the dependency key below keeps `use phantom::...` working.

Phantom's patched dependencies are renamed forks that live in this repository
under `vendor/`: `phantom-btls`, `phantom-h3`, `phantom-http2`,
`phantom-quinn-proto`, and the other `phantom-*` packages listed in
[Vendored forks](../internals/vendoring.md#vendored-forks). Phantom's manifests
depend on them by exact version and path, so a downstream build needs no
`[patch]` table and the stock packages can never replace them.

## Git dependency

Pin an exact commit. Choose commit `a84e73c` or a later one: earlier commits
predate the MIT OR Apache-2.0 license files and carry no license grant.

```toml
[dependencies]
phantom = { package = "phantom-http", git = "https://github.com/bywayhq/phantom", rev = "<commit>", features = ["full"] }
```

Cargo resolves every `phantom-*` fork from the same commit, because Phantom's
manifests refer to them by path inside that repository. Review Phantom changes
before moving the revision, then commit the new `rev` together with the
resulting `Cargo.lock` change.

## Path dependency

A revision-pinned submodule, or any other checkout of one exact commit, works
the same way:

```console
git submodule add https://github.com/bywayhq/phantom.git vendor/phantom
git -C vendor/phantom checkout --detach <commit>
git add .gitmodules vendor/phantom
```

```toml
[dependencies]
phantom = { package = "phantom-http", path = "vendor/phantom/crates/phantom", features = ["full"] }
```

Earlier Phantom revisions required copying a root `[patch]` table into the
consumer. That table is no longer needed; remove it when moving to a revision
that uses the renamed forks, because it now patches packages that no longer
appear in the graph.

## Fingerprint safety

The stock packages (`btls`, `tokio-btls`, `h3`, `h3-datagram`, `h3-quinn`,
`http2`, `quinn`, `quinn-proto`, `tungstenite`, `tokio-tungstenite`, and
`wreq-proto`) never appear in a Phantom graph. Another dependency of the
consumer may still use one of them; it then compiles as a separate crate whose
types are not interchangeable with Phantom's, and Phantom's behavior is
unchanged.

`btls-sys` still resolves from the reviewed fork
`https://github.com/0xARYA/btls` at a pinned revision. It declares
`links = "boringssl"`, so a consumer cannot also link another package with the
same `links` key, such as `boring-sys`; Cargo rejects that graph at resolution
time. Publishing `btls-sys` under a Phantom name with its own `links` key is a
planned release step. On Apple and Windows targets BoringSSL symbol prefixing
is currently disabled, so linking two BoringSSL copies there would still fail
at link time.

## Validate from the downstream root

After resolving and committing the downstream `Cargo.lock`, validate the
consumer from its repository root:

```console
cargo metadata --all-features --locked --format-version 1 > /dev/null
cargo check --all-features --locked
```

Phantom's own CI checks path and git consumers the same way; see
[Downstream CI](../internals/vendoring.md#downstream-ci). A downstream
repository must still run the commands above, and its own build and tests,
against its committed lockfile and toolchain.
