# Adding Phantom to a project

Add Phantom to your Cargo project from a pinned git revision or a pinned path
checkout, and check that your build keeps Phantom's patched dependencies.

> For builders who have read [Getting started](../getting-started.md).

Phantom is not on crates.io yet. Either way of depending on it is one
dependency line, with no `[patch]` table.

The package is named `phantom-http`, because `phantom` is taken on crates.io.
The library crate is still `phantom`, and the dependency key below keeps
`use phantom::...` working.

## Depend on a pinned git revision

Pin an exact commit, `be02e93` or later. Commits before `a84e73c` predate the
MIT OR Apache-2.0 license files and carry no license grant, and commits before
`be02e93` lack the Chrome 154 recipes these guides use. The documentation
describes the commit it ships with, so read it at the commit you pin.

```toml
[dependencies]
phantom = { package = "phantom-http", git = "https://github.com/bywayhq/phantom", rev = "<commit>", features = ["full"] }
```

Cargo resolves every Phantom fork from that same commit, because Phantom's
manifests refer to them by path inside the repository. To upgrade, review the
Phantom changes, move `rev`, and commit it together with the resulting
`Cargo.lock` change.

## Depend on a pinned path checkout

A submodule pinned to one commit, or any other checkout of an exact commit,
works the same way:

```console
git submodule add https://github.com/bywayhq/phantom.git vendor/phantom
git -C vendor/phantom checkout --detach <commit>
git add .gitmodules vendor/phantom
```

```toml
[dependencies]
phantom = { package = "phantom-http", path = "vendor/phantom/crates/phantom", features = ["full"] }
```

If you are upgrading from an older Phantom revision that required a root
`[patch]` table, remove that table. It patches packages that no longer appear
in the dependency graph.

## Keep Phantom's patched dependencies

Phantom patches several dependencies, such as its TLS, HTTP/2, QUIC, and
HTTP/3 libraries, to control what they send. Those patched copies live in this
repository under `vendor/` as renamed packages: `phantom-btls`, `phantom-h3`,
`phantom-http2`, `phantom-quinn-proto`, and the others listed in
[Vendored forks](../internals/vendoring.md#vendored-forks). Phantom's
manifests depend on them by exact version and path. As a result, no other
crate in your build can replace them with the unpatched versions and change
Phantom's fingerprint.

The stock packages (`btls`, `tokio-btls`, `h3`, `h3-datagram`, `h3-quinn`,
`http2`, `quinn`, `quinn-proto`, `tungstenite`, `tokio-tungstenite`, and
`wreq-proto`) never appear in Phantom's part of the graph. If another of your
dependencies uses one of them, it compiles as a separate crate. Its types do
not mix with Phantom's, and Phantom's behavior does not change.

## Check your project from its root

After you resolve and commit your `Cargo.lock`, check your project from its
repository root:

```console
cargo metadata --all-features --locked --format-version 1 > /dev/null
cargo check --all-features --locked
```

Phantom's own CI checks path and git consumers the same way; see
[Downstream CI](../internals/vendoring.md#downstream-ci). That does not replace
your own checks: run the commands above, and your own build and tests, against
your committed lockfile and toolchain.

## Limits

- `btls-sys` still comes from the reviewed fork
  `https://github.com/0xARYA/btls` at a pinned revision, and declares
  `links = "boringssl"`. Cargo rejects a graph that also contains another
  package with that `links` key, such as `boring-sys`.
- Publishing `btls-sys` under a Phantom name with its own `links` key is a
  planned release step. Even then, BoringSSL symbol prefixing is disabled on
  Apple and Windows targets, so two copies of BoringSSL would still fail to
  link there.

## Next

- [Using the client](client.md): build a client and send requests.
- [Vendored forks](../internals/vendoring.md#vendored-forks): what each
  patched package changes.
