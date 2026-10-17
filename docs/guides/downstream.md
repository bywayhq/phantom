# Adding Phantom to a project

Add Phantom to your `Cargo.toml`. You can use a registry release, pin a git
commit, or keep a copy inside your repository.

The package is named `phantom-http`, because `phantom` was taken on
crates.io. The dependency key `phantom` in the examples below keeps
`use phantom::...` working.

## Depend on a registry release

```toml
[dependencies]
phantom = { package = "phantom-http", version = "0.1", features = ["full"] }
```

Commit your `Cargo.lock`. Before upgrading, read
[CHANGELOG.md](../../CHANGELOG.md) for changes and migration notes.

## Depend on a pinned git revision

Pin an exact commit, `be02e93` or later. Older commits lack the Chrome 154
recipes these guides use, and commits before `a84e73c` have no license.
The documentation describes the commit it ships with, so read it at the
commit you pin.

```toml
[dependencies]
phantom = { package = "phantom-http", git = "https://github.com/bywayhq/phantom", rev = "<commit>", features = ["full"] }
```

To upgrade, read [CHANGELOG.md](../../CHANGELOG.md) for breaking changes
and how to migrate. Then change `rev`, and commit the new `Cargo.lock` with
it.

## Depend on a pinned path checkout

You can also keep a copy of Phantom in your repository, such as a git
submodule pinned to one commit.

```console
git submodule add https://github.com/bywayhq/phantom.git vendor/phantom
git -C vendor/phantom checkout --detach <commit>
git add .gitmodules vendor/phantom
```

```toml
[dependencies]
phantom = { package = "phantom-http", path = "vendor/phantom/crates/phantom", features = ["full"] }
```

If your project has a `[patch]` table from an older Phantom, remove it.
Phantom no longer needs one.

## Keep Phantom's patched dependencies

You don't need to do anything for this. Phantom ships its own changed
copies of its TLS, HTTP/2, QUIC, HTTP/3 and WebSocket libraries, so it
controls exactly what they send. They're renamed packages, such as
`phantom-btls` and `phantom-http2`, so no other crate in your build can
swap them for the stock versions.

If another dependency uses a stock package such as `quinn` or
`tungstenite`, it builds as a separate crate. Its types don't mix with
Phantom's, and Phantom's behavior doesn't change.
[Vendored forks](../internals/vendoring.md#vendored-forks) lists every
patched package.

## Check your project from its root

After you commit `Cargo.lock`, run these from your repository root:

```console
cargo metadata --all-features --locked --format-version 1 > /dev/null
cargo check --all-features --locked
```

## Native build requirements

Use Rust 1.88 or later, Git, CMake, libclang, and a C/C++ compiler. Windows
builds use Visual Studio C++ tools and NASM. On macOS, install Xcode's command
line tools. Linux builds also need `nm` and `objcopy` for symbol prefixing.
Git applies bundled source patches during the build. BoringSSL is included
in `phantom-btls-sys`; installation needs no native source checkout.

The original native license files ship with that package. Retain them when
redistributing native binaries.

## Limits

- Phantom's native package uses `links = "phantom_boringssl"`. This separate
  Cargo identity does not guarantee it can share a process with stock
  BoringSSL libraries. Symbol prefixing has Windows and Apple restrictions.

## Next

- [Using the client](client.md): build a client and send requests.
- [Vendored forks](../internals/vendoring.md#vendored-forks): what each
  patched package changes.
