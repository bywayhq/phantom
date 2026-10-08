# Adding Phantom to a project

Add Phantom to your `Cargo.toml`. Phantom isn't on crates.io yet, so you
depend on an exact git commit or on a copy inside your repository. Either
way it's one dependency line.

The package is named `phantom-http`, because `phantom` was taken on
crates.io. The dependency key `phantom` in the examples below keeps
`use phantom::...` working.

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

## Limits

- Phantom builds BoringSSL through `btls-sys`, from the fork
  `https://github.com/bywayhq/btls` at a pinned revision.
- `btls-sys` declares `links = "boringssl"`. Cargo refuses a build that has
  another crate with that key, such as `boring-sys`.

## Next

- [Using the client](client.md): build a client and send requests.
- [Vendored forks](../internals/vendoring.md#vendored-forks): what each
  patched package changes.
