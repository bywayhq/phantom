# Downstream integration

Phantom is not currently a one-line Git dependency. Its build depends on
patched dependency sources, and Cargo only honors `[patch]` tables from the
root manifest of the build. A downstream declaration such as
`phantom = { git = "https://github.com/bywayhq/phantom" }` therefore does not
inherit Phantom's patch table and is unsupported until the patched forks are
available as direct dependencies.

The supported downstream layout is a revision-pinned Phantom submodule whose
vendored dependency trees remain beside its crates:

```text
consumer/
|-- Cargo.lock
|-- Cargo.toml
|-- src/
`-- vendor/
    `-- phantom/                 # git submodule at one exact commit
        |-- crates/
        |   `-- phantom/
        `-- vendor/
            |-- btls/
            |-- h3/
            |-- http2/
            |-- quinn-proto/
            |-- tungstenite/
            `-- wreq-proto/
```

For example, from the downstream repository root, pin the currently documented
revision explicitly:

```console
git submodule add https://github.com/bywayhq/phantom.git vendor/phantom
git -C vendor/phantom checkout --detach 51a9ad03b0f1595a70a37e78c82609d54bf14ecf
git add .gitmodules vendor/phantom
```

The submodule gitlink is the dependency revision. Review Phantom changes before
moving it, then commit the updated gitlink together with the resulting
`Cargo.lock` change.

## Root manifest

Declare Phantom by path so its crates and vendored sources come from the same
pinned checkout:

```toml
[dependencies]
phantom = { path = "vendor/phantom/crates/phantom", features = ["full"] }
```

Copy the complete patch table below into the downstream workspace's root
`Cargo.toml`. The paths are relative to that manifest and match the layout
above.

```toml
[patch.crates-io]
h3 = { path = "vendor/phantom/vendor/h3/h3" }
h3-datagram = { path = "vendor/phantom/vendor/h3/h3-datagram" }
h3-quinn = { path = "vendor/phantom/vendor/h3/h3-quinn" }
http2 = { path = "vendor/phantom/vendor/http2" }
quinn-proto = { path = "vendor/phantom/vendor/quinn-proto" }
tungstenite = { path = "vendor/phantom/vendor/tungstenite" }
wreq-proto = { path = "vendor/phantom/vendor/wreq-proto" }

[patch."https://github.com/0xARYA/btls"]
btls = { path = "vendor/phantom/vendor/btls" }
```

Keep the source URL in the `btls` patch exactly as shown: Cargo patch tables
are scoped to a package source, and Phantom currently requests `btls` from that
Git source at a pinned revision.

The patch set is mandatory and versioned as one unit with Phantom. Current
Phantom code uses patch-only APIs and ABI, so omitting the root patches fails
compilation instead of falling back to a stock dependency with a different wire
fingerprint. A partial patch table is unsupported; copy it in full and update it
whenever the Phantom revision changes.

## Validate from the downstream root

After resolving and committing the downstream `Cargo.lock`, validate the
consumer from its repository root:

```console
cargo metadata --all-features --locked --format-version 1 > /dev/null
cargo build --all-features --locked
```

These commands verify that the committed lockfile resolves the pinned path and
patch graph and that all enabled Phantom capabilities compile in the consumer.
They are validation instructions, not a claim that a particular downstream
repository has been tested.
