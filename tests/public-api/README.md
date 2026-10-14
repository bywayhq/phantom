# Public API inventory

Review the library exports in these generated files. The inventories include
the support-crate API consolidation, proxy error sources, and shared route
lookup type. The containing Git commit records each snapshot update.

Generated with `cargo-public-api` 0.52.0 and `nightly-2026-09-01`, on
`x86_64-pc-windows-msvc`. `-sss` omits blanket, auto-trait, and derived
implementations. These files therefore do not prove `Send` or `Sync`.

```sh
scripts/dev/with-cargo-lock.sh cargo +nightly-2026-09-01 public-api \
  -p phantom-net --all-features -sss --color never
```

Replace the package name for each library. The QUIC provider also has
snapshots for default features, `--features keylog`, and `--features server`.
Check feature-gated documentation links with default and all-feature builds.

| Package | All-feature lines | Interface |
| --- | ---: | --- |
| `phantom-http` | 1,158 | Application client, ordered requests, responses, state, custom profile import |
| `phantom-net` | 1,440 | Protocol connections, routes, resolvers, transport errors |
| `phantom-profile` | 918 | Browser recipes and typed settings |
| `phantom-quic-btls` | 199 | Quinn crypto provider, handshake state, typed errors |
| `phantom-testkit` | 428 | Wire inspection and loopback test tools |

The QUIC snapshots confirm the nine retired packet-crypto exports are
absent in all four feature rows. Its intended public dependencies are
`btls`, `quinn-proto`, and `phantom-profile`, plus `zeroize` with `keylog`.
The provider README describes the boundary. The
[roadmap](../../docs/roadmap.md#phase-2-ergonomics)
summarizes the completed API work.

Settings have one public path at `phantom_profile`'s root. Shared request
types use `phantom_net::request`. Source bindings and shared TLS errors use
`phantom_net`'s root. Recipes remain under `phantom_profile::browser`.
The generator may print a definition's private module path in another
crate's signature. Use its public export when writing imports; downstream
compile checks verify those paths.

## Intended public dependencies

| Library | Dependencies named by its API |
| --- | --- |
| `phantom-http` | `bytes`, `http`, `http-body`, `futures-core`, `futures-sink`, optional `serde`, `phantom-net`, `phantom-profile` |
| `phantom-net` | `bytes`, `http`, `http-body`, Tokio I/O, `phantom-profile`, `phantom-quic-btls` |
| `phantom-profile` | Standard library only |
| `phantom-quic-btls` | `btls`, `quinn-proto`, `phantom-profile`, `zeroize` (`keylog`) |
| `phantom-testkit` | Tokio I/O, timers and task errors |

The client runs in Tokio. Backend error causes remain reachable through
`std::error::Error::source`; their concrete types are not part of the
client's signatures. See
[downstream build limits](../../docs/guides/downstream.md#limits) for the
BoringSSL linking restriction.

## Next

- [Migration notes](../../CHANGELOG.md#breaking): changes to public APIs.
- [Provider API](../../crates/phantom-quic-btls/README.md#api-boundary): QUIC types.
