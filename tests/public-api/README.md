# Public API inventory

Review the library exports in these generated files. They record the
Phase 2 API checkpoint `44ffae95`, shipped in
[PR 187](https://github.com/bywayhq/phantom/pull/187) at `b2cf66d0`.
Its full gate, PR checks, and all ten workflows on `main` passed.

Generated with `cargo-public-api` 0.52.0 and `nightly-2026-09-01`, on
`x86_64-pc-windows-msvc`. `-sss` omits blanket, auto-trait, and derived
implementations. These files therefore do not prove `Send` or `Sync`.

```sh
scripts/dev/with-cargo-lock.sh cargo +nightly-2026-09-01 public-api \
  -p phantom-net --all-features -sss --color never
```

Replace the package name for each library. The QUIC provider also has
snapshots for default features, `--features keylog`, and `--features server`.
Builds with default features were inspected for every library. Their
feature-gated documentation links need separate checks from all-feature docs.

| Package | All-feature lines | Interface |
| --- | ---: | --- |
| `phantom-http` | 1,018 | Application client, ordered requests, responses, state |
| `phantom-net` | 1,364 | Protocol connections, routes, resolvers, transport errors |
| `phantom-profile` | 1,578 | Browser recipes and typed settings |
| `phantom-quic-btls` | 191 | Quinn crypto provider, handshake state, typed errors |
| `phantom-testkit` | 410 | Wire inspection and loopback test tools |

The QUIC snapshots confirm the nine retired packet-crypto exports are
absent in all four feature rows. Its intended public dependencies are
`btls`, `quinn-proto`, and `phantom-profile`; the provider README describes
the boundary. Export and trait decisions are tracked in the
[Phase 2 checklist](../../docs/internals/phase2.md).

## Intended public dependencies

| Library | Dependencies named by its API |
| --- | --- |
| `phantom-http` | `bytes`, `http`, `http-body`, `futures-core`, `futures-sink`, optional `serde`, `phantom-net`, `phantom-profile` |
| `phantom-net` | `bytes`, `http`, `http-body`, Tokio I/O, `phantom-profile`, `phantom-quic-btls` |
| `phantom-profile` | Standard library only |
| `phantom-quic-btls` | `btls`, `quinn-proto`, `phantom-profile` |
| `phantom-testkit` | Tokio I/O and timers |

The client runs in Tokio. Backend error causes remain reachable through
`std::error::Error::source`; their concrete types are not part of the
client's signatures. See
[downstream build limits](../../docs/guides/downstream.md#limits) for the
BoringSSL linking restriction.

## Next

- [Phase 2 checklist](../../docs/internals/phase2.md): completed API work.
- [Provider API](../../crates/phantom-quic-btls/README.md#api-boundary): QUIC types.
