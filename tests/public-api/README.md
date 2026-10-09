# Public API inventory

Review the library exports in these generated files. They record the
profile and request checkpoint `f0e0d961`. Further Phase 2 API work remains;
refresh them when each change is integrated.

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
| `phantom-http` | 849 | Application client, ordered requests, responses, state |
| `phantom-net` | 1,326 | Protocol connections, routes, resolvers, transport errors |
| `phantom-profile` | 1,454 | Browser recipes and typed settings |
| `phantom-quic-btls` | 187 | Quinn crypto provider, handshake state, typed errors |
| `phantom-testkit` | 305 | Wire inspection and loopback test tools |

The QUIC snapshots confirm the nine retired packet-crypto exports are
absent in all four feature rows. Its intended public dependencies are
`btls`, `quinn-proto`, and `phantom-profile`; the provider README describes
the boundary. Remaining export and trait decisions are tracked in the
[Phase 2 checklist](../../docs/internals/phase2.md).

## Next

- [Phase 2 checklist](../../docs/internals/phase2.md): outstanding API work.
- [Provider API](../../crates/phantom-quic-btls/README.md#api-boundary): QUIC types.
