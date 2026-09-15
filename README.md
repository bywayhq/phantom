# Phantom

Phantom is an experimental Rust HTTP client focused on observable,
profile-driven wire behavior across TLS, HTTP/1.1, HTTP/2, QUIC, and HTTP/3.

The current vertical slices implement certificate- and hostname-checked TLS,
ordered streaming HTTP/1.1, and one-shot HTTP/2 over an exact `h2` TLS
negotiation. The Chrome 152 macOS TLS and HTTP/2 recipes have retained local
ClientHello and raw startup-frame fixtures with direct differentials. HTTP/3,
Firefox and Safari recipes, reusable sessions, SSE, and WebSocket remain
planned. The project does not make broad browser-compatibility claims.

## Principles

- Wire evidence is the specification.
- Browser behavior is represented by validated profiles rather than transport conditionals.
- Built-in and user-customized profiles use the same typed model.
- Unsupported behavior produces an explicit error instead of a silent fallback.
- Features land as small, runnable vertical slices.

## Current workspace

- `phantom`: the future public client facade
- `phantom-profile`: browser-neutral profile identity, typed TLS and HTTP/2
  settings, and the fixture-backed Chrome 152 macOS recipes
- `phantom-net`: the private BoringSSL adapter plus ordered streaming HTTP/1.1
  and one-shot HTTP/2 request paths, including exact-`h2` TLS and ALPS handling
- `phantom-testkit`: bounded TLS ClientHello and HTTP/2 frame capture with
  strict decoding for deterministic differentials

See [the roadmap](docs/roadmap.md), [architecture](docs/architecture.md),
[validation model](docs/validation.md), and [performance guide](docs/performance.md).

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
```
